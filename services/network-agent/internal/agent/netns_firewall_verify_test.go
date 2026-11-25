package agent

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"
)

// testdata/nft-lab-sealed.json is a REAL capture (nft 1.0.2, Ubuntu 22.04 on WSL2) of a lab
// namespace right after Seal, taken during an egresslab-firewall-lab run with:
//
//	sudo ip netns exec <egresslab-lab-...> nft -j list ruleset
//
// Only the structure matters to these tests; the runtime baseline is always read from the kernel.
func sealedRulesetFixture(t *testing.T) map[string]any {
	t.Helper()

	data, err := os.ReadFile("testdata/nft-lab-sealed.json")
	if err != nil {
		t.Fatal(err)
	}

	var doc map[string]any
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatal(err)
	}

	return doc
}

func encodeRuleset(t *testing.T, doc map[string]any) []byte {
	t.Helper()

	data, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}

	return data
}

func objects(doc map[string]any) []any {
	return doc["nftables"].([]any)
}

func withObject(t *testing.T, doc map[string]any, object string) map[string]any {
	t.Helper()

	var parsed any
	if err := json.Unmarshal([]byte(object), &parsed); err != nil {
		t.Fatal(err)
	}

	return map[string]any{"nftables": append(append([]any{}, objects(doc)...), parsed)}
}

const extraICMPRule = `{"rule": {"family": "inet", "table": "egresslab_lab", "chain": "output", "handle": 30,
  "expr": [{"match": {"op": "==", "left": {"meta": {"key": "l4proto"}}, "right": "icmp"}}, {"accept": null}]}}`

func TestLabRulesetFingerprintAcceptsSealedLab(t *testing.T) {
	doc := sealedRulesetFixture(t)

	first, err := labRulesetFingerprint(encodeRuleset(t, doc))
	if err != nil {
		t.Fatal(err)
	}

	if strings.Count(first, "\n") != 5 {
		t.Fatalf("expected 6 rules in the fingerprint, got:\n%s", first)
	}

	// Handles change on every reconcile; they must not affect the fingerprint.
	for _, object := range objects(doc) {
		for _, value := range object.(map[string]any) {
			if fields, ok := value.(map[string]any); ok {
				if _, has := fields["handle"]; has {
					fields["handle"] = 999
				}
			}
		}
	}

	second, err := labRulesetFingerprint(encodeRuleset(t, doc))
	if err != nil || second != first {
		t.Fatalf("fingerprint depends on handles: %v", err)
	}

	added, err := labRulesetFingerprint(encodeRuleset(t, withObject(t, doc, extraICMPRule)))
	if err != nil || added == first {
		t.Fatalf("an added rule did not change the fingerprint: %v", err)
	}
}

func TestLabRulesetFingerprintRejectsWeakenedStructure(t *testing.T) {
	cases := map[string]func(t *testing.T, doc map[string]any) map[string]any{
		"extra table": func(t *testing.T, doc map[string]any) map[string]any {
			return withObject(t, doc, `{"table": {"family": "ip", "name": "nat", "handle": 9}}`)
		},
		"set object": func(t *testing.T, doc map[string]any) map[string]any {
			return withObject(t, doc, `{"set": {"family": "inet", "table": "egresslab_lab", "name": "allow"}}`)
		},
		"extra chain": func(t *testing.T, doc map[string]any) map[string]any {
			return withObject(t, doc, `{"chain": {"family": "inet", "table": "egresslab_lab", "name": "prerouting",
			  "type": "nat", "hook": "prerouting", "prio": -100, "policy": "accept"}}`)
		},
		"rule in unknown chain": func(t *testing.T, doc map[string]any) map[string]any {
			return withObject(t, doc, `{"rule": {"family": "inet", "table": "egresslab_lab", "chain": "other", "expr": []}}`)
		},
		"policy accept": func(t *testing.T, doc map[string]any) map[string]any {
			return mutateChain(doc, "output", "policy", "accept")
		},
		"non-zero priority": func(t *testing.T, doc map[string]any) map[string]any {
			return mutateChain(doc, "input", "prio", 10)
		},
		"wrong hook": func(t *testing.T, doc map[string]any) map[string]any {
			return mutateChain(doc, "forward", "hook", "input")
		},
		"missing chain": func(t *testing.T, doc map[string]any) map[string]any {
			var kept []any
			for _, object := range objects(doc) {
				if chain, ok := object.(map[string]any)["chain"].(map[string]any); ok && chain["name"] == "forward" {
					continue
				}
				kept = append(kept, object)
			}
			return map[string]any{"nftables": kept}
		},
		"table deleted": func(t *testing.T, doc map[string]any) map[string]any {
			return map[string]any{"nftables": objects(doc)[:1]}
		},
	}

	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			doc := mutate(t, sealedRulesetFixture(t))
			if _, err := labRulesetFingerprint(encodeRuleset(t, doc)); err == nil {
				t.Fatal("weakened ruleset accepted")
			}
		})
	}

	if _, err := labRulesetFingerprint([]byte("not json")); err == nil {
		t.Fatal("garbage accepted")
	}
}

func mutateChain(doc map[string]any, name, field string, value any) map[string]any {
	for _, object := range objects(doc) {
		if chain, ok := object.(map[string]any)["chain"].(map[string]any); ok && chain["name"] == name {
			chain[field] = value
		}
	}

	return doc
}

// fakeKernel models the lab namespace ruleset: applying the seal installs the fixture, applying any
// other script appends one rule, and tests can tamper with it out of band.
type fakeKernel struct {
	t       *testing.T
	ruleset map[string]any
	applied []string
	listErr error
}

func (k *fakeKernel) run(_ context.Context, _ string, script string, check bool) error {
	if check {
		return nil
	}

	k.applied = append(k.applied, script)

	switch {
	case strings.Contains(script, "delete table"):
		// Reconcile: the table is rebuilt from the session's scripts.
		k.ruleset = sealedRulesetFixture(k.t)
		for range strings.Count(script, "add rule") - strings.Count(sealLabRules, "add rule") {
			k.ruleset = withObject(k.t, k.ruleset, extraICMPRule)
		}

	case strings.Contains(script, "create table"):
		k.ruleset = sealedRulesetFixture(k.t)

	default:
		k.ruleset = withObject(k.t, k.ruleset, extraICMPRule)
	}

	return nil
}

func (k *fakeKernel) list(context.Context, string) ([]byte, error) {
	if k.listErr != nil {
		return nil, k.listErr
	}

	return encodeRuleset(k.t, k.ruleset), nil
}

func verifyingFirewall(t *testing.T) (*LabFirewall, *fakeKernel) {
	t.Helper()

	kernel := &fakeKernel{t: t}
	manager := ownedTestManager(firewallTestName)

	// An offline namespace: only loopback, no WireGuard interface.
	manager.run = func(context.Context, ...string) ([]byte, error) {
		return []byte(`[{"ifname":"lo"}]`), nil
	}

	return newVerifyingLabFirewall(manager, kernel.run, kernel.list), kernel
}

func TestLabFirewallBlocksOnOutOfBandChange(t *testing.T) {
	firewall, kernel := verifyingFirewall(t)
	ctx := context.Background()

	if err := firewall.Seal(ctx, firewallTestName); err != nil {
		t.Fatal(err)
	}

	if err := firewall.PermitPeerICMP(ctx, firewallTestName, LabSideA); err != nil {
		t.Fatal(err)
	}

	if err := firewall.Verify(ctx, firewallTestName); err != nil {
		t.Fatalf("unchanged ruleset failed verification: %v", err)
	}

	// Someone deletes the policy-drop on output behind our back.
	mutateChain(kernel.ruleset, "output", "policy", "accept")

	applied := len(kernel.applied)

	if err := firewall.PermitPeerICMP(ctx, firewallTestName, LabSideB); !errors.Is(err, ErrFirewallDrift) {
		t.Fatalf("drift not detected: %v", err)
	}

	if len(kernel.applied) != applied {
		t.Fatal("rules were applied on top of a drifted ruleset")
	}

	// Restoring the kernel by hand is not enough: the drift flag stays until Reconcile.
	mutateChain(kernel.ruleset, "output", "policy", "drop")
	if err := firewall.Verify(ctx, firewallTestName); !errors.Is(err, ErrFirewallDrift) {
		t.Fatalf("drift flag cleared without reconcile: %v", err)
	}

	if err := firewall.Reconcile(ctx, firewallTestName); err != nil {
		t.Fatal(err)
	}

	last := kernel.applied[len(kernel.applied)-1]
	if !strings.HasPrefix(last, "add table inet egresslab_lab\ndelete table inet egresslab_lab\n") ||
		!strings.Contains(last, "create table inet egresslab_lab") || strings.Contains(last, "flush") {
		t.Fatalf("unexpected reconcile script:\n%s", last)
	}

	if err := firewall.Verify(ctx, firewallTestName); err != nil {
		t.Fatalf("verification failed after reconcile: %v", err)
	}

	if err := firewall.PermitPeerICMP(ctx, firewallTestName, LabSideB); err != nil {
		t.Fatal(err)
	}
}

func TestLabFirewallAddedRuleIsDrift(t *testing.T) {
	firewall, kernel := verifyingFirewall(t)
	ctx := context.Background()

	if err := firewall.Seal(ctx, firewallTestName); err != nil {
		t.Fatal(err)
	}

	kernel.ruleset = withObject(t, kernel.ruleset, extraICMPRule)

	if err := firewall.Verify(ctx, firewallTestName); !errors.Is(err, ErrFirewallDrift) {
		t.Fatalf("added rule not detected: %v", err)
	}
}

func TestLabFirewallUnreadableStateFailsClosed(t *testing.T) {
	firewall, kernel := verifyingFirewall(t)
	ctx := context.Background()

	kernel.listErr = errors.New("nft: permission denied")

	if err := firewall.Seal(ctx, firewallTestName); !errors.Is(err, ErrFirewallDrift) {
		t.Fatalf("unverifiable seal reported success: %v", err)
	}

	kernel.listErr = nil

	if err := firewall.PermitPeerICMP(ctx, firewallTestName, LabSideA); !errors.Is(err, ErrFirewallDrift) {
		t.Fatalf("unverified namespace was opened: %v", err)
	}
}

func TestReconcileRequiresSealedOwnedNamespace(t *testing.T) {
	firewall, _ := verifyingFirewall(t)
	ctx := context.Background()

	if err := firewall.Reconcile(ctx, firewallTestName); err == nil {
		t.Fatal("reconcile ran on a namespace that was never sealed")
	}

	if err := firewall.Reconcile(ctx, "egresslab-lab-00000000000000ff"); err == nil {
		t.Fatal("reconcile ran on an unowned namespace")
	}

	if err := firewall.Verify(ctx, "bad name"); err == nil {
		t.Fatal("invalid name accepted")
	}
}

func TestVPNConnectRefusesDriftedNamespace(t *testing.T) {
	lab, rec := testVPNLab(true)
	lab.firewall.drifted[vpnTestNS] = true

	if err := lab.Connect(context.Background(), vpnTestNS, vpnTestConfig(t)); !errors.Is(err, ErrFirewallDrift) {
		t.Fatalf("tunnel configured in a drifted namespace: %v", err)
	}

	if len(rec.ipCalls) != 0 || len(rec.wgCalls) != 0 {
		t.Fatal("commands ran before the drift check")
	}
}

// testdata/nft-lab-probe-permitted.json is a REAL capture (nft 1.0.2, Ubuntu 22.04 on WSL2) of a
// sealed lab namespace after PermitEgressProbe, taken during a live VPN lab run with:
//
//	ip netns exec <egresslab-lab-...> nft -j list ruleset
func TestLabRulesetFingerprintRealCapture(t *testing.T) {
	data, err := os.ReadFile("testdata/nft-lab-probe-permitted.json")
	if err != nil {
		t.Fatal(err)
	}

	fingerprint, err := labRulesetFingerprint(data)
	if err != nil {
		t.Fatalf("real nft output rejected: %v", err)
	}

	// 6 seal rules + 2 egress-probe rules.
	if got := strings.Count(fingerprint, "\n") + 1; got != 8 {
		t.Fatalf("expected 8 rules, got %d:\n%s", got, fingerprint)
	}

	for _, want := range []string{`"1.1.1.1"`, `"wg0"`, `"ipv6"`, `53`} {
		if !strings.Contains(fingerprint, want) {
			t.Fatalf("fingerprint is missing %s:\n%s", want, fingerprint)
		}
	}

	var doc map[string]any
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatal(err)
	}

	if _, err := labRulesetFingerprint(encodeRuleset(t, mutateChain(doc, "output", "policy", "accept"))); err == nil {
		t.Fatal("real capture with output policy accept was accepted")
	}
}
