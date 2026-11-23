package agent

import (
	"context"
	"errors"
	"strings"
	"testing"
)

const firewallTestName = "egresslab-lab-0000000000000001"

type nftInvocation struct {
	namespace string
	script    string
	check     bool
}

func ownedTestManager(names ...string) *NetNSLabManager {
	manager := &NetNSLabManager{owned: map[string]struct{}{}}
	for _, name := range names {
		manager.owned[name] = struct{}{}
	}

	return manager
}

func recordingFirewall(manager *NetNSLabManager, fail func(check bool) error) (*LabFirewall, *[]nftInvocation) {
	var calls []nftInvocation

	firewall := newLabFirewall(manager, func(_ context.Context, namespace, script string, check bool) error {
		calls = append(calls, nftInvocation{namespace: namespace, script: script, check: check})
		if fail != nil {
			return fail(check)
		}

		return nil
	})

	return firewall, &calls
}

func TestLabFirewallSealedThenPeerICMP(t *testing.T) {
	firewall, calls := recordingFirewall(ownedTestManager(firewallTestName), nil)
	ctx := context.Background()

	if err := firewall.Seal(ctx, firewallTestName); err != nil {
		t.Fatal(err)
	}

	if err := firewall.PermitPeerICMP(ctx, firewallTestName, LabSideA); err != nil {
		t.Fatal(err)
	}

	got := *calls
	if len(got) != 4 {
		t.Fatalf("expected 4 calls, got %d", len(got))
	}

	if !got[0].check || got[1].check || !got[2].check || got[3].check {
		t.Fatal("unexpected check/apply order")
	}

	for _, call := range got {
		if call.namespace != firewallTestName {
			t.Fatalf("command ran in %s", call.namespace)
		}
	}

	sealedRules := got[0].script

	if strings.Count(sealedRules, "policy drop") != 3 {
		t.Fatal("input, output and forward must all default to drop")
	}

	if !strings.Contains(sealedRules, "create table inet egresslab_lab") {
		t.Fatal("missing isolated firewall table")
	}

	if strings.Contains(sealedRules, "flush") {
		t.Fatal("lab rules must never flush existing rulesets")
	}

	if !strings.Contains(got[2].script, "ip saddr 10.253.0.2 ip daddr 10.253.0.1") {
		t.Fatal("missing peer restriction")
	}
}

func TestLabFirewallRejectsForeignNamespace(t *testing.T) {
	firewall, calls := recordingFirewall(ownedTestManager(), nil)

	if err := firewall.Seal(context.Background(), firewallTestName); err == nil {
		t.Fatal("expected ownership rejection")
	}

	if err := firewall.Seal(context.Background(), "../default"); err == nil {
		t.Fatal("expected invalid name rejection")
	}

	if len(*calls) != 0 {
		t.Fatal("executed network command")
	}
}

func TestLabFirewallRequiresSeal(t *testing.T) {
	firewall, calls := recordingFirewall(ownedTestManager(firewallTestName), nil)

	if err := firewall.PermitPeerICMP(context.Background(), firewallTestName, LabSideA); err == nil {
		t.Fatal("unsealed namespace was accepted")
	}

	if len(*calls) != 0 {
		t.Fatal("unexpected nft command")
	}
}

func TestLabFirewallRejectsDoubleSeal(t *testing.T) {
	firewall, calls := recordingFirewall(ownedTestManager(firewallTestName), nil)

	if err := firewall.Seal(context.Background(), firewallTestName); err != nil {
		t.Fatal(err)
	}

	if err := firewall.Seal(context.Background(), firewallTestName); err == nil {
		t.Fatal("second seal was accepted")
	}

	if len(*calls) != 2 {
		t.Fatalf("expected 2 calls, got %d", len(*calls))
	}
}

func TestLabFirewallStopsOnFailedCheck(t *testing.T) {
	firewall, calls := recordingFirewall(ownedTestManager(firewallTestName), func(check bool) error {
		if check {
			return errors.New("invalid nft rules")
		}

		return nil
	})

	if err := firewall.Seal(context.Background(), firewallTestName); err == nil {
		t.Fatal("expected validation failure")
	}

	if len(*calls) != 1 {
		t.Fatalf("expected 1 call, got %d", len(*calls))
	}

	if firewall.sealed[firewallTestName] {
		t.Fatal("failed setup must not be marked sealed")
	}
}

func TestLabFirewallFailedApplyIsNotReady(t *testing.T) {
	firewall, calls := recordingFirewall(ownedTestManager(firewallTestName), func(check bool) error {
		if !check {
			return errors.New("permission denied")
		}

		return nil
	})

	if err := firewall.Seal(context.Background(), firewallTestName); err == nil {
		t.Fatal("expected nft apply failure")
	}

	if len(*calls) != 2 {
		t.Fatalf("expected 2 calls, got %d", len(*calls))
	}

	if firewall.sealed[firewallTestName] {
		t.Fatal("must not claim successful firewall setup")
	}
}

func TestLabFirewallPeerValidation(t *testing.T) {
	if _, err := peerICMPRules("foreign"); err == nil {
		t.Fatal("invalid side accepted")
	}

	a, err := peerICMPRules(LabSideA)
	if err != nil {
		t.Fatal(err)
	}

	b, err := peerICMPRules(LabSideB)
	if err != nil {
		t.Fatal(err)
	}

	if a == b {
		t.Fatal("both sides produced the same rules")
	}

	expectations := []struct {
		script string
		wants  []string
	}{
		{a, []string{
			`input iifname "ev-a" ip saddr 10.253.0.2 ip daddr 10.253.0.1`,
			`output oifname "ev-a" ip saddr 10.253.0.1 ip daddr 10.253.0.2`,
		}},
		{b, []string{
			`input iifname "ev-b" ip saddr 10.253.0.1 ip daddr 10.253.0.2`,
			`output oifname "ev-b" ip saddr 10.253.0.2 ip daddr 10.253.0.1`,
		}},
	}

	for _, expectation := range expectations {
		script := expectation.script

		for _, want := range expectation.wants {
			if !strings.Contains(script, want) {
				t.Errorf("missing %q in:\n%s", want, script)
			}
		}

		if strings.Count(script, "icmp type { echo-request, echo-reply } accept") != 2 {
			t.Errorf("rules must only accept ICMP echo:\n%s", script)
		}
	}
}

func TestSealDeniesIPv6AndDNSExplicitly(t *testing.T) {
	lines := strings.Split(strings.TrimSpace(sealLabRules), "\n")

	position := func(rule string) int {
		for i, line := range lines {
			if line == "add rule inet egresslab_lab "+rule {
				return i
			}
		}

		t.Fatalf("seal is missing %q", rule)
		return -1
	}

	loIn, loOut := position(`input iifname "lo" accept`), position(`output oifname "lo" accept`)

	for _, rule := range []string{
		"input meta nfproto ipv6 drop",
		"output meta nfproto ipv6 drop",
		"output udp dport 53 drop",
		"output tcp dport 53 drop",
	} {
		if p := position(rule); p < loIn || p < loOut {
			t.Fatalf("%q must follow the loopback accepts", rule)
		}
	}

	// Every permit is appended after the seal, so these drops always win over later accepts.
	if !strings.HasPrefix(lines[0], "create table") {
		t.Fatal("seal must create the table first")
	}
}
