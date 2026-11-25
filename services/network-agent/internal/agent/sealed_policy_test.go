package agent

import (
	"encoding/json"
	"errors"
	"net/netip"
	"os"
	"strings"
	"testing"
)

func TestIntendedSealedPolicy(t *testing.T) {
	if err := verifySealedPolicy(encodeRuleset(t, sealedRulesetFixture(t))); err != nil {
		t.Fatal(err)
	}
}

func TestIntendedSealedPolicyRejectsExtraAllowRule(t *testing.T) {
	doc := withObject(t, sealedRulesetFixture(t), extraICMPRule)

	if err := verifySealedPolicy(encodeRuleset(t, doc)); !errors.Is(err, ErrFirewallDrift) {
		t.Fatalf("extra permit rule accepted: %v", err)
	}
}

func TestIntendedSealedPolicyRejectsMissingRule(t *testing.T) {
	items := objects(sealedRulesetFixture(t))
	removed := 0

	for i, item := range items {
		if _, ok := item.(map[string]any)["rule"]; !ok {
			continue
		}

		kept := append(append([]any{}, items[:i]...), items[i+1:]...)
		removed++

		err := verifySealedPolicy(encodeRuleset(t, map[string]any{"nftables": kept}))
		if !errors.Is(err, ErrFirewallDrift) {
			t.Fatalf("missing rule %d accepted: %v", i, err)
		}
	}

	if removed != 8 {
		t.Fatalf("expected 8 rules in the fixture, removed %d", removed)
	}
}

func TestIntendedSealedPolicyRejectsEarlyLoopback(t *testing.T) {
	doc := sealedRulesetFixture(t)
	items := objects(doc)

	var output []int

	for i, item := range items {
		if rule, ok := item.(map[string]any)["rule"].(map[string]any); ok && rule["chain"] == "output" {
			output = append(output, i)
		}
	}

	if len(output) != 6 {
		t.Fatal("invalid output fixture")
	}

	// The loopback accept ahead of the deny rules.
	first, last := output[0], output[len(output)-1]
	items[first], items[last] = items[last], items[first]

	if err := verifySealedPolicy(encodeRuleset(t, doc)); !errors.Is(err, ErrFirewallDrift) {
		t.Fatalf("unsafe rule order accepted: %v", err)
	}
}

// A structurally valid ruleset is not necessarily the intended one: the earlier seal (a real
// capture) put the loopback accepts first and had no port 853 drops.
func TestIntendedSealedPolicyRejectsLegacyRuleset(t *testing.T) {
	data, err := os.ReadFile("testdata/nft-lab-sealed.json")
	if err != nil {
		t.Fatal(err)
	}

	if _, err := labRulesetFingerprint(data); err != nil {
		t.Fatal(err)
	}

	if err := verifySealedPolicy(data); !errors.Is(err, ErrFirewallDrift) {
		t.Fatalf("legacy policy accepted: %v", err)
	}
}

func TestIntendedSealedPolicyRejectsNullObjects(t *testing.T) {
	for _, input := range []string{
		`{"nftables":[{"table":null}]}`,
		`{"nftables":[{"chain":null}]}`,
		`{"nftables":[{"rule":null}]}`,
	} {
		if err := verifySealedPolicy([]byte(input)); !errors.Is(err, ErrFirewallDrift) {
			t.Fatalf("%s accepted: %v", input, err)
		}
	}
}

func TestDormantTablesRejected(t *testing.T) {
	withTableFlags := func(flags any) []byte {
		doc := sealedRulesetFixture(t)
		for _, item := range objects(doc) {
			if table, ok := item.(map[string]any)["table"].(map[string]any); ok {
				table["flags"] = flags
			}
		}
		return encodeRuleset(t, doc)
	}

	underlay := string(underlayListing(t, "198.51.100.7:51820", 0xabcd, "accept"))
	want := underlayTunnel{
		table:    "egresslab_ul_00000000000000aa",
		mark:     0xabcd,
		endpoint: netip.MustParseAddrPort("198.51.100.7:51820"),
	}

	for _, flags := range []string{`"dormant"`, `["dormant"]`} {
		var value any
		if err := json.Unmarshal([]byte(flags), &value); err != nil {
			t.Fatal(err)
		}

		if err := verifySealedPolicy(withTableFlags(value)); !errors.Is(err, ErrFirewallDrift) {
			t.Errorf("lab table with flags %s accepted: %v", flags, err)
		}

		data := strings.Replace(underlay, `"handle": 7}`, `"handle": 7, "flags": `+flags+`}`, 1)
		if err := verifyUnderlayRuleset([]byte(data), want); err == nil {
			t.Errorf("underlay table with flags %s accepted", flags)
		}
	}

	// What nft 1.0.2 really prints (exit status 0) for a dormant table.
	broken := `{"nftables": [{"metainfo": {"version": "1.0.2", "release_name": "Lester Gooch", "json_schema_version": 1}}, ` +
		`{"table": {"family": "inet", "name": "egresslab_lab", "handle": 1, "flags": ` + "\n"

	if err := verifySealedPolicy([]byte(broken)); !errors.Is(err, ErrFirewallDrift) {
		t.Errorf("nft 1.0.2 dormant listing accepted: %v", err)
	}
}

// The ip-link-managed-*.json files are REAL captures (iproute2 5.15, kernel 6.6 on WSL2) of a
// wireguard link with a managed alias: in the root namespace, moved into an anonymous namespace,
// then renamed to wg0. They pin the JSON keys the inventory relies on.
func TestLocateManagedTunnelRealCaptures(t *testing.T) {
	load := func(name string) []managedLink {
		data, err := os.ReadFile("testdata/" + name)
		if err != nil {
			t.Fatal(err)
		}

		var links []managedLink
		if err := json.Unmarshal(data, &links); err != nil {
			t.Fatal(err)
		}

		return links
	}

	tunnel := &managedTunnel{
		namespace: vpnTestNS,
		rootName:  vpnTestLink,
		alias:     managedTunnelAliasPrefix + vpnTestNS + ":" + vpnTestLink,
	}
	loopback := []managedLink{{Name: "lo", Index: 1, Type: "loopback"}}

	for name, tt := range map[string]struct {
		outside, inside []managedLink
		want            managedLinkLocation
	}{
		"root namespace":   {load("ip-link-managed-root.json"), loopback, managedLinkLocation{"", vpnTestLink}},
		"moved":            {nil, load("ip-link-managed-moved.json"), managedLinkLocation{vpnTestNS, vpnTestLink}},
		"renamed into wg0": {nil, load("ip-link-managed-wg0.json"), managedLinkLocation{vpnTestNS, labWGInterface}},
	} {
		location, err := locateManagedTunnel(tt.outside, tt.inside, tunnel)
		if err != nil || location == nil || *location != tt.want {
			t.Errorf("%s: %+v %v", name, location, err)
		}
	}

	other := *tunnel
	other.alias = managedTunnelAliasPrefix + vpnTestNS + ":egwg00000001"

	if _, err := locateManagedTunnel(nil, load("ip-link-managed-wg0.json"), &other); err == nil {
		t.Error("wg0 with another tunnel's alias adopted")
	}

	if location, err := locateManagedTunnel(nil, loopback, tunnel); err != nil || location != nil {
		t.Errorf("empty namespace: %+v %v", location, err)
	}
}

// testdata/nft-underlay.json is a REAL capture (nft 1.0.2) of underlayRules applied in an
// anonymous namespace, with mark 0xabcd and endpoint 198.51.100.7:51820.
func TestVerifyUnderlayRulesetRealCapture(t *testing.T) {
	data, err := os.ReadFile("testdata/nft-underlay.json")
	if err != nil {
		t.Fatal(err)
	}

	want := underlayTunnel{
		table:    "egresslab_ul_00000000000000aa",
		mark:     0xabcd,
		endpoint: netip.MustParseAddrPort("198.51.100.7:51820"),
	}

	if err := verifyUnderlayRuleset(data, want); err != nil {
		t.Fatal(err)
	}

	want.mark = 0xabce
	if err := verifyUnderlayRuleset(data, want); err == nil {
		t.Fatal("other mark accepted")
	}
}
