package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"reflect"
	"strings"
	"testing"
)

func TestTunnelMarkAndTableName(t *testing.T) {
	mark, err := tunnelMark("egwg0000abcd")
	if err != nil || mark != 0xabcd {
		t.Fatalf("unexpected mark %#x %v", mark, err)
	}

	for _, link := range []string{"egwg00000000", "egwgzzzzzzzz", "wg0", "egwg0000abcd0"} {
		if _, err := tunnelMark(link); err == nil {
			t.Errorf("%s accepted", link)
		}
	}

	table, err := underlayTableName(vpnTestNS)
	if err != nil || table != "egresslab_ul_00000000000000aa" {
		t.Fatalf("unexpected table %q %v", table, err)
	}

	if _, err := underlayTableName("default"); err == nil {
		t.Fatal("non-lab namespace accepted")
	}
}

func TestUnderlayRules(t *testing.T) {
	script, err := underlayRules("egresslab_ul_00000000000000aa", 0xabcd, netip.MustParseAddrPort("198.51.100.7:51820"))
	if err != nil {
		t.Fatal(err)
	}

	expected := `create table inet egresslab_ul_00000000000000aa
add chain inet egresslab_ul_00000000000000aa output { type filter hook output priority 0; policy accept; }
add rule inet egresslab_ul_00000000000000aa output meta mark 0x0000abcd ip daddr 198.51.100.7 udp dport 51820 accept
add rule inet egresslab_ul_00000000000000aa output meta mark 0x0000abcd drop
`
	if script != expected {
		t.Fatalf("unexpected underlay rules:\n%s", script)
	}

	bad := []struct {
		table    string
		mark     uint32
		endpoint string
	}{
		{"filter", 0xabcd, "198.51.100.7:51820"},
		{"egresslab_ul_00000000000000aa", 0, "198.51.100.7:51820"},
		{"egresslab_ul_00000000000000aa", 0xabcd, "[2001:db8::7]:51820"},
		{"egresslab_ul_00000000000000aa", 0xabcd, "198.51.100.7:0"},
	}

	for _, b := range bad {
		if _, err := underlayRules(b.table, b.mark, netip.MustParseAddrPort(b.endpoint)); err == nil {
			t.Errorf("%+v accepted", b)
		}
	}
}

func TestConnectInstallsUnderlayBeforeTheTunnelExists(t *testing.T) {
	lab, rec := testVPNLab(true)

	ipCallsAtInstall := -1
	run := lab.rootNFT.run
	lab.rootNFT.run = func(ctx context.Context, script string, check bool) error {
		if !check && ipCallsAtInstall < 0 {
			ipCallsAtInstall = len(rec.ipCalls)
		}
		return run(ctx, script, check)
	}

	if err := lab.Connect(context.Background(), vpnTestNS, vpnTestConfig(t)); err != nil {
		t.Fatal(err)
	}

	if ipCallsAtInstall != 0 {
		t.Fatalf("underlay policy installed after %d ip commands", ipCallsAtInstall)
	}

	if len(rec.root) != 2 || !rec.root[0].check || rec.root[1].check ||
		!strings.Contains(rec.root[1].script, "ip daddr 198.51.100.7 udp dport 51820 accept") {
		t.Fatalf("unexpected underlay commands: %#v", rec.root)
	}

	if lab.underlay[vpnTestNS].mark != 0xabcd {
		t.Fatalf("underlay not tracked: %+v", lab.underlay)
	}
}

func TestConnectStopsWhenUnderlayCannotBeInstalled(t *testing.T) {
	lab, rec := testVPNLab(true)
	rec.rootErr = errors.New("nft: table exists")

	if err := lab.Connect(context.Background(), vpnTestNS, vpnTestConfig(t)); err == nil {
		t.Fatal("tunnel configured without an underlay policy")
	}

	if len(rec.ipCalls) != 0 || len(rec.wgCalls) != 0 {
		t.Fatal("tunnel commands ran without an underlay policy")
	}

	if _, tracked := lab.underlay[vpnTestNS]; tracked {
		t.Fatal("failed underlay install was tracked")
	}
}

func underlayListing(t *testing.T, endpoint string, mark uint32, policy string, extra ...string) []byte {
	t.Helper()

	addr := netip.MustParseAddrPort(endpoint)
	table := "egresslab_ul_00000000000000aa"

	objects := []string{
		`{"metainfo": {"version": "1.0.6", "json_schema_version": 1}}`,
		fmt.Sprintf(`{"table": {"family": "inet", "name": %q, "handle": 7}}`, table),
		fmt.Sprintf(`{"chain": {"family": "inet", "table": %q, "name": "output", "handle": 1, "type": "filter",
		  "hook": "output", "prio": 0, "policy": %q}}`, table, policy),
		fmt.Sprintf(`{"rule": {"family": "inet", "table": %q, "chain": "output", "handle": 2, "expr": [
		  {"match": {"op": "==", "left": {"meta": {"key": "mark"}}, "right": %d}},
		  {"match": {"op": "==", "left": {"payload": {"protocol": "ip", "field": "daddr"}}, "right": %q}},
		  {"match": {"op": "==", "left": {"payload": {"protocol": "udp", "field": "dport"}}, "right": %d}},
		  {"accept": null}]}}`, table, mark, addr.Addr().String(), addr.Port()),
		fmt.Sprintf(`{"rule": {"family": "inet", "table": %q, "chain": "output", "handle": 3, "expr": [
		  {"match": {"op": "==", "left": {"meta": {"key": "mark"}}, "right": %d}}, {"drop": null}]}}`, table, mark),
	}

	data := []byte(`{"nftables": [` + strings.Join(append(objects, extra...), ",") + `]}`)
	if !json.Valid(data) {
		t.Fatalf("invalid test JSON: %s", data)
	}

	return data
}

func TestVerifyUnderlayRuleset(t *testing.T) {
	want := underlayTunnel{
		table:    "egresslab_ul_00000000000000aa",
		mark:     0xabcd,
		endpoint: netip.MustParseAddrPort("198.51.100.7:51820"),
	}

	if err := verifyUnderlayRuleset(underlayListing(t, "198.51.100.7:51820", 0xabcd, "accept"), want); err != nil {
		t.Fatalf("matching policy rejected: %v", err)
	}

	extraRule := `{"rule": {"family": "inet", "table": "egresslab_ul_00000000000000aa", "chain": "output", "expr": [
	  {"match": {"op": "==", "left": {"meta": {"key": "mark"}}, "right": 43981}}, {"accept": null}]}}`

	bad := map[string][]byte{
		"other endpoint": underlayListing(t, "198.51.100.8:51820", 0xabcd, "accept"),
		"other port":     underlayListing(t, "198.51.100.7:51821", 0xabcd, "accept"),
		"other mark":     underlayListing(t, "198.51.100.7:51820", 0xabce, "accept"),
		"policy drop":    underlayListing(t, "198.51.100.7:51820", 0xabcd, "drop"),
		"extra rule":     underlayListing(t, "198.51.100.7:51820", 0xabcd, "accept", extraRule),
		"garbage":        []byte("{"),
	}

	for name, data := range bad {
		if err := verifyUnderlayRuleset(data, want); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}

	// Implicit dependencies are accepted only when they restate udp over IPv4.
	markMatch := `{"match": {"op": "==", "left": {"meta": {"key": "mark"}}`
	withDependency := func(key, value string) []byte {
		match := fmt.Sprintf(`{"match": {"op": "==", "left": {"meta": {"key": %q}}, "right": %q}}, `, key, value)
		return []byte(strings.Replace(string(underlayListing(t, "198.51.100.7:51820", 0xabcd, "accept")), markMatch, match+markMatch, 1))
	}

	for _, dep := range [][3]string{
		{"l4proto", "udp", "ok"}, {"nfproto", "ipv4", "ok"}, {"l4proto", "tcp", ""}, {"nfproto", "ipv6", ""},
	} {
		err := verifyUnderlayRuleset(withDependency(dep[0], dep[1]), want)
		if (err == nil) != (dep[2] == "ok") {
			t.Errorf("%s %s: %v", dep[0], dep[1], err)
		}
	}
}

func TestRuleMatchesIsStrict(t *testing.T) {
	parse := func(src string) []any {
		decoder := json.NewDecoder(strings.NewReader(src))
		decoder.UseNumber()

		var expr []any
		if err := decoder.Decode(&expr); err != nil {
			t.Fatal(err)
		}

		return expr
	}

	mark := `{"match": {"op": "==", "left": {"meta": {"key": "mark"}}, "right": 43981}}`

	matches, verdict := ruleMatches(parse(`[` + mark + `, {"drop": null}]`))
	if verdict != "drop" || len(matches) != 1 || matches["meta:mark"] != "43981" {
		t.Fatalf("valid rule: %v %q", matches, verdict)
	}

	for name, src := range map[string]string{
		"duplicate match":   `[` + mark + `, ` + mark + `, {"drop": null}]`,
		"verdict not last":  `[{"accept": null}, ` + mark + `]`,
		"two verdicts":      `[{"accept": null}, {"drop": null}]`,
		"verdict with body": `[` + mark + `, {"accept": {"x": 1}}]`,
		"no verdict":        `[` + mark + `]`,
		"null value":        `[{"match": {"op": "==", "left": {"meta": {"key": "mark"}}, "right": null}}, {"drop": null}]`,
		"missing value":     `[{"match": {"op": "==", "left": {"meta": {"key": "mark"}}}}, {"drop": null}]`,
		"other operator":    `[{"match": {"op": "!=", "left": {"meta": {"key": "mark"}}, "right": 1}}, {"drop": null}]`,
		"non-object match":  `[{"match": 1}, {"drop": null}]`,
		"other statement":   `[{"counter": null}, {"drop": null}]`,
	} {
		if matches, verdict := ruleMatches(parse(src)); matches != nil || verdict != "" {
			t.Errorf("%s: accepted as %v %q", name, matches, verdict)
		}
	}
}

func TestVerifyUnderlayChecksKernelAndFwmark(t *testing.T) {
	lab, _ := testVPNLab(true)

	fwmark := "0xabcd"
	lab.runWG = func(_ context.Context, _ string, _ []byte, args ...string) (string, error) {
		if reflect.DeepEqual(args, []string{"show", "wg0", "fwmark"}) {
			return fwmark + "\n", nil
		}
		return "", nil
	}

	lab.rootNFT.list = func(context.Context, string) ([]byte, error) {
		return underlayListing(t, "198.51.100.7:51820", 0xabcd, "accept"), nil
	}

	if err := lab.VerifyUnderlay(context.Background(), vpnTestNS); err == nil {
		t.Fatal("verified a namespace without an underlay policy")
	}

	if err := lab.Connect(context.Background(), vpnTestNS, vpnTestConfig(t)); err != nil {
		t.Fatal(err)
	}

	if err := lab.VerifyUnderlay(context.Background(), vpnTestNS); err != nil {
		t.Fatalf("matching underlay rejected: %v", err)
	}

	fwmark = "off"
	if err := lab.VerifyUnderlay(context.Background(), vpnTestNS); err == nil {
		t.Fatal("tunnel without fwmark accepted")
	}
}

func TestDisconnectRemovesLinkBeforeUnderlay(t *testing.T) {
	lab, rec := testVPNLab(true)

	if err := lab.Connect(context.Background(), vpnTestNS, vpnTestConfig(t)); err != nil {
		t.Fatal(err)
	}

	ipBefore, rootBefore := len(rec.ipCalls), len(rec.root)

	if err := lab.Disconnect(context.Background(), vpnTestNS); err != nil {
		t.Fatal(err)
	}

	if got := rec.ipCalls[ipBefore:]; !reflect.DeepEqual(got, [][]string{{"-n", vpnTestNS, "link", "del", "wg0"}}) {
		t.Fatalf("unexpected link removal: %v", got)
	}

	if got := rec.root[rootBefore:]; len(got) != 1 || got[0].script != "delete table inet egresslab_ul_00000000000000aa\n" {
		t.Fatalf("unexpected underlay removal: %#v", got)
	}

	if err := lab.Disconnect(context.Background(), vpnTestNS); err != nil || len(rec.root) != rootBefore+1 {
		t.Fatal("second disconnect was not a no-op")
	}
}

func TestDisconnectKeepsUnderlayWhenLinkSurvives(t *testing.T) {
	lab, rec := testVPNLab(true)

	if err := lab.Connect(context.Background(), vpnTestNS, vpnTestConfig(t)); err != nil {
		t.Fatal(err)
	}

	rec.failIP = func([]string) error { return errors.New("RTNETLINK answers: Operation not permitted") }
	rootBefore := len(rec.root)

	if err := lab.Disconnect(context.Background(), vpnTestNS); err == nil {
		t.Fatal("disconnect reported success although the link survived")
	}

	if len(rec.root) != rootBefore {
		t.Fatal("underlay policy removed while the tunnel link still exists")
	}

	// A link that is already gone (namespace deleted) is fine.
	rec.failIP = func([]string) error { return errors.New(`Cannot find device "wg0"`) }

	if err := lab.Disconnect(context.Background(), vpnTestNS); err != nil {
		t.Fatal(err)
	}
}
