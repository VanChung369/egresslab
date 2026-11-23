package agent

import (
	"context"
	"errors"
	"net/netip"
	"reflect"
	"strings"
	"testing"
)

const (
	vpnTestNS   = "egresslab-lab-00000000000000aa"
	vpnTestLink = "egwg0000abcd"
)

type vpnLabRecorder struct {
	ipCalls [][]string
	wgCalls []wgInvocation
	nft     []nftInvocation
	failIP  func(args []string) error
	probed  []string
	body    string
}

func vpnTestConfig(t *testing.T, edits ...[2]string) *ImportedWireGuardConfig {
	t.Helper()

	src := strings.Replace(demoConfig(), "vpn.example.com:51820", "198.51.100.7:51820", 1)
	for _, edit := range edits {
		src = strings.Replace(src, edit[0], edit[1], 1)
	}

	return mustParse(t, src)
}

func testVPNLab(sealed bool) (*VPNEgressLab, *vpnLabRecorder) {
	rec := &vpnLabRecorder{body: "fl=1\nh=1.1.1.1\nip=203.0.113.9\nts=1\n"}

	manager := &NetNSLabManager{
		owned: map[string]struct{}{vpnTestNS: {}},
		run: func(_ context.Context, args ...string) ([]byte, error) {
			rec.ipCalls = append(rec.ipCalls, append([]string(nil), args...))
			if rec.failIP != nil {
				return nil, rec.failIP(args)
			}
			return nil, nil
		},
	}

	firewall := newLabFirewall(manager, func(_ context.Context, namespace, script string, check bool) error {
		rec.nft = append(rec.nft, nftInvocation{namespace: namespace, script: script, check: check})
		return nil
	})
	firewall.sealed[vpnTestNS] = sealed

	runWG := func(_ context.Context, namespace, stdin string, args ...string) (string, error) {
		rec.wgCalls = append(rec.wgCalls, wgInvocation{namespace, stdin, append([]string(nil), args...)})
		if args[0] == "show" {
			return testWGKey(2) + "\t1795424850", nil
		}
		return "", nil
	}

	probe := func(_ context.Context, namespace, url string) ([]byte, error) {
		rec.probed = append(rec.probed, namespace+" "+url)
		return []byte(rec.body), nil
	}

	return newVPNEgressLab(manager, firewall, runWG, probe, func() (string, error) { return vpnTestLink, nil }), rec
}

func TestPlanVPNTunnel(t *testing.T) {
	plan, err := planVPNTunnel(vpnTestConfig(t))
	if err != nil {
		t.Fatal(err)
	}

	if plan.endpoint.String() != "198.51.100.7:51820" || len(plan.addresses) != 1 ||
		plan.addresses[0].String() != "10.2.0.2/32" || plan.skippedIPv6 != 1 {
		t.Fatalf("unexpected plan: %+v", plan)
	}

	unsupported := map[string]*ImportedWireGuardConfig{
		"hostname endpoint": mustParse(t, demoConfig()),
		"IPv6 endpoint":     vpnTestConfig(t, [2]string{"198.51.100.7:51820", "[2001:db8::7]:51820"}),
		"split tunnel":      vpnTestConfig(t, [2]string{"0.0.0.0/0, ::/0", "10.0.0.0/8"}),
		"IPv6-only default": vpnTestConfig(t, [2]string{"0.0.0.0/0, ::/0", "::/0"}),
		"IPv6-only address": vpnTestConfig(t, [2]string{"10.2.0.2/32, fd00::2/128", "fd00::2/128"}),
	}

	for name, cfg := range unsupported {
		if _, err := planVPNTunnel(cfg); !errors.Is(err, ErrUnsupportedTunnelConfig) {
			t.Errorf("%s: unexpected error %v", name, err)
		}
	}
}

func TestParseEgressProbeURL(t *testing.T) {
	target, err := ParseEgressProbeURL(DefaultEgressProbeURL)
	if err != nil || target.IP != netip.MustParseAddr("1.1.1.1") {
		t.Fatalf("default probe rejected: %+v %v", target, err)
	}

	if _, err := ParseEgressProbeURL("https://1.1.1.1:443/cdn-cgi/trace"); err != nil {
		t.Fatal(err)
	}

	for _, raw := range []string{
		"http://1.1.1.1/cdn-cgi/trace",
		"https://one.one.one.one/cdn-cgi/trace",
		"https://[2606:4700:4700::1111]/cdn-cgi/trace",
		"https://1.1.1.1:8443/cdn-cgi/trace",
		"https://user@1.1.1.1/cdn-cgi/trace",
		"1.1.1.1/cdn-cgi/trace",
	} {
		if _, err := ParseEgressProbeURL(raw); err == nil {
			t.Errorf("%s accepted", raw)
		}
	}
}

func TestParseTraceIP(t *testing.T) {
	ip, err := parseTraceIP([]byte("fl=1\r\nip=203.0.113.9\r\nloc=CA\r\n"))
	if err != nil || ip != netip.MustParseAddr("203.0.113.9") {
		t.Fatalf("unexpected result: %v %v", ip, err)
	}

	for _, body := range []string{"", "fl=1\n", "ip=not-an-ip\n", "ip=1.1.1.1\nip=8.8.8.8\n"} {
		if _, err := parseTraceIP([]byte(body)); err == nil {
			t.Errorf("%q accepted", body)
		}
	}
}

func TestVPNEgressLabConnectSequence(t *testing.T) {
	lab, rec := testVPNLab(true)
	withPSK := [2]string{"PersistentKeepalive = 25", "PersistentKeepalive = 25\nPresharedKey = " + demoKey(3)}
	cfg := vpnTestConfig(t, withPSK)

	if err := lab.Connect(context.Background(), vpnTestNS, cfg); err != nil {
		t.Fatal(err)
	}

	expectedIP := [][]string{
		{"link", "add", vpnTestLink, "type", "wireguard"},
		{"link", "set", vpnTestLink, "netns", vpnTestNS},
		{"-n", vpnTestNS, "link", "set", vpnTestLink, "name", "wg0"},
		{"-n", vpnTestNS, "addr", "add", "10.2.0.2/32", "dev", "wg0"},
		{"-n", vpnTestNS, "link", "set", "wg0", "mtu", "1280"},
		{"-n", vpnTestNS, "link", "set", "wg0", "up"},
		{"-n", vpnTestNS, "-4", "route", "add", "default", "dev", "wg0"},
	}

	if !reflect.DeepEqual(rec.ipCalls, expectedIP) {
		t.Fatalf("unexpected ip commands:\n%v", rec.ipCalls)
	}

	expectedWG := []wgInvocation{
		{vpnTestNS, demoKey(1), []string{"set", "wg0", "private-key", "/dev/stdin"}},
		{vpnTestNS, "", []string{
			"set", "wg0", "peer", demoKey(2), "endpoint", "198.51.100.7:51820",
			"allowed-ips", "0.0.0.0/0", "persistent-keepalive", "25",
		}},
		{vpnTestNS, demoKey(3), []string{"set", "wg0", "peer", demoKey(2), "preshared-key", "/dev/stdin"}},
	}

	if !reflect.DeepEqual(rec.wgCalls, expectedWG) {
		t.Fatalf("unexpected wg commands:\n%#v", rec.wgCalls)
	}

	for _, call := range rec.wgCalls {
		joined := strings.Join(call.args, " ")
		if strings.Contains(joined, demoKey(1)) || strings.Contains(joined, demoKey(3)) {
			t.Fatal("secret passed as a command argument")
		}
	}

	for _, call := range rec.ipCalls {
		if strings.Contains(strings.Join(call, " "), "::") {
			t.Fatalf("IPv6 configured: %v", call)
		}
	}
}

func TestVPNEgressLabRequiresSealedNamespace(t *testing.T) {
	lab, rec := testVPNLab(false)

	if err := lab.Connect(context.Background(), vpnTestNS, vpnTestConfig(t)); err == nil {
		t.Fatal("unsealed namespace accepted")
	}

	delete(lab.manager.owned, vpnTestNS)
	lab.firewall.sealed[vpnTestNS] = true

	if err := lab.Connect(context.Background(), vpnTestNS, vpnTestConfig(t)); err == nil {
		t.Fatal("foreign namespace accepted")
	}

	if err := lab.Connect(context.Background(), "../default", vpnTestConfig(t)); err == nil {
		t.Fatal("invalid name accepted")
	}

	if len(rec.ipCalls) != 0 || len(rec.wgCalls) != 0 {
		t.Fatal("commands ran before checks passed")
	}
}

func TestVPNEgressLabRejectsUnsupportedConfigBeforeCommands(t *testing.T) {
	lab, rec := testVPNLab(true)

	err := lab.Connect(context.Background(), vpnTestNS, mustParse(t, demoConfig()))
	if !errors.Is(err, ErrUnsupportedTunnelConfig) {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(rec.ipCalls) != 0 || len(rec.wgCalls) != 0 {
		t.Fatal("commands ran for an unsupported config")
	}
}

func TestVPNEgressLabRemovesRootLinkWhenMoveFails(t *testing.T) {
	lab, rec := testVPNLab(true)
	rec.failIP = func(args []string) error {
		if len(args) > 3 && args[3] == "netns" {
			return errors.New("move failed")
		}
		return nil
	}

	if err := lab.Connect(context.Background(), vpnTestNS, vpnTestConfig(t)); err == nil {
		t.Fatal("expected move failure")
	}

	last := rec.ipCalls[len(rec.ipCalls)-1]
	if !reflect.DeepEqual(last, []string{"link", "del", vpnTestLink}) {
		t.Fatalf("root link was not removed: %v", rec.ipCalls)
	}
}

func TestVPNEgressLabLeavesNamespaceLinkAfterLaterFailure(t *testing.T) {
	lab, rec := testVPNLab(true)
	rec.failIP = func(args []string) error {
		if len(args) > 2 && args[2] == "addr" {
			return errors.New("address failed")
		}
		return nil
	}

	if err := lab.Connect(context.Background(), vpnTestNS, vpnTestConfig(t)); err == nil {
		t.Fatal("expected address failure")
	}

	for _, call := range rec.ipCalls {
		if call[0] == "link" && call[1] == "del" {
			t.Fatalf("deleted a link that already lives in the lab namespace: %v", rec.ipCalls)
		}
	}
}

func TestEgressProbeRules(t *testing.T) {
	script, err := egressProbeRules(netip.MustParseAddr("1.1.1.1"))
	if err != nil {
		t.Fatal(err)
	}

	expected := `add rule inet egresslab_lab output oifname "wg0" ip daddr 1.1.1.1 tcp dport 443 accept
add rule inet egresslab_lab input iifname "wg0" ip saddr 1.1.1.1 tcp sport 443 ct state established accept
`
	if script != expected {
		t.Fatalf("unexpected rules:\n%s", script)
	}

	if _, err := egressProbeRules(netip.MustParseAddr("2606:4700:4700::1111")); err == nil {
		t.Fatal("IPv6 probe accepted")
	}
}

func TestPermitEgressProbeRequiresSeal(t *testing.T) {
	lab, rec := testVPNLab(false)
	probe := netip.MustParseAddr("1.1.1.1")

	if err := lab.firewall.PermitEgressProbe(context.Background(), vpnTestNS, probe); err == nil {
		t.Fatal("unsealed namespace accepted")
	}

	lab.firewall.sealed[vpnTestNS] = true

	if err := lab.firewall.PermitEgressProbe(context.Background(), vpnTestNS, probe); err != nil {
		t.Fatal(err)
	}

	if len(rec.nft) != 2 || rec.nft[0].namespace != vpnTestNS || !rec.nft[0].check || rec.nft[1].check {
		t.Fatalf("unexpected nft calls: %#v", rec.nft)
	}
}

func TestVPNEgressLabProbeHandshakeAndDrop(t *testing.T) {
	lab, rec := testVPNLab(true)
	target, _ := ParseEgressProbeURL(DefaultEgressProbeURL)

	ip, err := lab.Probe(context.Background(), vpnTestNS, target)
	if err != nil || ip != netip.MustParseAddr("203.0.113.9") {
		t.Fatalf("unexpected probe result: %v %v", ip, err)
	}

	if rec.probed[0] != vpnTestNS+" "+DefaultEgressProbeURL {
		t.Fatalf("probe ran in the wrong place: %v", rec.probed)
	}

	handshake, err := lab.LatestHandshake(context.Background(), vpnTestNS)
	if err != nil || handshake.Unix() != 1795424850 {
		t.Fatalf("unexpected handshake: %v %v", handshake, err)
	}

	cfg := vpnTestConfig(t)
	if err := lab.DropPeer(context.Background(), vpnTestNS, cfg); err != nil {
		t.Fatal(err)
	}

	last := rec.wgCalls[len(rec.wgCalls)-1]
	if !reflect.DeepEqual(last.args, []string{"set", "wg0", "peer", demoKey(2), "remove"}) {
		t.Fatalf("unexpected removal: %#v", last)
	}
}
