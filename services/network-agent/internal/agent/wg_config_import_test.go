package agent

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func demoKey(b byte) string {
	return base64.StdEncoding.EncodeToString([]byte(strings.Repeat(string([]byte{b}), 32)))
}

func demoConfig() string {
	return fmt.Sprintf(`# Proton-style sample; values are synthetic
[Interface]
PrivateKey = %s
Address = 10.2.0.2/32, fd00::2/128
DNS = 10.2.0.1
MTU = 1280

[Peer]
PublicKey = %s
AllowedIPs = 0.0.0.0/0, ::/0
Endpoint = vpn.example.com:51820
PersistentKeepalive = 25
`, demoKey(1), demoKey(2))
}

func withLine(after, line string) string {
	return strings.Replace(demoConfig(), after, after+"\n"+line, 1)
}

func replaced(old, new string) string {
	return strings.Replace(demoConfig(), old, new, 1)
}

func mustParse(t *testing.T, src string) *ImportedWireGuardConfig {
	t.Helper()

	cfg, err := ParseWireGuardConfig(strings.NewReader(src))
	if err != nil {
		t.Fatal(err)
	}

	return cfg
}

func TestParseWireGuardValid(t *testing.T) {
	cfg := mustParse(t, demoConfig())
	s := cfg.Summary()

	if !s.IPv4Default || !s.IPv6Default || s.NetworkReady || s.Status != "validated_not_connected" ||
		s.Addresses != 2 || s.DNSServers != 1 || s.AllowedRoutes != 2 || s.HasPresharedKey ||
		s.EndpointHost != "vpn.example.com" || s.EndpointPort != 51820 || s.KeepaliveSeconds != 25 || s.MTU != 1280 {
		t.Fatalf("bad summary: %+v", s)
	}

	raw, err := json.Marshal(s)
	if err != nil {
		t.Fatal(err)
	}

	if strings.Contains(string(raw), demoKey(1)) || !strings.Contains(string(raw), `"network_ready":false`) {
		t.Fatalf("secret or wrong readiness in summary: %s", raw)
	}
}

func TestImportedWireGuardConfigNeverRevealsSecrets(t *testing.T) {
	cfg := mustParse(t, withLine("PublicKey = "+demoKey(2), "PresharedKey = "+demoKey(3)))

	for _, value := range []any{cfg, *cfg, map[string]any{"config": cfg}} {
		if raw, err := json.Marshal(value); err == nil {
			t.Fatalf("config was serialized: %s", raw)
		}
	}

	output := ""
	for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%q", "%d", "%x"} {
		output += fmt.Sprintf(verb, cfg) + fmt.Sprintf(verb, *cfg)
	}

	for _, secret := range []string{demoKey(1), demoKey(3)} {
		if strings.Contains(output, secret) {
			t.Fatalf("secret appeared in formatted output: %s", output)
		}
	}

	if !cfg.Summary().HasPresharedKey {
		t.Fatal("preshared key was not recorded")
	}
}

func TestParseWireGuardRejectsUnsafeDirectives(t *testing.T) {
	directives := []string{
		"PostUp = touch /tmp/unsafe",
		"PreUp = x",
		"PostDown = x",
		"PreDown = x",
		"Table = auto",
		"SaveConfig = true",
		"ListenPort = 12345",
		"FwMark = 22",
	}

	for _, directive := range directives {
		t.Run(strings.Split(directive, " = ")[0], func(t *testing.T) {
			if _, err := ParseWireGuardConfig(strings.NewReader(withLine("DNS = 10.2.0.1", directive))); err == nil {
				t.Fatal("unsafe/unsupported directive accepted")
			}
		})
	}
}

func TestRejectedConfigIsWiped(t *testing.T) {
	// PrivateKey and PresharedKey are copied before the unsafe directive at the end is seen.
	src := withLine("PersistentKeepalive = 25", "PresharedKey = "+demoKey(3)) + "PostUp = x\n"

	cfg := &ImportedWireGuardConfig{}
	if err := cfg.parse([]byte(src)); err == nil {
		t.Fatal("unsafe directive accepted")
	}

	if cfg.privateKey != nil || cfg.peerPresharedKey != nil || cfg.peerPublicKey != "" || cfg.addresses != nil {
		t.Fatal("rejected config kept its contents")
	}
}

func TestParseWireGuardRejectsMalformed(t *testing.T) {
	tooManyAddresses := make([]string, maxWireGuardAddresses+1)
	for i := range tooManyAddresses {
		tooManyAddresses[i] = fmt.Sprintf("10.2.0.%d/32", i+2)
	}

	tests := map[string]string{
		"duplicate interface":      replaced("[Interface]", "[Interface]\n[Interface]"),
		"extra peer":               demoConfig() + "\n[Peer]\n",
		"peer before interface":    "[Peer]\nPublicKey = " + demoKey(2) + "\n",
		"unknown section":          withLine("MTU = 1280", "[Other]"),
		"option outside section":   "PrivateKey = " + demoKey(1) + "\n" + demoConfig(),
		"missing secret":           replaced("PrivateKey = "+demoKey(1)+"\n", ""),
		"missing address":          replaced("Address = 10.2.0.2/32, fd00::2/128\n", ""),
		"missing peer key":         replaced("PublicKey = "+demoKey(2)+"\n", ""),
		"missing endpoint":         replaced("Endpoint = vpn.example.com:51820\n", ""),
		"duplicate key":            withLine("PrivateKey = "+demoKey(1), "PrivateKey = "+demoKey(1)),
		"duplicate allowed ips":    withLine("AllowedIPs = 0.0.0.0/0, ::/0", "AllowedIPs = 10.0.0.0/8"),
		"bad key":                  replaced(demoKey(1), "abc"),
		"non-canonical key":        replaced(demoKey(1), strings.TrimSuffix(demoKey(1), "=")+"A"),
		"empty value":              replaced("MTU = 1280", "MTU ="),
		"bad mtu":                  replaced("MTU = 1280", "MTU = 100"),
		"bad keepalive":            replaced("PersistentKeepalive = 25", "PersistentKeepalive = off"),
		"bad endpoint":             replaced("vpn.example.com:51820", "https://vpn.example.com:51820"),
		"endpoint port zero":       replaced("vpn.example.com:51820", "vpn.example.com:0"),
		"endpoint port too large":  replaced("vpn.example.com:51820", "vpn.example.com:65536"),
		"endpoint bad hostname":    replaced("vpn.example.com:51820", "vpn_example.com:51820"),
		"endpoint zone":            replaced("vpn.example.com:51820", "[fe80::1%eth0]:51820"),
		"bad dns":                  replaced("DNS = 10.2.0.1", "DNS = search.example.com"),
		"bad address":              replaced("10.2.0.2/32, fd00::2/128", "10.2.0.2"),
		"too many addresses":       replaced("10.2.0.2/32, fd00::2/128", strings.Join(tooManyAddresses, ", ")),
		"mapped address":           replaced("10.2.0.2/32, fd00::2/128", "::ffff:10.2.0.2/128"),
		"no allowed":               replaced("AllowedIPs = 0.0.0.0/0, ::/0\n", ""),
		"trailing comma in routes": replaced("0.0.0.0/0, ::/0", "0.0.0.0/0,"),
		"too large":                strings.Repeat("#", maxWireGuardConfigBytes+1),
	}

	for name, src := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseWireGuardConfig(strings.NewReader(src)); err == nil {
				t.Fatal("accepted invalid config")
			}
		})
	}
}

func TestParseWireGuardErrorsDoNotEchoValues(t *testing.T) {
	secretish := strings.TrimSuffix(demoKey(9), "=") + "!"

	_, err := ParseWireGuardConfig(strings.NewReader(replaced(demoKey(1), secretish)))
	if err == nil {
		t.Fatal("invalid key accepted")
	}

	if strings.Contains(err.Error(), secretish) || !strings.Contains(err.Error(), "line 3") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestParseWireGuardAcceptsCRLFAndComments(t *testing.T) {
	src := strings.ReplaceAll(withLine("MTU = 1280", "# trailing note"), "\n", "\r\n")
	src = strings.Replace(src, "DNS = 10.2.0.1", "DNS = 10.2.0.1 # resolver", 1)

	if s := mustParse(t, src).Summary(); s.DNSServers != 1 || s.MTU != 1280 {
		t.Fatalf("bad summary: %+v", s)
	}
}

func TestParseWireGuardSplitTunnelIsNotReady(t *testing.T) {
	s := mustParse(t, replaced("AllowedIPs = 0.0.0.0/0, ::/0", "AllowedIPs = 10.20.0.0/16")).Summary()

	if s.IPv4Default || s.IPv6Default || s.NetworkReady {
		t.Fatalf("bad split tunnel status: %+v", s)
	}
}

func TestParseWireGuardIPv6Endpoint(t *testing.T) {
	s := mustParse(t, replaced("vpn.example.com:51820", "[2001:db8::42]:51820")).Summary()

	if s.EndpointHost != "2001:db8::42" || s.EndpointPort != 51820 {
		t.Fatalf("unexpected endpoint: %+v", s)
	}
}

func TestLoadWireGuardPrivateFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.conf")

	if err := os.WriteFile(path, []byte(demoConfig()), 0o600); err != nil {
		t.Fatal(err)
	}

	if _, err := LoadWireGuardConfig(path); err != nil {
		t.Fatal(err)
	}

	if runtime.GOOS != "windows" {
		for _, mode := range []os.FileMode{0o644, 0o640, 0o604, 0o610} {
			if err := os.Chmod(path, mode); err != nil {
				t.Fatal(err)
			}

			if _, err := LoadWireGuardConfig(path); err == nil {
				t.Fatalf("mode %o accepted", mode)
			}
		}

		if err := os.Chmod(path, 0o600); err != nil {
			t.Fatal(err)
		}
	}

	link := filepath.Join(dir, "link.conf")
	if err := os.Symlink(path, link); err == nil {
		if _, err := LoadWireGuardConfig(link); err == nil {
			t.Fatal("symlink accepted")
		}
	}

	if _, err := LoadWireGuardConfig(dir); err == nil {
		t.Fatal("directory accepted")
	}

	if _, err := LoadWireGuardConfig(filepath.Join(dir, "missing.conf")); err == nil {
		t.Fatal("missing file accepted")
	}
}

func TestSummaryReportsVPNLabCompatibility(t *testing.T) {
	hostname := mustParse(t, demoConfig()).Summary()
	if hostname.VPNLabCompatible || !strings.Contains(hostname.VPNLabIssue, "IPv4 address") {
		t.Fatalf("hostname endpoint reported as lab-compatible: %+v", hostname)
	}

	literal := mustParse(t, replaced("vpn.example.com:51820", "198.51.100.7:51820")).Summary()
	if !literal.VPNLabCompatible || literal.VPNLabIssue != "" {
		t.Fatalf("IPv4 endpoint reported as incompatible: %+v", literal)
	}

	split := mustParse(t, strings.NewReplacer(
		"vpn.example.com:51820", "198.51.100.7:51820",
		"AllowedIPs = 0.0.0.0/0, ::/0", "AllowedIPs = 10.0.0.0/8",
	).Replace(demoConfig())).Summary()
	if split.VPNLabCompatible || !strings.Contains(split.VPNLabIssue, "0.0.0.0/0") {
		t.Fatalf("split tunnel reported as lab-compatible: %+v", split)
	}

	if err := CheckVPNLabCompatibility(mustParse(t, demoConfig())); err == nil {
		t.Fatal("hostname endpoint passed the lab compatibility check")
	}
}

func TestParseRejectsMultiplePeersExplicitly(t *testing.T) {
	src := demoConfig() + fmt.Sprintf("\n[Peer]\nPublicKey = %s\nAllowedIPs = 10.0.0.0/8\nEndpoint = 198.51.100.8:51820\n", demoKey(3))

	_, err := ParseWireGuardConfig(strings.NewReader(src))
	if err == nil || !strings.Contains(err.Error(), "single-peer") {
		t.Fatalf("multi-peer config not rejected explicitly: %v", err)
	}
}
