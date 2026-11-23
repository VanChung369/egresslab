package agent

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"reflect"
	"strings"
	"testing"
)

const (
	wgTestA = "egresslab-lab-0000000000000001"
	wgTestB = "egresslab-lab-0000000000000002"
)

type wgInvocation struct {
	namespace string
	stdin     string
	args      []string
}

type wgLabRecorder struct {
	ipCalls    [][]string
	nftScripts []string
	wgCalls    []wgInvocation
	badGenkey  bool
}

func testWGKey(b byte) string {
	return base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{b}, 32))
}

func testWGLab() (*WireGuardLab, *wgLabRecorder) {
	rec := &wgLabRecorder{}

	manager := &NetNSLabManager{
		owned: map[string]struct{}{wgTestA: {}, wgTestB: {}},
		run: func(_ context.Context, args ...string) ([]byte, error) {
			rec.ipCalls = append(rec.ipCalls, append([]string(nil), args...))
			return nil, nil
		},
	}

	firewall := newLabFirewall(manager, func(_ context.Context, _ string, script string, _ bool) error {
		rec.nftScripts = append(rec.nftScripts, script)
		return nil
	})

	generated := 0

	run := func(_ context.Context, namespace, stdin string, args ...string) (string, error) {
		rec.wgCalls = append(rec.wgCalls, wgInvocation{namespace, stdin, append([]string(nil), args...)})

		switch args[0] {
		case "genkey":
			if rec.badGenkey {
				return "not-a-key", nil
			}
			generated++
			return testWGKey(byte(generated)), nil

		case "pubkey":
			if stdin == testWGKey(1) {
				return testWGKey(3), nil
			}
			return testWGKey(4), nil

		case "set":
			arguments := strings.Join(args, " ")
			if strings.Contains(arguments, testWGKey(1)) || strings.Contains(arguments, testWGKey(2)) {
				return "", errors.New("private key leaked to command arguments")
			}
			return "", nil
		}

		return "", errors.New("unexpected wg command")
	}

	return newWireGuardLab(manager, firewall, run), rec
}

func TestWireGuardLabSetup(t *testing.T) {
	lab, rec := testWGLab()

	if err := lab.Setup(context.Background(), wgTestA, wgTestB); err != nil {
		t.Fatal(err)
	}

	if len(rec.nftScripts) != 8 {
		t.Fatalf("expected 8 nft commands, got %d", len(rec.nftScripts))
	}

	for _, script := range rec.nftScripts {
		if strings.Contains(script, "flush") {
			t.Fatal("unsafe firewall command")
		}
	}

	expectedIP := [][]string{
		{"-n", wgTestA, "link", "add", "wg0", "type", "wireguard"},
		{"-n", wgTestB, "link", "add", "wg0", "type", "wireguard"},
		{"-n", wgTestA, "addr", "add", "10.254.0.1/30", "dev", "wg0"},
		{"-n", wgTestB, "addr", "add", "10.254.0.2/30", "dev", "wg0"},
		{"-n", wgTestA, "link", "set", "wg0", "up"},
		{"-n", wgTestB, "link", "set", "wg0", "up"},
	}

	if !reflect.DeepEqual(rec.ipCalls, expectedIP) {
		t.Fatalf("unexpected ip commands: %v", rec.ipCalls)
	}

	expectedWG := []wgInvocation{
		{"", "", []string{"genkey"}},
		{"", testWGKey(1), []string{"pubkey"}},
		{"", "", []string{"genkey"}},
		{"", testWGKey(2), []string{"pubkey"}},
		{wgTestA, testWGKey(1), []string{"set", "wg0", "listen-port", "51820", "private-key", "/dev/stdin"}},
		{wgTestB, testWGKey(2), []string{"set", "wg0", "listen-port", "51821", "private-key", "/dev/stdin"}},
		{wgTestA, "", []string{
			"set", "wg0", "peer", testWGKey(4), "allowed-ips", "10.254.0.2/32", "endpoint", "10.253.0.2:51821",
		}},
		{wgTestB, "", []string{
			"set", "wg0", "peer", testWGKey(3), "allowed-ips", "10.254.0.1/32", "endpoint", "10.253.0.1:51820",
		}},
	}

	if !reflect.DeepEqual(rec.wgCalls, expectedWG) {
		t.Fatalf("unexpected wg commands:\n%#v", rec.wgCalls)
	}
}

func TestWireGuardLabWrongNamespaces(t *testing.T) {
	lab, rec := testWGLab()

	for _, pair := range [][2]string{{"bad", "bad"}, {wgTestA, wgTestA}, {wgTestA, "../default"}} {
		if err := lab.Setup(context.Background(), pair[0], pair[1]); err == nil {
			t.Errorf("namespaces %v accepted", pair)
		}
	}

	if len(rec.ipCalls) != 0 || len(rec.wgCalls) != 0 || len(rec.nftScripts) != 0 {
		t.Fatal("unexpected commands")
	}
}

func TestWireGuardLabRejectsInvalidKeyOutput(t *testing.T) {
	lab, rec := testWGLab()
	rec.badGenkey = true

	if err := lab.Setup(context.Background(), wgTestA, wgTestB); err == nil {
		t.Fatal("invalid key output accepted")
	}

	if len(rec.ipCalls) != 0 || len(rec.nftScripts) != 0 {
		t.Fatal("network was changed after a key generation failure")
	}
}

func TestWireGuardLabRequiresOwnedNamespaces(t *testing.T) {
	lab, rec := testWGLab()
	delete(lab.manager.owned, wgTestB)

	if err := lab.Setup(context.Background(), wgTestA, wgTestB); err == nil {
		t.Fatal("foreign namespace accepted")
	}

	if len(rec.ipCalls) != 0 || len(rec.wgCalls) != 0 || len(rec.nftScripts) != 0 {
		t.Fatal("commands ran before ownership was confirmed")
	}
}

func TestWireGuardRules(t *testing.T) {
	a, err := wireGuardLabRules(LabSideA)
	if err != nil {
		t.Fatal(err)
	}

	b, err := wireGuardLabRules(LabSideB)
	if err != nil {
		t.Fatal(err)
	}

	expectations := map[string][]string{
		a: {
			`input iifname "ev-a" ip saddr 10.253.0.2 ip daddr 10.253.0.1 udp sport 51821 udp dport 51820 accept`,
			`output oifname "ev-a" ip saddr 10.253.0.1 ip daddr 10.253.0.2 udp sport 51820 udp dport 51821 accept`,
			`input iifname "wg0" ip saddr 10.254.0.2 ip daddr 10.254.0.1 icmp type`,
			`output oifname "wg0" ip saddr 10.254.0.1 ip daddr 10.254.0.2 icmp type`,
		},
		b: {
			`input iifname "ev-b" ip saddr 10.253.0.1 ip daddr 10.253.0.2 udp sport 51820 udp dport 51821 accept`,
			`output oifname "ev-b" ip saddr 10.253.0.2 ip daddr 10.253.0.1 udp sport 51821 udp dport 51820 accept`,
			`input iifname "wg0" ip saddr 10.254.0.1 ip daddr 10.254.0.2 icmp type`,
			`output oifname "wg0" ip saddr 10.254.0.2 ip daddr 10.254.0.1 icmp type`,
		},
	}

	for script, wants := range expectations {
		for _, want := range wants {
			if !strings.Contains(script, want) {
				t.Errorf("missing rule %q in:\n%s", want, script)
			}
		}

		if strings.Count(script, "add rule") != 4 {
			t.Errorf("expected exactly 4 rules:\n%s", script)
		}
	}

	if _, err := wireGuardLabRules("invalid"); err == nil {
		t.Fatal("invalid side accepted")
	}
}
