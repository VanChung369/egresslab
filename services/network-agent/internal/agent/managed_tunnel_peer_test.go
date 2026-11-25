package agent

import (
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"os"
	"strings"
	"testing"
)

func TestManagedPeerRejectsUnexpectedInitialState(t *testing.T) {
	for property, value := range map[string]string{
		"public-key": demoKey(4),
		"peers":      demoKey(2),
	} {
		t.Run(property, func(t *testing.T) {
			b, kernel := newManagedTunnelFixture(t)
			kernel.wgOverrides[property] = value

			if err := b.connectConfig(context.Background(), vpnTestNS, vpnTestConfig(t)); !errors.Is(err, ErrManagedPeerDrift) {
				t.Fatalf("unexpected error: %v", err)
			}

			if kernel.peerCalls != 0 {
				t.Fatal("peer configured after failed verification")
			}

			if b.active != nil || kernel.name != "" || kernel.tableRemovals != 1 {
				t.Fatal("rollback incomplete")
			}
		})
	}
}

func TestManagedPeerRejectsDrift(t *testing.T) {
	tests := []struct{ name, property, value string }{
		{"wrong interface key", "public-key", demoKey(4)},
		{"missing peer", "peers", ""},
		{"wrong peer", "peers", demoKey(4)},
		{"extra peer", "peers", demoKey(2) + "\n" + demoKey(4)},
		{"endpoint IP changed", "endpoints", demoKey(2) + "\t198.51.100.8:51820"},
		{"endpoint port changed", "endpoints", demoKey(2) + "\t198.51.100.7:443"},
		{"endpoint missing", "endpoints", demoKey(2) + "\t(none)"},
		{"split tunnel", "allowed-ips", demoKey(2) + "\t10.0.0.0/8"},
		{"unexpected IPv6 allowed IPs", "allowed-ips", demoKey(2) + "\t0.0.0.0/0 ::/0"},
		{"keepalive disabled", "persistent-keepalive", demoKey(2) + "\toff"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b, kernel := newManagedTunnelFixture(t)
			ctx := context.Background()

			if err := b.connectConfig(ctx, vpnTestNS, vpnTestConfig(t)); err != nil {
				t.Fatal(err)
			}

			kernel.wgOverrides[tt.property] = tt.value

			if err := b.VerifyConfigured(ctx, vpnTestNS); !errors.Is(err, ErrManagedPeerDrift) {
				t.Fatalf("drift accepted: %v", err)
			}

			if b.active == nil || !b.active.faulted {
				t.Fatal("tunnel not marked faulted")
			}

			// Correcting the kernel does not clear the fault.
			delete(kernel.wgOverrides, tt.property)

			if err := b.VerifyConfigured(ctx, vpnTestNS); !errors.Is(err, ErrManagedTunnelUncertain) {
				t.Fatalf("fault silently cleared: %v", err)
			}

			if err := b.CleanupStage(ctx, vpnTestNS); err != nil {
				t.Fatal(err)
			}

			if b.active != nil || kernel.tableRemovals != 1 {
				t.Fatal("cleanup incomplete")
			}
		})
	}
}

func TestManagedPeerRollsBackInvalidEndpoint(t *testing.T) {
	b, kernel := newManagedTunnelFixture(t)
	kernel.wgOverrides["endpoints"] = demoKey(2) + "\t198.51.100.8:51820"

	if err := b.connectConfig(context.Background(), vpnTestNS, vpnTestConfig(t)); !errors.Is(err, ErrManagedPeerDrift) {
		t.Fatalf("invalid endpoint accepted: %v", err)
	}

	if kernel.peerCalls != 1 || b.active != nil || kernel.name != "" || kernel.tableRemovals != 1 {
		t.Fatal("connection rollback incomplete")
	}
}

func TestManagedPeerReadbackFailure(t *testing.T) {
	b, kernel := newManagedTunnelFixture(t)
	ctx := context.Background()

	if err := b.connectConfig(ctx, vpnTestNS, vpnTestConfig(t)); err != nil {
		t.Fatal(err)
	}

	kernel.wgReadError = "endpoints"

	if err := b.VerifyConfigured(ctx, vpnTestNS); !errors.Is(err, ErrManagedPeerDrift) {
		t.Fatalf("readback failure ignored: %v", err)
	}

	if b.active == nil || !b.active.faulted {
		t.Fatal("tunnel fault not retained")
	}
}

func TestManagedPeerKeepaliveDisabled(t *testing.T) {
	b, kernel := newManagedTunnelFixture(t)
	cfg := vpnTestConfig(t, [2]string{"PersistentKeepalive = 25", "PersistentKeepalive = 0"})
	kernel.wgOverrides["persistent-keepalive"] = demoKey(2) + "\toff"

	if err := b.connectConfig(context.Background(), vpnTestNS, cfg); err != nil {
		t.Fatal(err)
	}

	if b.active.peer.keepalive != 0 {
		t.Fatal("incorrect keepalive policy")
	}
}

func TestManagedPeerPolicyNeedsAUsableKey(t *testing.T) {
	t.Run("derivation fails", func(t *testing.T) {
		b, kernel := newManagedTunnelFixture(t)
		runWG := b.vpn.runWG
		b.vpn.runWG = func(ctx context.Context, ns string, stdin []byte, args ...string) (string, error) {
			if args[0] == "pubkey" {
				return "", errors.New("wg failed")
			}
			return runWG(ctx, ns, stdin, args...)
		}

		if err := b.connectConfig(context.Background(), vpnTestNS, vpnTestConfig(t)); err == nil {
			t.Fatal("connected without an expected interface key")
		}

		requireUntouched(t, b, kernel)
	})

	// The interface's own key as the peer: refused before anything is created.
	t.Run("peer is the interface", func(t *testing.T) {
		b, kernel := newManagedTunnelFixture(t)

		if err := b.connectConfig(context.Background(), vpnTestNS, vpnTestConfig(t, [2]string{"PublicKey = " + demoKey(2), "PublicKey = " + demoKey(3)})); err == nil {
			t.Fatal("peer key equal to the interface key accepted")
		}

		requireUntouched(t, b, kernel)
	})
}

// testdata/wg-show-peer.json is a REAL capture (wireguard-tools v1.0.20210914, kernel 6.6 on WSL2)
// of "wg show wg0 <property>" for a synthetic key, peer and TEST-NET endpoint, before and after the
// peer was added. It pins the text format the checks compare against.
func TestManagedPeerRealCapture(t *testing.T) {
	data, err := os.ReadFile("testdata/wg-show-peer.json")
	if err != nil {
		t.Fatal(err)
	}

	var capture struct {
		InterfacePublicKey string            `json:"interface_public_key"`
		PeerPublicKey      string            `json:"peer_public_key"`
		Endpoint           string            `json:"endpoint"`
		Outputs            map[string]string `json:"outputs"`
	}

	if err := json.Unmarshal(data, &capture); err != nil {
		t.Fatal(err)
	}

	reading := map[string]string{"public-key": "public-key", "peers": "peers-empty"}
	b := &ManagedTunnelBackend{vpn: &VPNEgressLab{runWG: func(_ context.Context, _ string, _ []byte, args ...string) (string, error) {
		raw, ok := capture.Outputs[reading[args[2]]]
		if !ok {
			return "", errors.New("not captured")
		}
		return strings.TrimSpace(raw), nil // as newSystemWGRunner returns it
	}}}

	tunnel := &managedTunnel{namespace: vpnTestNS, peer: managedPeerPolicy{
		interfacePublicKey: capture.InterfacePublicKey,
		peerPublicKey:      capture.PeerPublicKey,
		endpoint:           netip.MustParseAddrPort(capture.Endpoint),
		keepalive:          25,
	}}

	if err := b.verifyBeforePeerLocked(context.Background(), tunnel); err != nil {
		t.Fatalf("before the peer: %v", err)
	}

	for _, p := range []string{"peers", "endpoints", "allowed-ips", "persistent-keepalive"} {
		reading[p] = p
	}

	if err := b.verifyPeerLocked(context.Background(), tunnel); err != nil {
		t.Fatalf("configured peer: %v", err)
	}

	tunnel.peer.keepalive = 0
	reading["persistent-keepalive"] = "persistent-keepalive-off"

	if err := b.verifyPeerLocked(context.Background(), tunnel); err != nil {
		t.Fatalf("keepalive off: %v", err)
	}

	tunnel.peer.endpoint = netip.MustParseAddrPort("198.51.100.7:51821")
	if err := b.verifyPeerLocked(context.Background(), tunnel); !errors.Is(err, ErrManagedPeerDrift) {
		t.Fatalf("other port accepted: %v", err)
	}
}
