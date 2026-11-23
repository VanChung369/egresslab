package agent

import (
	"context"
	"errors"
	"reflect"
	"testing"
)

func TestReconcileRejectsLiveWireGuard(t *testing.T) {
	firewall, kernel := verifyingFirewall(t)
	ctx := context.Background()

	if err := firewall.Seal(ctx, firewallTestName); err != nil {
		t.Fatal(err)
	}

	var inspected []string
	firewall.manager.run = func(_ context.Context, args ...string) ([]byte, error) {
		inspected = args
		return []byte(`[{"ifname":"lo"}, {"ifname":"wg0", "linkinfo":{"info_kind":"wireguard"}}]`), nil
	}

	before := len(kernel.applied)

	if err := firewall.Reconcile(ctx, firewallTestName); !errors.Is(err, ErrFirewallReconcileRequiresOffline) {
		t.Fatalf("live tunnel accepted: %v", err)
	}

	if len(kernel.applied) != before {
		t.Fatal("firewall was modified around a live tunnel")
	}

	want := []string{"-n", firewallTestName, "-details", "-json", "link", "show"}
	if !reflect.DeepEqual(inspected, want) {
		t.Fatalf("links were not read from the lab namespace: %v", inspected)
	}
}

func TestReconcileRejectsUnverifiableLinks(t *testing.T) {
	tests := []struct {
		name   string
		output string
		err    error
	}{
		{name: "invalid JSON", output: "not-json"},
		{name: "empty listing", output: "[]"},
		{name: "missing loopback", output: `[{"ifname":"eth0"}]`},
		{name: "missing link name", output: `[{"ifname":"lo"}, {"ifname":""}]`},
		{name: "different WireGuard name", output: `[{"ifname":"lo"}, {"ifname":"wgtunnel", "linkinfo":{"info_kind":"wireguard"}}]`},
		{name: "read failure", err: errors.New("netlink permission denied")},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			firewall, kernel := verifyingFirewall(t)
			ctx := context.Background()

			if err := firewall.Seal(ctx, firewallTestName); err != nil {
				t.Fatal(err)
			}

			firewall.manager.run = func(context.Context, ...string) ([]byte, error) {
				return []byte(tt.output), tt.err
			}

			before := len(kernel.applied)

			if err := firewall.Reconcile(ctx, firewallTestName); !errors.Is(err, ErrFirewallReconcileRequiresOffline) {
				t.Fatalf("unverifiable links accepted: %v", err)
			}

			if len(kernel.applied) != before {
				t.Fatal("ruleset was modified")
			}
		})
	}
}

func TestReconcileAllowsOfflineNamespace(t *testing.T) {
	firewall, _ := verifyingFirewall(t)
	ctx := context.Background()

	if err := firewall.Seal(ctx, firewallTestName); err != nil {
		t.Fatal(err)
	}

	if err := firewall.Reconcile(ctx, firewallTestName); err != nil {
		t.Fatal(err)
	}

	if err := firewall.Verify(ctx, firewallTestName); err != nil {
		t.Fatal(err)
	}
}
