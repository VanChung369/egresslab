package agent

import (
	"context"
	"errors"
	"net/netip"
	"strings"
	"testing"
)

// Real captures from a lab namespace (iproute2 6.1, Linux 6.8, Ubuntu 24.04): wg0 with
// 10.2.0.2/32, MTU 1280, and "default dev wg0".
const (
	managedAddressFixture = `[{"ifindex":2,"ifname":"wg0","flags":["POINTOPOINT","NOARP","UP","LOWER_UP"],"mtu":1280,` +
		`"qdisc":"noqueue","operstate":"UNKNOWN","group":"default","txqlen":1000,"addr_info":[{"family":"inet",` +
		`"local":"10.2.0.2","prefixlen":32,"scope":"global","label":"wg0","valid_life_time":4294967295,` +
		`"preferred_life_time":4294967295}]}]`

	managedRulesFixture = `[{"priority":0,"src":"all","table":"local"},{"priority":32766,"src":"all","table":"main"},` +
		`{"priority":32767,"src":"all","table":"default"}]`

	managedRoutesFixture = `[{"dst":"default","dev":"wg0","scope":"link","flags":[]},{"type":"local","dst":"10.2.0.2",` +
		`"dev":"wg0","table":"local","protocol":"kernel","scope":"host","prefsrc":"10.2.0.2","flags":[]}]`

	managedSelectionFixture = `[{"dst":"1.1.1.1","dev":"wg0","prefsrc":"10.2.0.2","flags":[],"uid":0,"cache":[]}]`

	// The same capture with the address as 10.2.0.2/24.
	managedSubnetRoutesFixture = `[{"dst":"default","dev":"wg0","scope":"link","flags":[]},{"dst":"10.2.0.0/24",` +
		`"dev":"wg0","protocol":"kernel","scope":"link","prefsrc":"10.2.0.2","flags":[]},{"type":"local",` +
		`"dst":"10.2.0.2","dev":"wg0","table":"local","protocol":"kernel","scope":"host","prefsrc":"10.2.0.2",` +
		`"flags":[]},{"type":"broadcast","dst":"10.2.0.255","dev":"wg0","table":"local","protocol":"kernel",` +
		`"scope":"link","prefsrc":"10.2.0.2","flags":[]}]`

	// The capture's loopback entry after "ip link set lo up".
	managedLoopbackEntry = `{"ifindex":1,"ifname":"lo","flags":["LOOPBACK","UP","LOWER_UP"],"mtu":65536,` +
		`"qdisc":"noqueue","operstate":"UNKNOWN","group":"default","txqlen":1000,"addr_info":[{"family":"inet",` +
		`"local":"127.0.0.1","prefixlen":8,"scope":"host","label":"lo","valid_life_time":4294967295,` +
		`"preferred_life_time":4294967295}]},`
)

var managedNetworkReadbacks = map[string]string{
	"-4 -json addr show":            managedAddressFixture,
	"-4 -json rule show":            managedRulesFixture,
	"-4 -json route show table all": managedRoutesFixture,
	"-4 -json route get 1.1.1.1":    managedSelectionFixture,
}

func managedTestPolicy(prefix string) managedNetworkPolicy {
	return managedNetworkPolicy{addresses: []netip.Prefix{netip.MustParsePrefix(prefix)}, mtu: 1280}
}

func TestManagedNetworkAcceptsKernelCaptures(t *testing.T) {
	policy := managedTestPolicy("10.2.0.2/32")

	for name, err := range map[string]error{
		"addresses":       verifyManagedAddresses([]byte(managedAddressFixture), policy),
		"empty link":      verifyManagedAddresses([]byte("[{},"+managedAddressFixture[1:]), policy),
		"rules":           verifyManagedRules([]byte(managedRulesFixture)),
		"routes":          verifyManagedRoutes([]byte(managedRoutesFixture), policy),
		"route selection": verifyManagedRouteSelection([]byte(managedSelectionFixture), policy),
	} {
		if err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestManagedNetworkRejectsDrift(t *testing.T) {
	const (
		addr      = "-4 -json addr show"
		rule      = "-4 -json rule show"
		route     = "-4 -json route show table all"
		selection = "-4 -json route get 1.1.1.1"
	)

	replace := func(fixture, old, new string) string { return strings.Replace(fixture, old, new, 1) }

	tests := []struct {
		name    string
		command string
		value   string
	}{
		{"MTU changed", addr, replace(managedAddressFixture, `"mtu":1280`, `"mtu":1500`)},
		{"interface down", addr, replace(managedAddressFixture, `"UP",`, "")},
		{"address changed", addr, replace(managedAddressFixture, "10.2.0.2", "10.2.0.3")},
		{"prefix changed", addr, replace(managedAddressFixture, `"prefixlen":32`, `"prefixlen":24`)},
		{"address expires", addr, replace(managedAddressFixture, `"valid_life_time":4294967295`, `"valid_life_time":60`)},
		{"loopback address", addr, "[" + managedLoopbackEntry + managedAddressFixture[1:]},
		{"no wg0", addr, "[]"},
		{"rule attribute added", rule,
			replace(managedRulesFixture, `"table":"main"`, `"table":"main","fwmark":"0x100"`)},
		{"extra rule", rule, replace(managedRulesFixture, "[", `[{"priority":100,"src":"all","table":"100"},`)},
		{"main rule removed", rule, replace(managedRulesFixture, `{"priority":32766,"src":"all","table":"main"},`, "")},
		{"default gateway added", route,
			replace(managedRoutesFixture, `"dst":"default"`, `"dst":"default","gateway":"10.2.0.1"`)},
		{"route metric added", route, replace(managedRoutesFixture, `"dst":"default"`, `"dst":"default","metric":5`)},
		{"foreign routing table", route, replace(managedRoutesFixture, `"dst":"default"`, `"dst":"default","table":"100"`)},
		{"default via another device", route, replace(managedRoutesFixture, `"dev":"wg0"`, `"dev":"eth0"`)},
		{"default route missing", route,
			replace(managedRoutesFixture, `{"dst":"default","dev":"wg0","scope":"link","flags":[]},`, "")},
		{"local route missing", route, `[{"dst":"default","dev":"wg0","scope":"link","flags":[]}]`},
		{"wrong egress device", selection, replace(managedSelectionFixture, "wg0", "eth0")},
		{"wrong source address", selection, replace(managedSelectionFixture, "10.2.0.2", "192.168.0.2")},
		{"lookup via gateway", selection,
			replace(managedSelectionFixture, `"dev":"wg0"`, `"gateway":"10.2.0.1","dev":"wg0"`)},
		{"malformed routing data", route, "null"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b, kernel := newManagedTunnelFixture(t)
			ctx := context.Background()

			if err := b.connectConfig(ctx, vpnTestNS, vpnTestConfig(t)); err != nil {
				t.Fatal(err)
			}

			kernel.networkOverrides[tt.command] = tt.value

			if err := b.VerifyConfigured(ctx, vpnTestNS); !errors.Is(err, ErrManagedNetworkDrift) {
				t.Fatalf("drift accepted: %v", err)
			}

			if b.active == nil || !b.active.faulted {
				t.Fatal("network drift did not fault the tunnel")
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

func TestManagedNetworkSupportsConnectedSubnet(t *testing.T) {
	policy := managedTestPolicy("10.2.0.2/24")

	if err := verifyManagedRoutes([]byte(managedSubnetRoutesFixture), policy); err != nil {
		t.Fatal(err)
	}

	for name, routes := range map[string]string{
		"foreign broadcast": strings.Replace(managedSubnetRoutesFixture, "10.2.0.255", "10.3.0.255", 1),
		"connected route missing": strings.Replace(managedSubnetRoutesFixture,
			`{"dst":"10.2.0.0/24","dev":"wg0","protocol":"kernel","scope":"link","prefsrc":"10.2.0.2","flags":[]},`, "", 1),
		"connected route from another source": strings.Replace(managedSubnetRoutesFixture,
			`"prefsrc":"10.2.0.2","flags":[]},{"type":"local"`, `"prefsrc":"10.2.0.9","flags":[]},{"type":"local"`, 1),
	} {
		if err := verifyManagedRoutes([]byte(routes), policy); !errors.Is(err, ErrManagedNetworkDrift) {
			t.Errorf("%s accepted: %v", name, err)
		}
	}

	// A /32 plan has no connected route, so the /24 capture is drift there.
	if err := verifyManagedRoutes([]byte(managedSubnetRoutesFixture), managedTestPolicy("10.2.0.2/32")); err == nil {
		t.Fatal("connected route accepted for a /32 address")
	}
}

func TestManagedNetworkReadbackRollback(t *testing.T) {
	b, kernel := newManagedTunnelFixture(t)
	kernel.networkReadError = "-4 -json route show table all"

	err := b.connectConfig(context.Background(), vpnTestNS, vpnTestConfig(t))
	if !errors.Is(err, ErrManagedNetworkDrift) {
		t.Fatalf("unexpected error: %v", err)
	}

	if b.active != nil || kernel.name != "" || kernel.tableRemovals != 1 {
		t.Fatal("rollback incomplete")
	}
}

func TestManagedNetworkMTU(t *testing.T) {
	t.Run("configured", func(t *testing.T) {
		b, kernel := newManagedTunnelFixture(t)

		if err := b.connectConfig(context.Background(), vpnTestNS, vpnTestConfig(t)); err != nil {
			t.Fatal(err)
		}

		if b.active.network.mtu != 1280 || kernel.mtu != "1280" {
			t.Fatalf("configured MTU not applied: %d, %q", b.active.network.mtu, kernel.mtu)
		}
	})

	t.Run("default", func(t *testing.T) {
		b, kernel := newManagedTunnelFixture(t)

		cfg := vpnTestConfig(t, [2]string{"MTU = 1280\n", ""})

		if err := b.connectConfig(context.Background(), vpnTestNS, cfg); err != nil {
			t.Fatal(err)
		}

		if b.active.network.mtu != managedDefaultMTU || kernel.mtu != "1420" {
			t.Fatalf("default MTU was not set explicitly: %d, %q", b.active.network.mtu, kernel.mtu)
		}
	})
}

func TestManagedNetworkPolicyRefusesUnsupportedAddresses(t *testing.T) {
	const line = "Address = 10.2.0.2/32, fd00::2/128"

	for name, address := range map[string]string{
		"link-local":        "Address = 169.254.1.2/32",
		"loopback":          "Address = 127.0.0.2/32",
		"duplicate address": "Address = 10.2.0.2/32, 10.2.0.2/24",
		"zero prefix":       "Address = 10.2.0.2/0",
	} {
		cfg := vpnTestConfig(t, [2]string{line, address})

		if err := CheckVPNLabCompatibility(cfg); !errors.Is(err, ErrUnsupportedTunnelConfig) {
			t.Errorf("%s: %v", name, err)
		}

		if summary := cfg.Summary(); summary.VPNLabCompatible || summary.VPNLabIssue == "" {
			t.Errorf("%s reported compatible", name)
		}

		b, kernel := newManagedTunnelFixture(t)
		if err := b.connectConfig(context.Background(), vpnTestNS, cfg); !errors.Is(err, ErrUnsupportedTunnelConfig) {
			t.Errorf("%s connected: %v", name, err)
		}

		requireUntouched(t, b, kernel)
	}

	if err := CheckVPNLabCompatibility(vpnTestConfig(t, [2]string{line, "Address = 10.2.0.2/24"})); err != nil {
		t.Fatalf("connected subnet refused: %v", err)
	}
}
