package agent

import (
	"context"
	"errors"
	"net/netip"
	"testing"
	"time"
)

// The resolvers here are fakes: no DNS query or packet is sent to any address.
func fixedLookup(answers ...string) endpointLookup {
	return func(context.Context, string, string) ([]netip.Addr, error) {
		ips := make([]netip.Addr, 0, len(answers))
		for _, answer := range answers {
			ips = append(ips, netip.MustParseAddr(answer))
		}

		return ips, nil
	}
}

func TestManagedEndpoint(t *testing.T) {
	ctx := context.Background()

	literal, err := resolveManagedEndpoint(ctx, "198.51.100.7", 51820, nil)
	if err != nil || literal.String() != "198.51.100.7:51820" {
		t.Fatal(literal, err)
	}

	calls := 0

	lookup := func(ctx context.Context, network, host string) ([]netip.Addr, error) {
		calls++

		if network != "ip4" || host != "vpn.example.com." {
			t.Fatal(network, host)
		}

		deadline, ok := ctx.Deadline()
		if !ok || time.Until(deadline) > endpointLookupTimeout {
			t.Fatal("missing lookup deadline")
		}

		return fixedLookup("9.9.9.9", "8.8.8.8", "8.8.8.8")(ctx, network, host)
	}

	ip, err := resolveManagedEndpoint(ctx, "VPN.Example.com", 51820, lookup)
	if err != nil || ip.String() != "8.8.8.8:51820" || calls != 1 {
		t.Fatal(ip, err, calls)
	}
}

func TestManagedEndpointRefusals(t *testing.T) {
	for _, raw := range []string{
		"10.0.0.1", "172.16.0.1", "192.168.0.1", "127.0.0.1", "169.254.169.254", "100.64.0.1",
		"198.18.0.1", "192.0.2.1", "198.51.100.7", "203.0.113.1", "240.0.0.1", "0.0.0.1",
		"224.0.0.1", "255.255.255.255", "::ffff:8.8.8.8", "2001:db8::1",
	} {
		t.Run(raw, func(t *testing.T) {
			_, err := resolveManagedEndpoint(context.Background(), "vpn.example.com", 51820,
				fixedLookup("8.8.8.8", raw))

			if !errors.Is(err, ErrEndpointResolution) {
				t.Fatal("unsafe DNS answer accepted", err)
			}
		})
	}

	for _, host := range []string{
		"localhost", "vpn.local", "host.internal", "foo.home.arpa", "x.invalid", "x.test", "vpn.example",
		"x.onion", "::1", "2001:db8::7", "a b.com", "127.1", "1.2.3", "vpn",
	} {
		if _, err := validateManagedEndpoint(host, 51820); !errors.Is(err, ErrUnsupportedTunnelConfig) {
			t.Errorf("unsafe endpoint %q accepted: %v", host, err)
		}
	}

	if _, err := validateManagedEndpoint("vpn.example.com", 0); err == nil {
		t.Error("port 0 accepted")
	}
}

func TestManagedEndpointLookupFailures(t *testing.T) {
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()

	tests := map[string]struct {
		ctx    context.Context
		lookup endpointLookup
	}{
		"DNS error": {context.Background(), func(context.Context, string, string) ([]netip.Addr, error) {
			return nil, errors.New("DNS failed")
		}},
		"empty response": {context.Background(), fixedLookup()},
		"too many results": {context.Background(), fixedLookup(
			"8.8.8.8", "8.8.8.8", "8.8.8.8", "8.8.8.8", "8.8.8.8", "8.8.8.8", "8.8.8.8", "8.8.8.8", "8.8.8.8",
			"8.8.8.8", "8.8.8.8", "8.8.8.8", "8.8.8.8", "8.8.8.8", "8.8.8.8", "8.8.8.8", "8.8.8.8")},
		"no resolver": {context.Background(), nil},
		"cancelled":   {cancelled, fixedLookup("8.8.8.8")},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			_, err := resolveManagedEndpoint(tt.ctx, "vpn.example.com", 51820, tt.lookup)
			if !errors.Is(err, ErrEndpointResolution) {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

func TestManagedEndpointCompatibility(t *testing.T) {
	tests := []struct {
		name            string
		endpoint        string
		allowedIPs      string
		legacy, managed bool
	}{
		{"IPv4 literal", "198.51.100.7:51820", "0.0.0.0/0, ::/0", true, true},
		{"hostname", "vpn.example.com:51820", "0.0.0.0/0, ::/0", false, true},
		{"IPv6 endpoint", "[2001:db8::42]:51820", "0.0.0.0/0, ::/0", false, false},
		{"reserved domain", "vpn.internal:51820", "0.0.0.0/0, ::/0", false, false},
		{"no IPv4 default route", "vpn.example.com:51820", "10.0.0.0/8", false, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := mustParse(t, replaced("vpn.example.com:51820", tt.endpoint))
			cfg.allowedIPs = mustParse(t, replaced("0.0.0.0/0, ::/0", tt.allowedIPs)).allowedIPs

			summary := cfg.Summary()
			if summary.VPNLabCompatible != tt.legacy || summary.ManagedVPNCompatible != tt.managed {
				t.Fatalf("legacy %v, managed %v", summary.VPNLabCompatible, summary.ManagedVPNCompatible)
			}

			if plan, err := planManagedVPNTunnel(cfg); tt.managed && tt.endpoint == "vpn.example.com:51820" &&
				(err != nil || plan.endpoint.IsValid()) {
				t.Fatal("static planning resolved a hostname")
			}
		})
	}
}
