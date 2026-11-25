package agent

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"time"
)

const (
	endpointLookupTimeout = 5 * time.Second
	maxEndpointAnswers    = 16
)

var ErrEndpointResolution = errors.New("WireGuard endpoint resolution failed")

type endpointLookup func(ctx context.Context, network, host string) ([]netip.Addr, error)

// newEndpointLookup uses the Linux runtime's own resolver configuration; no DNS server is
// hardcoded.
func newEndpointLookup() endpointLookup {
	r := &net.Resolver{PreferGo: true, StrictErrors: true}

	return r.LookupNetIP
}

// Special-purpose IPv4 ranges (IANA registry) that IsGlobalUnicast and IsPrivate do not cover.
var blockedDNSPrefixes = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("192.0.0.0/24"),
	netip.MustParsePrefix("192.0.2.0/24"),
	netip.MustParsePrefix("192.88.99.0/24"),
	netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("198.51.100.0/24"),
	netip.MustParsePrefix("203.0.113.0/24"),
	netip.MustParsePrefix("240.0.0.0/4"),
}

var blockedEndpointSuffixes = []string{
	".local", ".localhost", ".internal", ".home.arpa", ".invalid", ".test", ".example", ".onion",
}

func allowedDNSAddress(ip netip.Addr) bool {
	if !ip.Is4() || !ip.IsGlobalUnicast() || ip.IsPrivate() {
		return false
	}

	for _, prefix := range blockedDNSPrefixes {
		if prefix.Contains(ip) {
			return false
		}
	}

	return true
}

// validateManagedEndpoint is static: it never performs network I/O. An IPv4 literal (staged by
// root) keeps the earlier policy and is returned as is; a zero endpoint with no error means the
// hostname must be resolved.
func validateManagedEndpoint(host string, port uint16) (netip.AddrPort, error) {
	if port == 0 {
		return netip.AddrPort{}, fmt.Errorf("%w: endpoint port missing", ErrUnsupportedTunnelConfig)
	}

	if ip, err := netip.ParseAddr(host); err == nil {
		if !ip.Is4() || !ip.IsGlobalUnicast() {
			return netip.AddrPort{}, fmt.Errorf("%w: endpoint must be a unicast IPv4 address or a DNS name",
				ErrUnsupportedTunnelConfig)
		}

		return netip.AddrPortFrom(ip, port), nil
	}

	host = strings.ToLower(host)
	labels := strings.Split(host, ".")
	top := labels[len(labels)-1]

	// A name needs a dot and an alphabetic top-level label, so "127.1" is never treated as one.
	if !validWGHostname(host) || len(labels) < 2 || !strings.ContainsAny(top, "abcdefghijklmnopqrstuvwxyz") {
		return netip.AddrPort{}, fmt.Errorf("%w: endpoint needs an IPv4 address or a DNS name",
			ErrUnsupportedTunnelConfig)
	}

	for _, suffix := range blockedEndpointSuffixes {
		if strings.HasSuffix("."+host, suffix) {
			return netip.AddrPort{}, fmt.Errorf("%w: endpoint uses a local or reserved domain",
				ErrUnsupportedTunnelConfig)
		}
	}

	return netip.AddrPort{}, nil
}

// resolveManagedEndpoint resolves a hostname once, before a tunnel is created, and pins the
// lowest acceptable IPv4 answer. Any refused answer refuses the whole response. Errors name the
// cause, never an address.
func resolveManagedEndpoint(
	ctx context.Context,
	host string,
	port uint16,
	lookup endpointLookup,
) (netip.AddrPort, error) {
	if ctx.Err() != nil {
		return netip.AddrPort{}, fmt.Errorf("%w: cancelled", ErrEndpointResolution)
	}

	literal, err := validateManagedEndpoint(host, port)
	if err != nil || literal.IsValid() {
		return literal, err
	}

	if lookup == nil {
		return netip.AddrPort{}, fmt.Errorf("%w: no resolver", ErrEndpointResolution)
	}

	dnsCtx, cancel := context.WithTimeout(ctx, endpointLookupTimeout)
	defer cancel()

	// The trailing dot makes the name absolute, so no search domain is appended.
	answers, err := lookup(dnsCtx, "ip4", strings.ToLower(host)+".")

	switch {
	case err != nil || dnsCtx.Err() != nil:
		return netip.AddrPort{}, fmt.Errorf("%w: lookup failed", ErrEndpointResolution)
	case len(answers) == 0:
		return netip.AddrPort{}, fmt.Errorf("%w: no IPv4 answer", ErrEndpointResolution)
	case len(answers) > maxEndpointAnswers:
		return netip.AddrPort{}, fmt.Errorf("%w: too many answers", ErrEndpointResolution)
	}

	var selected netip.Addr

	for _, ip := range answers {
		if !allowedDNSAddress(ip) {
			return netip.AddrPort{}, fmt.Errorf("%w: answer in a refused address range", ErrEndpointResolution)
		}

		if !selected.IsValid() || ip.Compare(selected) < 0 {
			selected = ip
		}
	}

	return netip.AddrPortFrom(selected, port), nil
}

// planManagedVPNTunnel is the managed tunnel's static compatibility check: it never performs
// network I/O, and leaves a hostname endpoint zero until resolveManagedEndpoint runs.
func planManagedVPNTunnel(cfg *ImportedWireGuardConfig) (vpnTunnelPlan, error) {
	plan, err := planVPNNetwork(cfg)
	if err != nil {
		return vpnTunnelPlan{}, err
	}

	if plan.endpoint, err = validateManagedEndpoint(cfg.endpointHost, cfg.endpointPort); err != nil {
		return vpnTunnelPlan{}, err
	}

	if _, err := newManagedNetworkPolicy(cfg, plan); err != nil {
		return vpnTunnelPlan{}, err
	}

	return plan, nil
}
