package agent

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"slices"
	"strconv"
)

var ErrManagedNetworkDrift = errors.New("managed tunnel network configuration drifted")

const (
	managedDefaultMTU = 1420
	managedRouteProbe = "1.1.1.1"
	foreverLifetime   = 4294967295
)

// managedNetworkPolicy is the IPv4 network state the lab namespace must report, written down from
// the vault config before the tunnel exists and never learned from the kernel.
type managedNetworkPolicy struct {
	addresses []netip.Prefix
	mtu       int
}

func newManagedNetworkPolicy(cfg *ImportedWireGuardConfig, plan vpnTunnelPlan) (managedNetworkPolicy, error) {
	if cfg == nil || len(plan.addresses) == 0 {
		return managedNetworkPolicy{}, ErrUnsupportedTunnelConfig
	}

	p := managedNetworkPolicy{addresses: slices.Clone(plan.addresses), mtu: cfg.mtu}

	if p.mtu == 0 {
		p.mtu = managedDefaultMTU
	}

	if p.mtu < 576 || p.mtu > 9000 {
		return managedNetworkPolicy{}, fmt.Errorf("%w: MTU must be between 576 and 9000", ErrUnsupportedTunnelConfig)
	}

	seen := make(map[netip.Addr]bool)

	for _, a := range p.addresses {
		if !a.IsValid() || !a.Addr().Is4() || !a.Addr().IsGlobalUnicast() || a.Bits() == 0 || seen[a.Addr()] {
			return managedNetworkPolicy{}, fmt.Errorf(
				"%w: interface addresses must be distinct unicast IPv4 prefixes", ErrUnsupportedTunnelConfig)
		}

		seen[a.Addr()] = true
	}

	return p, nil
}

func (p managedNetworkPolicy) address(ip netip.Addr) (netip.Prefix, bool) {
	for _, a := range p.addresses {
		if a.Addr() == ip {
			return a, true
		}
	}

	return netip.Prefix{}, false
}

// strictNetworkList refuses unknown attributes (gateway, fwmark, metric, nexthop, ...) rather than
// accept kernel state this check does not understand.
func strictNetworkList[T any](data []byte) ([]T, error) {
	var result []T

	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()

	if err := decoder.Decode(&result); err != nil || result == nil {
		return nil, ErrManagedNetworkDrift
	}

	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return nil, ErrManagedNetworkDrift
	}

	return result, nil
}

type managedIPv4Address struct {
	Family            string `json:"family"`
	Local             string `json:"local"`
	PrefixLen         int    `json:"prefixlen"`
	Scope             string `json:"scope"`
	Label             string `json:"label"`
	Secondary         bool   `json:"secondary"`
	ValidLifetime     uint64 `json:"valid_life_time"`
	PreferredLifetime uint64 `json:"preferred_life_time"`
}

// verifyManagedAddresses reads "ip -4 -json addr show": only wg0 may carry IPv4 addresses, exactly
// the planned ones, with the planned MTU, and up as a point-to-point link without ARP. UP is the
// administrative state only; it says nothing about a handshake.
func verifyManagedAddresses(data []byte, p managedNetworkPolicy) error {
	var entries []json.RawMessage
	if err := json.Unmarshal(data, &entries); err != nil || entries == nil {
		return ErrManagedNetworkDrift
	}

	seenLinks := make(map[string]bool)
	seenAddresses := make(map[netip.Addr]bool)

	for _, entry := range entries {
		// An empty object names no link and carries no address.
		if bytes.Equal(bytes.TrimSpace(entry), []byte("{}")) {
			continue
		}

		var link struct {
			Name      string          `json:"ifname"`
			MTU       int             `json:"mtu"`
			Flags     []string        `json:"flags"`
			Addresses json.RawMessage `json:"addr_info"`
		}

		if err := json.Unmarshal(entry, &link); err != nil || link.Name == "" || seenLinks[link.Name] {
			return ErrManagedNetworkDrift
		}

		seenLinks[link.Name] = true

		addresses, err := strictNetworkList[managedIPv4Address](link.Addresses)
		if err != nil {
			return err
		}

		// The sealed lab keeps loopback down and without an IPv4 address.
		if link.Name == "lo" && len(addresses) == 0 {
			continue
		}

		if link.Name != labWGInterface || link.MTU != p.mtu ||
			!slices.Contains(link.Flags, "UP") ||
			!slices.Contains(link.Flags, "POINTOPOINT") ||
			!slices.Contains(link.Flags, "NOARP") {
			return ErrManagedNetworkDrift
		}

		for _, a := range addresses {
			ip, err := netip.ParseAddr(a.Local)
			expected, ok := p.address(ip)

			if err != nil || !ok || seenAddresses[ip] ||
				a.Family != "inet" ||
				a.Scope != "global" ||
				a.PrefixLen != expected.Bits() ||
				(a.Label != "" && a.Label != labWGInterface) ||
				a.ValidLifetime != foreverLifetime ||
				a.PreferredLifetime != foreverLifetime {
				return ErrManagedNetworkDrift
			}

			seenAddresses[ip] = true
		}
	}

	if !seenLinks[labWGInterface] || len(seenAddresses) != len(p.addresses) {
		return ErrManagedNetworkDrift
	}

	return nil
}

// verifyManagedRules requires exactly the kernel's three default IPv4 rules, so no rule can steer
// traffic by source, fwmark, UID or interface into another table.
func verifyManagedRules(data []byte) error {
	type rule struct {
		Priority *int   `json:"priority"`
		Source   string `json:"src"`
		Table    string `json:"table"`
	}

	rules, err := strictNetworkList[rule](data)
	if err != nil || len(rules) != 3 {
		return ErrManagedNetworkDrift
	}

	expected := []struct {
		priority int
		table    string
	}{{0, "local"}, {32766, "main"}, {32767, "default"}}

	for i, want := range expected {
		r := rules[i]

		if r.Priority == nil || *r.Priority != want.priority || r.Source != "all" || r.Table != want.table {
			return ErrManagedNetworkDrift
		}
	}

	return nil
}

type managedIPv4Route struct {
	Destination     string   `json:"dst"`
	Device          string   `json:"dev"`
	Table           string   `json:"table"`
	Type            string   `json:"type"`
	Protocol        string   `json:"protocol"`
	Scope           string   `json:"scope"`
	PreferredSource string   `json:"prefsrc"`
	Flags           []string `json:"flags"`
}

func hostRouteAddress(raw string) (netip.Addr, error) {
	if ip, err := netip.ParseAddr(raw); err == nil && ip.Is4() {
		return ip, nil
	}

	if p, err := netip.ParsePrefix(raw); err == nil && p.Addr().Is4() && p.Bits() == 32 {
		return p.Addr(), nil
	}

	return netip.Addr{}, ErrManagedNetworkDrift
}

// derivedBroadcast reports whether dst is the network or broadcast address of a planned prefix
// that holds src. /31 and /32 prefixes have no broadcast routes.
func derivedBroadcast(dst, src netip.Addr, p managedNetworkPolicy) bool {
	for _, a := range p.addresses {
		if a.Bits() >= 31 || !a.Contains(src) {
			continue
		}

		first := a.Masked().Addr().As4()

		var last [4]byte
		binary.BigEndian.PutUint32(last[:], binary.BigEndian.Uint32(first[:])|(^uint32(0)>>a.Bits()))

		if dst == netip.AddrFrom4(first) || dst == netip.AddrFrom4(last) {
			return true
		}
	}

	return false
}

// verifyManagedRoutes reads "ip -4 -json route show table all". Every route must use wg0. The main
// table holds one default route and the kernel's connected route for each planned prefix shorter
// than /32; the local table holds only the routes the kernel derives from the planned addresses.
// No other table, gateway or route attribute is accepted.
func verifyManagedRoutes(data []byte, p managedNetworkPolicy) error {
	routes, err := strictNetworkList[managedIPv4Route](data)
	if err != nil {
		return err
	}

	connected := make(map[netip.Prefix]bool)
	local := make(map[netip.Addr]bool)

	for _, a := range p.addresses {
		local[a.Addr()] = false

		if a.Bits() < 32 {
			connected[a.Masked()] = false
		}
	}

	defaultSeen := false
	broadcasts := make(map[netip.Addr]bool)

	for _, r := range routes {
		if r.Device != labWGInterface || len(r.Flags) != 0 {
			return ErrManagedNetworkDrift
		}

		// iproute2 omits the main table.
		if r.Table == "" || r.Table == "main" {
			if (r.Type != "" && r.Type != "unicast") || r.Scope != "link" {
				return ErrManagedNetworkDrift
			}

			if r.Destination == "default" || r.Destination == "0.0.0.0/0" {
				if defaultSeen || (r.Protocol != "" && r.Protocol != "boot") || r.PreferredSource != "" {
					return ErrManagedNetworkDrift
				}

				defaultSeen = true

				continue
			}

			prefix, err := netip.ParsePrefix(r.Destination)
			seen, exists := connected[prefix]
			src, srcErr := netip.ParseAddr(r.PreferredSource)
			_, known := p.address(src)

			if err != nil || !exists || seen || r.Protocol != "kernel" || srcErr != nil || !known ||
				!prefix.Contains(src) {
				return ErrManagedNetworkDrift
			}

			connected[prefix] = true

			continue
		}

		if r.Table != "local" || r.Protocol != "kernel" {
			return ErrManagedNetworkDrift
		}

		dst, err := hostRouteAddress(r.Destination)
		src, srcErr := netip.ParseAddr(r.PreferredSource)
		_, known := p.address(src)

		if err != nil || srcErr != nil || !known {
			return ErrManagedNetworkDrift
		}

		switch r.Type {
		case "local":
			a, exists := p.address(dst)

			if !exists || local[dst] || r.Scope != "host" || !a.Contains(src) {
				return ErrManagedNetworkDrift
			}

			local[dst] = true

		case "broadcast":
			if r.Scope != "link" || broadcasts[dst] || !derivedBroadcast(dst, src, p) {
				return ErrManagedNetworkDrift
			}

			broadcasts[dst] = true

		default:
			return ErrManagedNetworkDrift
		}
	}

	if !defaultSeen {
		return ErrManagedNetworkDrift
	}

	for _, seen := range local {
		if !seen {
			return ErrManagedNetworkDrift
		}
	}

	for _, seen := range connected {
		if !seen {
			return ErrManagedNetworkDrift
		}
	}

	return nil
}

// verifyManagedRouteSelection reads "ip -4 -json route get 1.1.1.1", a kernel lookup that sends no
// packet: it must choose wg0 with a planned source address. It does not prove that traffic flows.
func verifyManagedRouteSelection(data []byte, p managedNetworkPolicy) error {
	type selection struct {
		Destination     string   `json:"dst"`
		Device          string   `json:"dev"`
		Table           string   `json:"table"`
		Type            string   `json:"type"`
		PreferredSource string   `json:"prefsrc"`
		Flags           []string `json:"flags"`
		UID             uint32   `json:"uid"`
		Cache           []string `json:"cache"`
	}

	routes, err := strictNetworkList[selection](data)
	if err != nil || len(routes) != 1 {
		return ErrManagedNetworkDrift
	}

	r := routes[0]

	src, err := netip.ParseAddr(r.PreferredSource)
	_, known := p.address(src)

	if err != nil || !known ||
		r.Destination != managedRouteProbe ||
		r.Device != labWGInterface ||
		(r.Table != "" && r.Table != "main") ||
		(r.Type != "" && r.Type != "unicast") ||
		len(r.Flags) != 0 ||
		len(r.Cache) != 0 {
		return ErrManagedNetworkDrift
	}

	return nil
}

// verifyNetworkLocked reads addresses, rules, routes and the route lookup back from the lab
// namespace. A value read is never put in an error. The caller must hold manager.mu.
func (b *ManagedTunnelBackend) verifyNetworkLocked(ctx context.Context, t *managedTunnel) error {
	checks := []struct {
		name   string
		args   []string
		verify func([]byte) error
	}{
		{"addresses", []string{"-4", "-json", "addr", "show"},
			func(data []byte) error { return verifyManagedAddresses(data, t.network) }},
		{"rules", []string{"-4", "-json", "rule", "show"}, verifyManagedRules},
		{"routes", []string{"-4", "-json", "route", "show", "table", "all"},
			func(data []byte) error { return verifyManagedRoutes(data, t.network) }},
		{"route selection", []string{"-4", "-json", "route", "get", managedRouteProbe},
			func(data []byte) error { return verifyManagedRouteSelection(data, t.network) }},
	}

	for _, check := range checks {
		commandCtx, cancel := context.WithTimeout(ctx, netNSCommandTimeout)
		data, err := b.sealed.manager.run(commandCtx, append([]string{"-n", t.namespace}, check.args...)...)
		cancel()

		if err != nil || check.verify(data) != nil {
			return fmt.Errorf("%w: %s", ErrManagedNetworkDrift, check.name)
		}
	}

	return nil
}

// applyDefaultMTULocked sets the managed default when the config names no MTU, so the expected
// value never depends on the kernel's own default. The caller must hold manager.mu.
func (b *ManagedTunnelBackend) applyDefaultMTULocked(
	ctx context.Context,
	t *managedTunnel,
	cfg *ImportedWireGuardConfig,
) error {
	if cfg.mtu != 0 {
		return nil
	}

	return b.vpn.ip(ctx, "-n", t.namespace, "link", "set", labWGInterface, "mtu", strconv.Itoa(t.network.mtu))
}
