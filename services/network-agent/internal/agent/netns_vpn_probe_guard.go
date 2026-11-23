package agent

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
)

var ErrVPNIsolationNotVerified = errors.New("VPN egress isolation not verified")

// verifyProbeIsolation checks the two kernel firewall boundaries the VPN lab relies on: the
// lab namespace's default-deny table and the host-side underlay table plus wg0's fwmark.
//
// Both are needed: an accept in one nftables base chain does not bypass other base chains on
// the same hook (a drop anywhere is final), so neither boundary can stand in for the other.
func (l *VPNEgressLab) verifyProbeIsolation(ctx context.Context, namespace string) error {
	if err := l.firewall.Verify(ctx, namespace); err != nil {
		return fmt.Errorf("%w: namespace firewall: %w", ErrVPNIsolationNotVerified, err)
	}

	if err := l.VerifyUnderlay(ctx, namespace); err != nil {
		return fmt.Errorf("%w: WireGuard underlay: %w", ErrVPNIsolationNotVerified, err)
	}

	return nil
}

// ProbeVerified runs a single diagnostic probe through the lab namespace. Both firewall
// boundaries must match their expected kernel state before and after the request; otherwise
// no IP is returned, so a result taken while isolation changed is never used.
//
// This is a before/after check for the lab, not continuous enforcement, and it must not
// authorize a production proxy.
func (l *VPNEgressLab) ProbeVerified(
	ctx context.Context,
	namespace string,
	target EgressProbeTarget,
) (netip.Addr, error) {
	if l == nil || l.firewall == nil {
		return netip.Addr{}, fmt.Errorf("%w: uninitialized VPN lab", ErrVPNIsolationNotVerified)
	}

	if !labNamePattern.MatchString(namespace) {
		return netip.Addr{}, fmt.Errorf("%w: invalid lab namespace", ErrVPNIsolationNotVerified)
	}

	// The URL and the destination IP that nftables permits must name the same HTTPS endpoint.
	parsed, err := ParseEgressProbeURL(target.URL)
	if err != nil {
		return netip.Addr{}, fmt.Errorf("%w: invalid probe target: %w", ErrVPNIsolationNotVerified, err)
	}

	if parsed.IP != target.IP {
		return netip.Addr{}, fmt.Errorf("%w: probe URL and permitted IP differ", ErrVPNIsolationNotVerified)
	}

	// Gate 1: before any traffic.
	if err := l.verifyProbeIsolation(ctx, namespace); err != nil {
		return netip.Addr{}, err
	}

	observed, probeErr := l.Probe(ctx, namespace, target)

	// Gate 2: after the request, even if it failed, so drift during the probe is always seen.
	if err := l.verifyProbeIsolation(ctx, namespace); err != nil {
		return netip.Addr{}, err
	}

	if probeErr != nil {
		return netip.Addr{}, probeErr
	}

	return observed, nil
}
