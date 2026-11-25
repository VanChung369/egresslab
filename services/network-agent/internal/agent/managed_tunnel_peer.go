package agent

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"strconv"
	"strings"
)

var ErrManagedPeerDrift = errors.New("managed WireGuard peer configuration drifted")

// managedPeerPolicy is the peer configuration the kernel must report, written down before the
// tunnel exists and never learned from it. It holds public values only: no private or preshared
// key.
type managedPeerPolicy struct {
	interfacePublicKey string
	peerPublicKey      string
	endpoint           netip.AddrPort
	keepalive          uint16
}

// newPeerPolicyLocked derives the interface public key from the vault's private key (on stdin)
// before anything is created. The caller must hold manager.mu.
func (b *ManagedTunnelBackend) newPeerPolicyLocked(
	ctx context.Context,
	cfg *ImportedWireGuardConfig,
	plan vpnTunnelPlan,
) (managedPeerPolicy, error) {
	if cfg == nil ||
		!validSecretKey(cfg.privateKey) ||
		!validImportKey(cfg.peerPublicKey) ||
		!plan.endpoint.Addr().Is4() ||
		plan.endpoint.Port() == 0 {
		return managedPeerPolicy{}, ErrUnsupportedTunnelConfig
	}

	public, err := b.vpn.runWG(ctx, "", cfg.privateKey, "pubkey")
	if err != nil {
		return managedPeerPolicy{}, errors.New("could not derive the WireGuard public key")
	}

	public = strings.TrimSpace(public)

	if !validImportKey(public) || public == cfg.peerPublicKey {
		return managedPeerPolicy{}, errors.New("invalid WireGuard interface public key")
	}

	return managedPeerPolicy{
		interfacePublicKey: public,
		peerPublicKey:      cfg.peerPublicKey,
		endpoint:           plan.endpoint,
		keepalive:          cfg.keepalive,
	}, nil
}

// keepaliveValue is how wg(8) prints the setting: "off" when it is not enabled.
func (p managedPeerPolicy) keepaliveValue() string {
	if p.keepalive == 0 {
		return "off"
	}

	return strconv.Itoa(int(p.keepalive))
}

// requireWGValueLocked reads one public property with "wg show wg0 <property>" (never showconf or
// dump, which print private and preshared keys) and requires an exact match. The value read is
// never put in an error. The caller must hold manager.mu.
func (b *ManagedTunnelBackend) requireWGValueLocked(ctx context.Context, namespace, property, expected string) error {
	actual, err := b.vpn.runWG(ctx, namespace, nil, "show", labWGInterface, property)
	if err != nil {
		return fmt.Errorf("%w: cannot read %s", ErrManagedPeerDrift, property)
	}

	if strings.TrimSpace(actual) != expected {
		return fmt.Errorf("%w: unexpected %s", ErrManagedPeerDrift, property)
	}

	return nil
}

// verifyBeforePeerLocked requires the interface to carry the expected identity and no peer yet.
// The caller must hold manager.mu.
func (b *ManagedTunnelBackend) verifyBeforePeerLocked(ctx context.Context, t *managedTunnel) error {
	if err := b.requireWGValueLocked(ctx, t.namespace, "public-key", t.peer.interfacePublicKey); err != nil {
		return err
	}

	return b.requireWGValueLocked(ctx, t.namespace, "peers", "")
}

// verifyPeerLocked compares a fresh kernel readback with the policy: exactly one peer, the pinned
// IPv4 endpoint and port (no roaming), AllowedIPs exactly 0.0.0.0/0, and the staged keepalive.
// The caller must hold manager.mu.
func (b *ManagedTunnelBackend) verifyPeerLocked(ctx context.Context, t *managedTunnel) error {
	p := t.peer

	if !validImportKey(p.interfacePublicKey) || !validImportKey(p.peerPublicKey) || !p.endpoint.IsValid() {
		return ErrManagedPeerDrift
	}

	for _, check := range [][2]string{
		{"public-key", p.interfacePublicKey},
		{"peers", p.peerPublicKey},
		{"endpoints", p.peerPublicKey + "\t" + p.endpoint.String()},
		{"allowed-ips", p.peerPublicKey + "\t0.0.0.0/0"},
		{"persistent-keepalive", p.peerPublicKey + "\t" + p.keepaliveValue()},
	} {
		if err := b.requireWGValueLocked(ctx, t.namespace, check[0], check[1]); err != nil {
			return err
		}
	}

	return nil
}
