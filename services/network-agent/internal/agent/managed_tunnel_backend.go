package agent

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"
)

var (
	ErrManagedTunnelBusy      = errors.New("a managed tunnel already exists")
	ErrManagedTunnelUncertain = errors.New("managed tunnel state uncertain; recovery required")
	ErrNoManagedTunnel        = errors.New("no managed tunnel for this namespace")
)

const (
	managedTunnelAliasPrefix    = "egresslab-managed:"
	managedTunnelCleanupTimeout = 40 * time.Second
)

// ManagedTunnelBackend brings a WireGuard config from the managed vault up in a sealed lab. It
// shares the sealed lab's namespace manager and firewall; all of its state is guarded by
// manager.mu. It holds at most one tunnel, and it configures the tunnel only: the lab firewall
// stays loopback-only, so no traffic is permitted through it and no handshake or egress is
// checked.
type ManagedTunnelBackend struct {
	sealed *SealedLabBackend
	vault  *WireGuardConfigVault
	vpn    *VPNEgressLab

	lookupEndpoint endpointLookup

	active *managedTunnel
}

func NewManagedTunnelBackend(sealed *SealedLabBackend, vault *WireGuardConfigVault) (*ManagedTunnelBackend, error) {
	if sealed == nil || sealed.manager == nil || sealed.firewall == nil || sealed.firewall.manager != sealed.manager ||
		vault == nil {
		return nil, errors.New("invalid managed tunnel dependencies")
	}

	runWG, err := newSystemWGRunner()
	if err != nil {
		return nil, err
	}

	rootNFT, err := newSystemUnderlayNFT()
	if err != nil {
		return nil, err
	}

	vpn := newVPNEgressLab(sealed.manager, sealed.firewall, runWG, nil, randomTunnelLinkName, rootNFT)

	return &ManagedTunnelBackend{sealed: sealed, vault: vault, vpn: vpn, lookupEndpoint: newEndpointLookup()}, nil
}

// ConnectStage configures the profile's current vault stage in namespace. It does not check any
// capability: the caller must already have authorized the profile, namespace and stage together.
func (b *ManagedTunnelBackend) ConnectStage(ctx context.Context, profileID, namespace, stageID string) error {
	if !labNamePattern.MatchString(namespace) {
		return errors.New("invalid lab namespace")
	}

	return b.vault.useVPNStage(profileID, stageID, func(cfg *ImportedWireGuardConfig) error {
		if err := b.sealed.Preflight(ctx); err != nil {
			return err
		}

		return b.connectConfig(ctx, namespace, cfg)
	})
}

func (b *ManagedTunnelBackend) connectConfig(ctx context.Context, namespace string, cfg *ImportedWireGuardConfig) error {
	plan, err := planManagedVPNTunnel(cfg)
	if err != nil {
		return err
	}

	// Before anything is created: the expected addresses and MTU, from the vault config alone.
	network, err := newManagedNetworkPolicy(cfg, plan)
	if err != nil {
		return err
	}

	b.sealed.manager.mu.Lock()
	defer b.sealed.manager.mu.Unlock()

	if b.active != nil {
		if b.active.faulted {
			return ErrManagedTunnelUncertain
		}

		return ErrManagedTunnelBusy
	}

	if err := b.sealed.requireOnlyLoopbackLocked(ctx, namespace); err != nil {
		return err
	}

	if err := b.sealed.firewall.requireSealedPolicyLocked(ctx, namespace); err != nil {
		return err
	}

	// Recovery does not inventory root WireGuard links yet, so refuse while any could be ours.
	outside, err := b.listLinksLocked(ctx, "")
	if err != nil {
		return err
	}

	for _, link := range outside {
		if tunnelLinkPattern.MatchString(link.Name) || strings.HasPrefix(link.Alias, managedTunnelAliasPrefix) {
			return fmt.Errorf("%w: tunnel link %s in the VM namespace", ErrRecoveryRequired, link.Name)
		}
	}

	// Resolved once, after the ownership, firewall and slot checks and before any kernel change.
	// The pinned address serves the underlay, the peer and the expected peer state; VerifyLab never
	// resolves again.
	if plan.endpoint, err = resolveManagedEndpoint(ctx, cfg.endpointHost, cfg.endpointPort, b.lookupEndpoint); err != nil {
		return err
	}

	link, err := b.vpn.linkName()
	if err != nil {
		return err
	}

	mark, err := tunnelMark(link)
	if err != nil {
		return err
	}

	table, err := underlayTableName(namespace)
	if err != nil {
		return err
	}

	// Before anything is created: the expected peer state, from the vault config alone.
	peer, err := b.newPeerPolicyLocked(ctx, cfg, plan)
	if err != nil {
		return err
	}

	tunnel := &managedTunnel{
		namespace: namespace,
		rootName:  link,
		alias:     managedTunnelAliasPrefix + namespace + ":" + link,
		peer:      peer,
		network:   network,
	}

	// Tracked before the first kernel change, so a failure can never forget what was created.
	b.active = tunnel

	err = b.connectKernelLocked(ctx, tunnel, cfg, plan, mark, table)
	if err == nil {
		return nil
	}

	tunnel.faulted = true

	cleanupCtx, cancel := context.WithTimeout(context.Background(), managedTunnelCleanupTimeout)
	defer cancel()

	if cleanupErr := b.disconnectLocked(cleanupCtx, tunnel); cleanupErr != nil {
		return errors.Join(ErrManagedTunnelUncertain, err, cleanupErr)
	}

	return fmt.Errorf("managed tunnel failed and was rolled back: %w", err)
}

// The caller must hold manager.mu.
func (b *ManagedTunnelBackend) connectKernelLocked(
	ctx context.Context,
	t *managedTunnel,
	cfg *ImportedWireGuardConfig,
	plan vpnTunnelPlan,
	mark uint32,
	table string,
) error {
	l := b.vpn
	ns := t.namespace

	if err := l.installUnderlayLocked(ctx, ns, underlayTunnel{table: table, mark: mark, endpoint: plan.endpoint}); err != nil {
		return fmt.Errorf("install underlay policy: %w", err)
	}

	for _, step := range [][]string{
		{"link", "add", t.rootName, "type", "wireguard"},
		{"link", "set", "dev", t.rootName, "alias", t.alias},
		{"link", "set", t.rootName, "netns", ns},
		{"-n", ns, "link", "set", t.rootName, "name", labWGInterface},
	} {
		if err := l.ip(ctx, step...); err != nil {
			return fmt.Errorf("create tunnel link: %w", err)
		}
	}

	if err := b.requireInPlaceLocked(ctx, t); err != nil {
		return err
	}

	if err := b.applyDefaultMTULocked(ctx, t, cfg); err != nil {
		return fmt.Errorf("configure default MTU: %w", err)
	}

	// The peer, and with it the first handshake, comes only after the lab firewall, the root
	// underlay policy (table and fwmark), the interface key and an empty peer list are read back.
	beforePeer := func(ctx context.Context) error {
		if err := b.sealed.firewall.requireSealedPolicyLocked(ctx, ns); err != nil {
			return err
		}

		if err := l.verifyUnderlayLocked(ctx, ns); err != nil {
			return err
		}

		return b.verifyBeforePeerLocked(ctx, t)
	}

	if err := l.configureVPNLinkLocked(ctx, ns, cfg, plan, mark, beforePeer); err != nil {
		return err
	}

	return b.verifyConfiguredLocked(ctx, t)
}

// requireInPlaceLocked requires the tagged link to be wg0 inside the lab namespace.
// The caller must hold manager.mu.
func (b *ManagedTunnelBackend) requireInPlaceLocked(ctx context.Context, t *managedTunnel) error {
	location, err := b.locateLocked(ctx, t)
	if err != nil {
		return err
	}

	if location == nil || location.namespace != t.namespace || location.name != labWGInterface {
		return fmt.Errorf("%w: tunnel link is not wg0 in %s", ErrManagedTunnelUncertain, t.namespace)
	}

	return nil
}

// The caller must hold manager.mu.
func (b *ManagedTunnelBackend) verifyConfiguredLocked(ctx context.Context, t *managedTunnel) error {
	if err := b.requireInPlaceLocked(ctx, t); err != nil {
		return err
	}

	if err := b.sealed.firewall.requireSealedPolicyLocked(ctx, t.namespace); err != nil {
		return err
	}

	if err := b.vpn.verifyUnderlayLocked(ctx, t.namespace); err != nil {
		return err
	}

	if err := b.verifyPeerLocked(ctx, t); err != nil {
		return err
	}

	return b.verifyNetworkLocked(ctx, t)
}

// VerifyConfigured re-checks the link, the lab firewall, the underlay policy, the WireGuard peer
// state and the IPv4 addresses, MTU, rules, routes and route lookup against what was staged. It
// proves neither a handshake nor the egress address. A failure faults the tunnel until Disconnect.
func (b *ManagedTunnelBackend) VerifyConfigured(ctx context.Context, namespace string) error {
	b.sealed.manager.mu.Lock()
	defer b.sealed.manager.mu.Unlock()

	t := b.active
	if t == nil || t.namespace != namespace {
		return ErrNoManagedTunnel
	}

	if t.faulted || t.linkRemoved {
		return ErrManagedTunnelUncertain
	}

	if err := b.verifyConfiguredLocked(ctx, t); err != nil {
		t.faulted = true
		return err
	}

	return nil
}

// Disconnect removes the tunnel link, confirms it is gone, then removes its underlay table. On
// failure the tunnel stays tracked and faulted, and Disconnect can be retried.
func (b *ManagedTunnelBackend) Disconnect(ctx context.Context, namespace string) error {
	b.sealed.manager.mu.Lock()
	defer b.sealed.manager.mu.Unlock()

	t := b.active
	if t == nil || t.namespace != namespace {
		return ErrNoManagedTunnel
	}

	t.faulted = true

	return b.disconnectLocked(ctx, t)
}

// disconnectLocked releases the underlay table only after this call (or an earlier one) deleted
// the link and a fresh inventory no longer finds it. A link that vanished on its own is not proof
// of a clean removal, so the table is kept for the operator. The caller must hold manager.mu.
func (b *ManagedTunnelBackend) disconnectLocked(ctx context.Context, t *managedTunnel) error {
	l := b.vpn

	if _, owned := b.sealed.manager.owned[t.namespace]; !owned {
		return fmt.Errorf("%w: namespace no longer owned", ErrManagedTunnelUncertain)
	}

	// Missing after a failed install: the nft command may still have created the table.
	underlay, exists := l.underlay[t.namespace]
	if !exists {
		return fmt.Errorf("%w: underlay policy not confirmed", ErrManagedTunnelUncertain)
	}

	location, err := b.locateLocked(ctx, t)
	if err != nil {
		return err
	}

	if !t.linkRemoved {
		if location == nil {
			return fmt.Errorf("%w: tunnel link not found", ErrManagedTunnelUncertain)
		}

		args := []string{"link", "del", "dev", location.name}
		if location.namespace != "" {
			args = append([]string{"-n", location.namespace}, args...)
		}

		if err := l.ip(ctx, args...); err != nil {
			return fmt.Errorf("remove tunnel link: %w", err)
		}

		if location, err = b.locateLocked(ctx, t); err != nil {
			return err
		}

		if location != nil {
			return fmt.Errorf("%w: tunnel link still present", ErrManagedTunnelUncertain)
		}

		t.linkRemoved = true
	}

	if location != nil {
		return fmt.Errorf("%w: removed tunnel link reappeared", ErrManagedTunnelUncertain)
	}

	commandCtx, cancel := context.WithTimeout(ctx, netNSCommandTimeout)
	defer cancel()

	if err := l.rootNFT.run(commandCtx, fmt.Sprintf("delete table inet %s\n", underlay.table), false); err != nil {
		return fmt.Errorf("remove underlay policy %s: %w", underlay.table, err)
	}

	delete(l.underlay, t.namespace)
	b.active = nil

	return nil
}

// CleanupStage removes whatever tunnel this backend tracks for namespace, after a failed connect,
// before the namespace is deleted, or at shutdown. With nothing tracked it returns nil; it does
// not prove the namespace clean, which stays the sealed lab backend's job. A failure keeps the
// tunnel tracked.
func (b *ManagedTunnelBackend) CleanupStage(ctx context.Context, namespace string) error {
	b.sealed.manager.mu.Lock()
	defer b.sealed.manager.mu.Unlock()

	if _, owned := b.sealed.manager.owned[namespace]; !owned {
		return fmt.Errorf("%w: namespace not owned", ErrManagedTunnelUncertain)
	}

	t := b.active
	if t == nil {
		return nil
	}

	if t.namespace != namespace {
		return fmt.Errorf("%w: the tracked tunnel is in another namespace", ErrManagedTunnelUncertain)
	}

	t.faulted = true

	return b.disconnectLocked(ctx, t)
}
