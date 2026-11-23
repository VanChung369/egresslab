package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
)

var ErrFirewallReconcileRequiresOffline = errors.New("firewall reconcile requires an offline tunnel")

// requireOfflineForReconcileLocked refuses reconciliation unless the kernel's own link listing
// proves that no WireGuard interface exists in the namespace. Rebuilding the ruleset around a
// live tunnel could open a window without enforcement. If the links cannot be read or parsed,
// it refuses instead of assuming the tunnel is down.
//
// It protects Reconcile from a live WireGuard tunnel only; it is not proof that all traffic in
// the namespace has stopped. The caller must hold f.manager.mu.
func (f *LabFirewall) requireOfflineForReconcileLocked(ctx context.Context, namespace string) error {
	if f.manager == nil || f.manager.run == nil {
		return fmt.Errorf("%w: link inspection unavailable", ErrFirewallReconcileRequiresOffline)
	}

	commandCtx, cancel := context.WithTimeout(ctx, netNSCommandTimeout)
	defer cancel()

	output, err := f.manager.run(commandCtx, "-n", namespace, "-details", "-json", "link", "show")
	if err != nil {
		return fmt.Errorf("%w: inspect links: %w", ErrFirewallReconcileRequiresOffline, err)
	}

	var links []struct {
		Name     string `json:"ifname"`
		LinkInfo struct {
			Kind string `json:"info_kind"`
		} `json:"linkinfo"`
	}

	if err := json.Unmarshal(output, &links); err != nil || len(links) == 0 {
		return fmt.Errorf("%w: invalid or empty link listing", ErrFirewallReconcileRequiresOffline)
	}

	hasLoopback := false

	for _, link := range links {
		if link.Name == "" {
			return fmt.Errorf("%w: link name missing", ErrFirewallReconcileRequiresOffline)
		}

		if link.Name == "lo" {
			hasLoopback = true
		}

		if link.Name == labWGInterface || link.LinkInfo.Kind == "wireguard" {
			return fmt.Errorf("%w: WireGuard link %q still exists", ErrFirewallReconcileRequiresOffline, link.Name)
		}
	}

	if !hasLoopback {
		return fmt.Errorf("%w: loopback link not found", ErrFirewallReconcileRequiresOffline)
	}

	return nil
}
