package agent

import (
	"context"
	"errors"
	"fmt"
	"strings"
)

var ErrIPv6Isolation = errors.New("namespace IPv6 isolation not verified")

// Per-interface switches: conf/all says nothing about existing interfaces, so default (for links
// created or moved in later), lo and wg0 are each set and read on their own. disable_ipv6=1
// removes the interface's IPv6 addresses and routes and refuses new ones.
const (
	ipv6DefaultKey   = "net.ipv6.conf.default.disable_ipv6"
	ipv6LoopbackKey  = "net.ipv6.conf.lo.disable_ipv6"
	ipv6WireGuardKey = "net.ipv6.conf.wg0.disable_ipv6"
)

// runIPv6SysctlLocked runs sysctl inside an owned lab namespace ("ip netns exec"), never in the
// VM namespace. The caller must hold manager.mu.
func (b *SealedLabBackend) runIPv6SysctlLocked(ctx context.Context, namespace string, args ...string) ([]byte, error) {
	if !labNamePattern.MatchString(namespace) || b.sysctlPath == "" {
		return nil, ErrIPv6Isolation
	}

	if _, owned := b.manager.owned[namespace]; !owned {
		return nil, ErrIPv6Isolation
	}

	commandCtx, cancel := context.WithTimeout(ctx, netNSCommandTimeout)
	defer cancel()

	argv := append([]string{"netns", "exec", namespace, b.sysctlPath}, args...)

	output, err := b.manager.run(commandCtx, argv...)
	if err != nil {
		return nil, fmt.Errorf("%w: sysctl command failed: %w", ErrIPv6Isolation, err)
	}

	return output, nil
}

// disableIPv6Locked disables IPv6 for default and lo when sealing, or for wg0 alone once the tunnel
// link is inside the lab, then reads every expected switch back. The caller must hold manager.mu.
func (b *SealedLabBackend) disableIPv6Locked(ctx context.Context, namespace string, withTunnel bool) error {
	keys := []string{ipv6DefaultKey, ipv6LoopbackKey}
	if withTunnel {
		keys = []string{ipv6WireGuardKey}
	}

	args := []string{"-q", "-w"}
	for _, key := range keys {
		args = append(args, key+"=1")
	}

	if _, err := b.runIPv6SysctlLocked(ctx, namespace, args...); err != nil {
		return err
	}

	return b.verifyIPv6Locked(ctx, namespace, withTunnel)
}

// verifyIPv6Locked only reads: drift is reported, never repaired. The caller must hold manager.mu.
func (b *SealedLabBackend) verifyIPv6Locked(ctx context.Context, namespace string, withTunnel bool) error {
	keys := []string{ipv6DefaultKey, ipv6LoopbackKey}
	if withTunnel {
		keys = append(keys, ipv6WireGuardKey)
	}

	output, err := b.runIPv6SysctlLocked(ctx, namespace, append([]string{"-n"}, keys...)...)
	if err != nil {
		return err
	}

	values := strings.Fields(string(output))
	if len(values) != len(keys) {
		return fmt.Errorf("%w: unexpected sysctl output", ErrIPv6Isolation)
	}

	for i, value := range values {
		if value != "1" {
			return fmt.Errorf("%w: %s is not 1", ErrIPv6Isolation, keys[i])
		}
	}

	return nil
}
