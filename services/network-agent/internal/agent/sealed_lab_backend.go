package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
)

var ErrLabNotLoopbackOnly = errors.New("sealed lab must contain only a loopback interface")

// SealedLabBackend is the helper's narrow kernel API: it cannot attach a tunnel or open traffic.
type SealedLabBackend struct {
	manager     *NetNSLabManager
	firewall    *LabFirewall
	recovery    *LabRecovery
	kernelCheck func() error
	sysctlPath  string
}

func NewSealedLabBackend() (*SealedLabBackend, error) {
	manager, err := NewNetNSLabManager()
	if err != nil {
		return nil, err
	}

	firewall, err := NewLabFirewall(manager)
	if err != nil {
		return nil, err
	}

	// Built on the backend's own manager, so the gate can tell this helper's labs from others.
	recovery, err := NewLabRecovery(manager)
	if err != nil {
		return nil, err
	}

	sysctlPath, err := findSystemBinary("sysctl")
	if err != nil {
		return nil, err
	}

	return &SealedLabBackend{
		manager:     manager,
		firewall:    firewall,
		recovery:    recovery,
		kernelCheck: CheckSealedLabKernel,
		sysctlPath:  sysctlPath,
	}, nil
}

func (b *SealedLabBackend) Create(ctx context.Context) (string, error) {
	return b.manager.Create(ctx)
}

func (b *SealedLabBackend) Seal(ctx context.Context, name string) error {
	if err := b.requireOnlyLoopback(ctx, name); err != nil {
		return err
	}

	if err := b.firewall.Seal(ctx, name); err != nil {
		return err
	}

	b.manager.mu.Lock()
	defer b.manager.mu.Unlock()

	if err := b.requireOnlyLoopbackLocked(ctx, name); err != nil {
		return err
	}

	// IPv6 is disabled only once the firewall is sealed and matches the intended policy.
	if err := b.firewall.requireSealedPolicyLocked(ctx, name); err != nil {
		return err
	}

	return b.disableIPv6Locked(ctx, name, false)
}

// Verify only reads: the topology, the intended sealed firewall and the IPv6 switches.
func (b *SealedLabBackend) Verify(ctx context.Context, name string) error {
	b.manager.mu.Lock()
	defer b.manager.mu.Unlock()

	if err := b.requireOnlyLoopbackLocked(ctx, name); err != nil {
		return err
	}

	if err := b.firewall.requireSealedPolicyLocked(ctx, name); err != nil {
		return err
	}

	return b.verifyIPv6Locked(ctx, name, false)
}

func (b *SealedLabBackend) requireOnlyLoopback(ctx context.Context, name string) error {
	b.manager.mu.Lock()
	defer b.manager.mu.Unlock()

	return b.requireOnlyLoopbackLocked(ctx, name)
}

// The caller must hold manager.mu.
func (b *SealedLabBackend) requireOnlyLoopbackLocked(ctx context.Context, name string) error {
	if !labNamePattern.MatchString(name) {
		return errors.New("invalid lab namespace")
	}

	if _, owned := b.manager.owned[name]; !owned {
		return errors.New("namespace is not owned")
	}

	commandCtx, cancel := context.WithTimeout(ctx, netNSCommandTimeout)
	defer cancel()

	output, err := b.manager.run(commandCtx, "-n", name, "-details", "-json", "link", "show")
	if err != nil {
		return fmt.Errorf("%w: inspect kernel links: %w", ErrLabNotLoopbackOnly, err)
	}

	return validateLoopbackOnly(output)
}

func validateLoopbackOnly(data []byte) error {
	var links []struct {
		Name  string `json:"ifname"`
		Index int    `json:"ifindex"`
		Type  string `json:"link_type"`
	}

	if err := json.Unmarshal(data, &links); err != nil {
		return fmt.Errorf("%w: invalid link listing", ErrLabNotLoopbackOnly)
	}

	if len(links) != 1 || links[0].Name != "lo" || links[0].Index <= 0 || links[0].Type != "loopback" {
		return ErrLabNotLoopbackOnly
	}

	return nil
}

// Delete refuses a namespace holding any device besides lo, leaving it for recovery.
func (b *SealedLabBackend) Delete(ctx context.Context, name string) error {
	b.manager.mu.Lock()
	defer b.manager.mu.Unlock()

	if err := b.requireOnlyLoopbackLocked(ctx, name); err != nil {
		// "ip -n" also fails when the namespace was removed outside the helper; forget it then.
		if _, owned := b.manager.owned[name]; !owned {
			return err
		}

		if err := b.manager.forgetIfGone(name, err); err != nil {
			return err
		}

		b.forgetFirewallLocked(name)

		return nil
	}

	commandCtx, cancel := context.WithTimeout(ctx, netNSCommandTimeout)
	defer cancel()

	if err := b.manager.deleteLocked(commandCtx, name); err != nil {
		return err
	}

	b.forgetFirewallLocked(name)

	return nil
}

// The caller must hold manager.mu.
func (b *SealedLabBackend) forgetFirewallLocked(name string) {
	delete(b.firewall.sealed, name)
	delete(b.firewall.applied, name)
	delete(b.firewall.baseline, name)
	delete(b.firewall.drifted, name)
}
