package agent

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

var (
	ErrRecoveryRequired   = errors.New("leftover lab resources must be recovered first")
	ErrKernelIncompatible = errors.New("kernel creates fallback tunnel devices in new namespaces")
)

const (
	sysClassNet           = "/sys/class/net"
	fallbackTunnelsSysctl = "/proc/sys/net/core/fb_tunnels_only_for_init_net"
)

// Devices the kernel adds to every namespace when a tunnel module loads, unless
// net.core.fb_tunnels_only_for_init_net is 1 or 2 (Documentation/admin-guide/sysctl/net.rst).
var fallbackTunnelDevices = []string{"tunl0", "gre0", "gretap0", "erspan0", "sit0", "ip6tnl0", "ip6gre0", "ip_vti0", "ip6_vti0"}

// CheckSealedLabKernel reports, without changing anything, whether new namespaces will get
// devices besides lo. The helper runs in the initial namespace, so the fallback devices it sees
// are the ones every new namespace would get while the sysctl is 0.
func CheckSealedLabKernel() error {
	return checkFallbackTunnels(sysClassNet, fallbackTunnelsSysctl)
}

func checkFallbackTunnels(netDir, sysctlPath string) error {
	var present []string

	for _, name := range fallbackTunnelDevices {
		if _, err := os.Lstat(filepath.Join(netDir, name)); err == nil {
			present = append(present, name)
		}
	}

	if len(present) == 0 {
		return nil
	}

	// Kernels without the sysctl always create the devices in every namespace.
	value := "0"
	if data, err := os.ReadFile(sysctlPath); err == nil {
		value = strings.TrimSpace(string(data))
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("%w: read %s: %w", ErrKernelIncompatible, sysctlPath, err)
	}

	if value != "0" {
		return nil
	}

	return fmt.Errorf("%w: %s present and net.core.fb_tunnels_only_for_init_net=0; set it to 1 or unload "+
		"the tunnel modules (EgressLab changes neither)", ErrKernelIncompatible, strings.Join(present, ", "))
}

// Preflight blocks lab creation when the kernel would add devices to new namespaces, or when any
// lab resource exists that this backend does not own: leftovers of a crashed session, labs of
// other live processes, unmarked namespaces, stale markers and underlay tables. It never cleans.
// The caller must not hold manager.mu.
func (b *SealedLabBackend) Preflight(ctx context.Context) error {
	if err := b.kernelCheck(); err != nil {
		return err
	}

	if b.recovery == nil {
		return fmt.Errorf("%w: recovery scanner unavailable", ErrRecoveryRequired)
	}

	items, err := b.recovery.Scan(ctx)
	if err != nil {
		return fmt.Errorf("%w: scan: %w", ErrRecoveryRequired, err)
	}

	b.manager.mu.Lock()
	defer b.manager.mu.Unlock()

	var leftovers []string

	for _, item := range items {
		if _, owned := b.manager.owned[item.Name]; owned && item.Kind == "namespace" {
			continue
		}

		leftovers = append(leftovers, fmt.Sprintf("%s %s (%s)", item.Kind, item.Name, item.State))
	}

	if len(leftovers) > 0 {
		return fmt.Errorf("%w: %s", ErrRecoveryRequired, strings.Join(leftovers, "; "))
	}

	return nil
}
