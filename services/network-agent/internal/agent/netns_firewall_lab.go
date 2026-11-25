package agent

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"runtime"
	"strings"
)

const labNFTTable = "egresslab_lab"

type LabSide string

const (
	LabSideA LabSide = "a"
	LabSideB LabSide = "b"
)

type nftLabRunner func(ctx context.Context, namespace, script string, checkOnly bool) error

type LabFirewall struct {
	manager  *NetNSLabManager
	run      nftLabRunner
	list     nftRulesetLister // nil only in tests that do not model kernel readback
	sealed   map[string]bool
	applied  map[string][]string
	baseline map[string]string
	drifted  map[string]bool
}

var sealLabRules = fmt.Sprintf(`create table inet %[1]s
add chain inet %[1]s input { type filter hook input priority 0; policy drop; }
add chain inet %[1]s output { type filter hook output priority 0; policy drop; }
add chain inet %[1]s forward { type filter hook forward priority 0; policy drop; }
add rule inet %[1]s input meta nfproto ipv6 drop
add rule inet %[1]s input iifname "lo" accept
add rule inet %[1]s output meta nfproto ipv6 drop
add rule inet %[1]s output udp dport 53 drop
add rule inet %[1]s output tcp dport 53 drop
add rule inet %[1]s output tcp dport 853 drop
add rule inet %[1]s output udp dport 853 drop
add rule inet %[1]s output oifname "lo" accept
`, labNFTTable)

// The IPv6 and DNS transport drops precede the loopback accepts and every permit appended later, so
// nothing can open IPv6, plain DNS (53), DNS over TLS or DNS over QUIC (853) from a lab namespace,
// loopback included. They cover the standard ports only: HTTPS (and so DNS over HTTPS) stays closed
// by the drop policy and must be controlled wherever it is permitted.

func NewLabFirewall(manager *NetNSLabManager) (*LabFirewall, error) {
	if runtime.GOOS != "linux" {
		return nil, ErrLinuxRequired
	}

	if manager == nil {
		return nil, errors.New("nil namespace manager")
	}

	ipPath, err := findSystemBinary("ip")
	if err != nil {
		return nil, err
	}

	nftPath, err := findSystemBinary("nft")
	if err != nil {
		return nil, err
	}

	run := func(ctx context.Context, namespace, script string, checkOnly bool) error {
		args := []string{"netns", "exec", namespace, nftPath}
		if checkOnly {
			args = append(args, "--check")
		}
		args = append(args, "-f", "-")

		cmd := exec.CommandContext(ctx, ipPath, args...)
		isolateFromTerminalSignals(cmd)
		cmd.Stdin = strings.NewReader(script)

		output, err := cmd.CombinedOutput()
		if err != nil {
			return fmt.Errorf("nft in namespace %s: %w: %s", namespace, err, strings.TrimSpace(string(output)))
		}

		return nil
	}

	list := func(ctx context.Context, namespace string) ([]byte, error) {
		cmd := exec.CommandContext(ctx, ipPath, "netns", "exec", namespace, nftPath, "-j", "list", "ruleset")
		isolateFromTerminalSignals(cmd)

		var stderr strings.Builder
		cmd.Stderr = &stderr

		output, err := cmd.Output()
		if err != nil {
			return nil, fmt.Errorf("nft list in namespace %s: %w: %s", namespace, err, strings.TrimSpace(stderr.String()))
		}

		return output, nil
	}

	return newVerifyingLabFirewall(manager, run, list), nil
}

func newLabFirewall(manager *NetNSLabManager, run nftLabRunner) *LabFirewall {
	return newVerifyingLabFirewall(manager, run, nil)
}

func newVerifyingLabFirewall(manager *NetNSLabManager, run nftLabRunner, list nftRulesetLister) *LabFirewall {
	return &LabFirewall{
		manager:  manager,
		run:      run,
		list:     list,
		sealed:   make(map[string]bool),
		applied:  make(map[string][]string),
		baseline: make(map[string]string),
		drifted:  make(map[string]bool),
	}
}

func (f *LabFirewall) Seal(ctx context.Context, name string) error {
	return f.seal(ctx, name, false)
}

func (f *LabFirewall) sealIfNeeded(ctx context.Context, name string) error {
	return f.seal(ctx, name, true)
}

func (f *LabFirewall) seal(ctx context.Context, name string, allowSealed bool) error {
	if !labNamePattern.MatchString(name) {
		return errors.New("invalid lab namespace name")
	}

	f.manager.mu.Lock()
	defer f.manager.mu.Unlock()

	if _, ok := f.manager.owned[name]; !ok {
		return fmt.Errorf("namespace %s not owned by this session", name)
	}

	if f.sealed[name] {
		if allowSealed {
			return nil
		}

		return fmt.Errorf("namespace %s already sealed", name)
	}

	if err := f.apply(ctx, name, sealLabRules); err != nil {
		return err
	}

	f.sealed[name] = true

	return f.recordLocked(ctx, name, sealLabRules)
}

// applyVerifiedLocked adds rules only after the kernel ruleset is confirmed unchanged, then
// captures the new state as the baseline.
func (f *LabFirewall) applyVerifiedLocked(ctx context.Context, name, script string) error {
	if err := f.requireVerifiedLocked(ctx, name); err != nil {
		return err
	}

	if err := f.apply(ctx, name, script); err != nil {
		return err
	}

	return f.recordLocked(ctx, name, script)
}

func (f *LabFirewall) PermitPeerICMP(ctx context.Context, name string, side LabSide) error {
	if !labNamePattern.MatchString(name) {
		return errors.New("invalid lab namespace name")
	}

	script, err := peerICMPRules(side)
	if err != nil {
		return err
	}

	f.manager.mu.Lock()
	defer f.manager.mu.Unlock()

	return f.applyVerifiedLocked(ctx, name, script)
}

func peerICMPRules(side LabSide) (string, error) {
	var iface, local, peer string

	switch side {
	case LabSideA:
		iface, local, peer = labVethA, labHost(labAddressA), labHost(labAddressB)

	case LabSideB:
		iface, local, peer = labVethB, labHost(labAddressB), labHost(labAddressA)

	default:
		return "", errors.New("invalid lab side")
	}

	icmp := "icmp type { echo-request, echo-reply } accept"

	return fmt.Sprintf(`add rule inet %[1]s input iifname "%[2]s" ip saddr %[4]s ip daddr %[3]s %[5]s
add rule inet %[1]s output oifname "%[2]s" ip saddr %[3]s ip daddr %[4]s %[5]s
`, labNFTTable, iface, local, peer, icmp), nil
}

func labHost(prefix string) string {
	host, _, _ := strings.Cut(prefix, "/")
	return host
}

func (f *LabFirewall) apply(ctx context.Context, namespace, script string) error {
	for _, checkOnly := range []bool{true, false} {
		commandCtx, cancel := context.WithTimeout(ctx, netNSCommandTimeout)
		err := f.run(commandCtx, namespace, script, checkOnly)
		cancel()

		if err != nil {
			return fmt.Errorf("apply lab firewall (check=%t) in %s: %w", checkOnly, namespace, err)
		}
	}

	return nil
}
