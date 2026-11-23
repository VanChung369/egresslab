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
	manager *NetNSLabManager
	run     nftLabRunner
	sealed  map[string]bool
}

var sealLabRules = fmt.Sprintf(`create table inet %[1]s
add chain inet %[1]s input { type filter hook input priority 0; policy drop; }
add chain inet %[1]s output { type filter hook output priority 0; policy drop; }
add chain inet %[1]s forward { type filter hook forward priority 0; policy drop; }
add rule inet %[1]s input iifname "lo" accept
add rule inet %[1]s output oifname "lo" accept
`, labNFTTable)

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

	return newLabFirewall(manager, run), nil
}

func newLabFirewall(manager *NetNSLabManager, run nftLabRunner) *LabFirewall {
	return &LabFirewall{
		manager: manager,
		run:     run,
		sealed:  make(map[string]bool),
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

	return nil
}

func (f *LabFirewall) PermitPeerICMP(ctx context.Context, name string, side LabSide) error {
	if !labNamePattern.MatchString(name) {
		return errors.New("invalid lab namespace name")
	}

	f.manager.mu.Lock()
	defer f.manager.mu.Unlock()

	if _, ok := f.manager.owned[name]; !ok {
		return fmt.Errorf("namespace %s not owned by this session", name)
	}

	if !f.sealed[name] {
		return fmt.Errorf("namespace %s must be sealed first", name)
	}

	script, err := peerICMPRules(side)
	if err != nil {
		return err
	}

	return f.apply(ctx, name, script)
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
