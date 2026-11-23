package agent

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
)

const (
	labWGInterface = "wg0"
	labWGAddressA  = "10.254.0.1/30"
	labWGAddressB  = "10.254.0.2/30"
	labWGPortA     = 51820
	labWGPortB     = 51821
)

type wgLabCommand func(ctx context.Context, namespace, stdin string, args ...string) (string, error)

type wgLabKeys struct {
	private string
	public  string
}

type WireGuardLab struct {
	manager  *NetNSLabManager
	firewall *LabFirewall
	runWG    wgLabCommand
}

func NewWireGuardLab(m *NetNSLabManager, f *LabFirewall) (*WireGuardLab, error) {
	if runtime.GOOS != "linux" {
		return nil, ErrLinuxRequired
	}

	if m == nil || f == nil || f.manager != m {
		return nil, errors.New("WireGuard lab needs matching managers")
	}

	wgPath, err := findSystemWG()
	if err != nil {
		return nil, err
	}

	ipPath, err := findSystemIP()
	if err != nil {
		return nil, err
	}

	run := func(ctx context.Context, namespace, stdin string, args ...string) (string, error) {
		command, argv := wgPath, args
		if namespace != "" {
			command = ipPath
			argv = append([]string{"netns", "exec", namespace, wgPath}, args...)
		}

		commandCtx, cancel := context.WithTimeout(ctx, netNSCommandTimeout)
		defer cancel()

		cmd := exec.CommandContext(commandCtx, command, argv...)
		isolateFromTerminalSignals(cmd)

		if stdin != "" {
			cmd.Stdin = strings.NewReader(stdin + "\n")
		}

		output, err := cmd.Output()
		if err != nil {
			return "", fmt.Errorf("wireguard %s failed: %w", args[0], err)
		}

		return strings.TrimSpace(string(output)), nil
	}

	return newWireGuardLab(m, f, run), nil
}

func findSystemWG() (string, error) {
	candidates := []string{
		"/usr/bin/wg",
		"/usr/sbin/wg",
		"/bin/wg",
		"/sbin/wg",
	}

	for _, path := range candidates {
		info, err := os.Stat(path)
		if err == nil && info.Mode().IsRegular() && info.Mode().Perm()&0o111 != 0 {
			return path, nil
		}
	}

	return "", errors.New("system wg executable not found")
}

func newWireGuardLab(m *NetNSLabManager, f *LabFirewall, run wgLabCommand) *WireGuardLab {
	return &WireGuardLab{
		manager:  m,
		firewall: f,
		runWG:    run,
	}
}

func validWGKey(key string) bool {
	raw, err := base64.StdEncoding.DecodeString(key)
	return err == nil && len(raw) == 32
}

func (l *WireGuardLab) newKeys(ctx context.Context) (wgLabKeys, error) {
	private, err := l.runWG(ctx, "", "", "genkey")
	if err != nil {
		return wgLabKeys{}, err
	}

	if !validWGKey(private) {
		return wgLabKeys{}, errors.New("invalid WireGuard private key output")
	}

	public, err := l.runWG(ctx, "", private, "pubkey")
	if err != nil {
		return wgLabKeys{}, err
	}

	if !validWGKey(public) {
		return wgLabKeys{}, errors.New("invalid WireGuard public key output")
	}

	return wgLabKeys{private: private, public: public}, nil
}

func (l *WireGuardLab) Setup(ctx context.Context, a, b string) error {
	if a == b || !labNamePattern.MatchString(a) || !labNamePattern.MatchString(b) {
		return errors.New("two different lab namespaces are required")
	}

	if l == nil || l.manager == nil || l.firewall == nil || l.firewall.manager != l.manager || l.runWG == nil {
		return errors.New("WireGuard lab is not initialized")
	}

	l.manager.mu.Lock()
	_, ownsA := l.manager.owned[a]
	_, ownsB := l.manager.owned[b]
	l.manager.mu.Unlock()

	if !ownsA || !ownsB {
		return errors.New("both namespaces must be owned by this lab session")
	}

	ka, err := l.newKeys(ctx)
	if err != nil {
		return fmt.Errorf("generate A keys: %w", err)
	}

	kb, err := l.newKeys(ctx)
	if err != nil {
		return fmt.Errorf("generate B keys: %w", err)
	}

	if err := l.firewall.Seal(ctx, a); err != nil {
		return fmt.Errorf("seal A: %w", err)
	}

	if err := l.firewall.Seal(ctx, b); err != nil {
		return fmt.Errorf("seal B: %w", err)
	}

	if err := l.firewall.PermitWireGuardLab(ctx, a, LabSideA); err != nil {
		return fmt.Errorf("permit WireGuard A: %w", err)
	}

	if err := l.firewall.PermitWireGuardLab(ctx, b, LabSideB); err != nil {
		return fmt.Errorf("permit WireGuard B: %w", err)
	}

	l.manager.mu.Lock()
	defer l.manager.mu.Unlock()

	if _, ok := l.manager.owned[a]; !ok {
		return errors.New("namespace A no longer owned")
	}

	if _, ok := l.manager.owned[b]; !ok {
		return errors.New("namespace B no longer owned")
	}

	if err := l.runIPSteps(ctx, []ipStep{
		{"create wg A", []string{"-n", a, "link", "add", labWGInterface, "type", "wireguard"}},
		{"create wg B", []string{"-n", b, "link", "add", labWGInterface, "type", "wireguard"}},
	}); err != nil {
		return err
	}

	peers := []struct {
		title     string
		namespace string
		keys      wgLabKeys
		port      int
		peer      wgLabKeys
		peerWG    string
		peerHost  string
		peerPort  int
	}{
		{"A", a, ka, labWGPortA, kb, labWGAddressB, labAddressB, labWGPortB},
		{"B", b, kb, labWGPortB, ka, labWGAddressA, labAddressA, labWGPortA},
	}

	for _, p := range peers {
		if _, err := l.runWG(ctx, p.namespace, p.keys.private,
			"set", labWGInterface,
			"listen-port", strconv.Itoa(p.port),
			"private-key", "/dev/stdin",
		); err != nil {
			return fmt.Errorf("set %s private key: %w", p.title, err)
		}
	}

	for _, p := range peers {
		if _, err := l.runWG(ctx, p.namespace, "",
			"set", labWGInterface,
			"peer", p.peer.public,
			"allowed-ips", labHost(p.peerWG)+"/32",
			"endpoint", net.JoinHostPort(labHost(p.peerHost), strconv.Itoa(p.peerPort)),
		); err != nil {
			return fmt.Errorf("set %s peer: %w", p.title, err)
		}
	}

	return l.runIPSteps(ctx, []ipStep{
		{"address wg A", []string{"-n", a, "addr", "add", labWGAddressA, "dev", labWGInterface}},
		{"address wg B", []string{"-n", b, "addr", "add", labWGAddressB, "dev", labWGInterface}},
		{"up wg A", []string{"-n", a, "link", "set", labWGInterface, "up"}},
		{"up wg B", []string{"-n", b, "link", "set", labWGInterface, "up"}},
	})
}

type ipStep struct {
	title string
	args  []string
}

func (l *WireGuardLab) runIPSteps(ctx context.Context, steps []ipStep) error {
	for _, step := range steps {
		commandCtx, cancel := context.WithTimeout(ctx, netNSCommandTimeout)
		_, err := l.manager.run(commandCtx, step.args...)
		cancel()

		if err != nil {
			return fmt.Errorf("%s: %w", step.title, err)
		}
	}

	return nil
}
