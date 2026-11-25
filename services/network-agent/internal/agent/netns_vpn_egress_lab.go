package agent

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os/exec"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"time"
)

const (
	DefaultEgressProbeURL = "https://1.1.1.1/cdn-cgi/trace"
	maxEgressProbeBytes   = 4096
	egressProbeTimeout    = 10 * time.Second
)

var (
	ErrUnsupportedTunnelConfig = errors.New("WireGuard config is not supported by the VPN egress lab")

	tunnelLinkPattern = regexp.MustCompile(`^egwg[0-9a-f]{8}$`)
)

type vpnTunnelPlan struct {
	endpoint    netip.AddrPort
	addresses   []netip.Prefix
	skippedIPv6 int
}

type EgressProbeTarget struct {
	URL string
	IP  netip.Addr
}

type egressProbeRunner func(ctx context.Context, namespace, url string) ([]byte, error)

type VPNEgressLab struct {
	manager  *NetNSLabManager
	firewall *LabFirewall
	runWG    wgLabCommand
	probe    egressProbeRunner
	linkName func() (string, error)
	rootNFT  underlayNFT
	underlay map[string]underlayTunnel // guarded by manager.mu
}

func NewVPNEgressLab(m *NetNSLabManager, f *LabFirewall, probeBinary string) (*VPNEgressLab, error) {
	if runtime.GOOS != "linux" {
		return nil, ErrLinuxRequired
	}

	if m == nil || f == nil || f.manager != m {
		return nil, errors.New("VPN egress lab needs matching managers")
	}

	runWG, err := newSystemWGRunner()
	if err != nil {
		return nil, err
	}

	ipPath, err := findSystemBinary("ip")
	if err != nil {
		return nil, err
	}

	probe := func(ctx context.Context, namespace, url string) ([]byte, error) {
		command, argv := probeBinary, []string{"internal-probe", url}
		if namespace != "" {
			command = ipPath
			argv = append([]string{"netns", "exec", namespace, probeBinary}, argv...)
		}

		probeCtx, cancel := context.WithTimeout(ctx, egressProbeTimeout+5*time.Second)
		defer cancel()

		cmd := exec.CommandContext(probeCtx, command, argv...)
		isolateFromTerminalSignals(cmd)

		var stderr bytes.Buffer
		cmd.Stderr = &stderr

		output, err := cmd.Output()
		if err != nil {
			return nil, fmt.Errorf("egress probe failed: %w: %s", err, strings.TrimSpace(stderr.String()))
		}

		return output, nil
	}

	rootNFT, err := newSystemUnderlayNFT()
	if err != nil {
		return nil, err
	}

	return newVPNEgressLab(m, f, runWG, probe, randomTunnelLinkName, rootNFT), nil
}

func newVPNEgressLab(
	m *NetNSLabManager,
	f *LabFirewall,
	runWG wgLabCommand,
	probe egressProbeRunner,
	linkName func() (string, error),
	rootNFT underlayNFT,
) *VPNEgressLab {
	return &VPNEgressLab{
		manager:  m,
		firewall: f,
		runWG:    runWG,
		probe:    probe,
		linkName: linkName,
		rootNFT:  rootNFT,
		underlay: make(map[string]underlayTunnel),
	}
}

func randomTunnelLinkName() (string, error) {
	var data [4]byte
	if _, err := rand.Read(data[:]); err != nil {
		return "", fmt.Errorf("generate tunnel link name: %w", err)
	}

	return "egwg" + hex.EncodeToString(data[:]), nil
}

func planVPNTunnel(cfg *ImportedWireGuardConfig) (vpnTunnelPlan, error) {
	if cfg == nil {
		return vpnTunnelPlan{}, errors.New("missing WireGuard config")
	}

	host, err := netip.ParseAddr(cfg.endpointHost)
	if err != nil || !host.Is4() {
		return vpnTunnelPlan{}, fmt.Errorf("%w: endpoint must be an IPv4 address", ErrUnsupportedTunnelConfig)
	}

	plan, err := planVPNNetwork(cfg)
	if err != nil {
		return vpnTunnelPlan{}, err
	}

	plan.endpoint = netip.AddrPortFrom(host, cfg.endpointPort)

	return plan, nil
}

// planVPNNetwork checks the interface addresses and AllowedIPs. It neither resolves nor selects
// the remote endpoint.
func planVPNNetwork(cfg *ImportedWireGuardConfig) (vpnTunnelPlan, error) {
	if cfg == nil {
		return vpnTunnelPlan{}, errors.New("missing WireGuard config")
	}

	var plan vpnTunnelPlan

	fullTunnel := false
	for _, route := range cfg.allowedIPs {
		if route.Bits() == 0 && route.Addr().Is4() {
			fullTunnel = true
		}
	}

	if !fullTunnel {
		return vpnTunnelPlan{}, fmt.Errorf("%w: AllowedIPs must include 0.0.0.0/0", ErrUnsupportedTunnelConfig)
	}

	for _, address := range cfg.addresses {
		if address.Addr().Is4() {
			plan.addresses = append(plan.addresses, address)
		} else {
			plan.skippedIPv6++
		}
	}

	if len(plan.addresses) == 0 {
		return vpnTunnelPlan{}, fmt.Errorf("%w: an IPv4 interface address is required", ErrUnsupportedTunnelConfig)
	}

	return plan, nil
}

func ParseEgressProbeURL(raw string) (EgressProbeTarget, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.User != nil || u.Fragment != "" || (u.Port() != "" && u.Port() != "443") {
		return EgressProbeTarget{}, errors.New("probe URL must be https on port 443")
	}

	ip, err := netip.ParseAddr(u.Hostname())
	if err != nil || !ip.Is4() {
		return EgressProbeTarget{}, errors.New("probe host must be an IPv4 literal; the lab namespace has no DNS")
	}

	return EgressProbeTarget{URL: raw, IP: ip}, nil
}

func FetchEgressTrace(ctx context.Context, rawURL string) ([]byte, error) {
	target, err := ParseEgressProbeURL(rawURL)
	if err != nil {
		return nil, err
	}

	dialer := &net.Dialer{Timeout: egressProbeTimeout}

	// No proxy from the environment, no redirect, no connection reuse, and a dialer that reaches
	// only the pinned address: nothing in this client can resolve a name.
	transport := &http.Transport{
		Proxy:             nil,
		DialContext:       pinnedProbeDial(target.IP, dialer.DialContext),
		DisableKeepAlives: true,
	}
	defer transport.CloseIdleConnections()

	client := &http.Client{
		Timeout:   egressProbeTimeout,
		Transport: transport,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	request, err := http.NewRequestWithContext(ctx, http.MethodGet, target.URL, nil)
	if err != nil {
		return nil, err
	}

	response, err := client.Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("probe returned HTTP %d", response.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(response.Body, maxEgressProbeBytes+1))
	if err != nil {
		return nil, err
	}

	if len(body) > maxEgressProbeBytes {
		return nil, errors.New("probe response too large")
	}

	return body, nil
}

func parseTraceIP(body []byte) (netip.Addr, error) {
	var found netip.Addr

	scanner := bufio.NewScanner(bytes.NewReader(body))
	for scanner.Scan() {
		value, ok := strings.CutPrefix(strings.TrimSpace(scanner.Text()), "ip=")
		if !ok {
			continue
		}

		if found.IsValid() {
			return netip.Addr{}, errors.New("probe response has more than one ip field")
		}

		ip, err := netip.ParseAddr(value)
		if err != nil {
			return netip.Addr{}, errors.New("probe response has an invalid ip field")
		}

		found = ip
	}

	if !found.IsValid() {
		return netip.Addr{}, errors.New("probe response has no ip field")
	}

	return found, nil
}

func egressProbeRules(probe netip.Addr) (string, error) {
	if !probe.Is4() {
		return "", errors.New("probe address must be IPv4")
	}

	return fmt.Sprintf("add rule inet %[1]s output oifname %[2]q ip daddr %[3]s tcp dport 443 accept\n"+
		"add rule inet %[1]s input iifname %[2]q ip saddr %[3]s tcp sport 443 ct state established accept\n",
		labNFTTable, labWGInterface, probe), nil
}

func (f *LabFirewall) PermitEgressProbe(ctx context.Context, name string, probe netip.Addr) error {
	if !labNamePattern.MatchString(name) {
		return errors.New("invalid lab namespace name")
	}

	script, err := egressProbeRules(probe)
	if err != nil {
		return err
	}

	f.manager.mu.Lock()
	defer f.manager.mu.Unlock()

	return f.applyVerifiedLocked(ctx, name, script)
}

func (l *VPNEgressLab) Connect(ctx context.Context, name string, cfg *ImportedWireGuardConfig) error {
	if !labNamePattern.MatchString(name) {
		return errors.New("invalid lab namespace name")
	}

	plan, err := planVPNTunnel(cfg)
	if err != nil {
		return err
	}

	l.manager.mu.Lock()
	defer l.manager.mu.Unlock()

	// Bringing a tunnel up opens traffic, so the kernel ruleset must match what was installed.
	if err := l.firewall.requireVerifiedLocked(ctx, name); err != nil {
		return err
	}

	link, err := l.linkName()
	if err != nil {
		return err
	}

	mark, err := tunnelMark(link)
	if err != nil {
		return err
	}

	table, err := underlayTableName(name)
	if err != nil {
		return err
	}

	// The underlay policy exists before the link, so the first encrypted packet is already confined.
	if err := l.installUnderlayLocked(ctx, name, underlayTunnel{table: table, mark: mark, endpoint: plan.endpoint}); err != nil {
		return fmt.Errorf("install underlay policy: %w", err)
	}

	if err := l.ip(ctx, "link", "add", link, "type", "wireguard"); err != nil {
		return fmt.Errorf("create tunnel link: %w", err)
	}

	if err := l.ip(ctx, "link", "set", link, "netns", name); err != nil {
		moveErr := fmt.Errorf("move tunnel link into %s: %w", name, err)

		if delErr := l.ip(context.WithoutCancel(ctx), "link", "del", link); delErr != nil {
			return errors.Join(moveErr, fmt.Errorf("remove tunnel link %s from the VM: %w", link, delErr))
		}

		return moveErr
	}

	if err := l.ip(ctx, "-n", name, "link", "set", link, "name", labWGInterface); err != nil {
		return fmt.Errorf("rename tunnel link: %w", err)
	}

	return l.configureVPNLinkLocked(ctx, name, cfg, plan, mark, nil)
}

// configureVPNLinkLocked configures wg0 once it is inside the lab namespace. beforePeer, if set,
// runs after the fwmark is set and before any peer exists. The caller must hold manager.mu.
func (l *VPNEgressLab) configureVPNLinkLocked(
	ctx context.Context,
	name string,
	cfg *ImportedWireGuardConfig,
	plan vpnTunnelPlan,
	mark uint32,
	beforePeer func(context.Context) error,
) error {
	// The fwmark is set before any peer exists, so no encrypted packet ever leaves unmarked.
	if _, err := l.runWG(ctx, name, cfg.privateKey,
		"set", labWGInterface, "fwmark", fmt.Sprintf("0x%08x", mark), "private-key", "/dev/stdin",
	); err != nil {
		return fmt.Errorf("set tunnel fwmark and private key: %w", err)
	}

	if beforePeer != nil {
		if err := beforePeer(ctx); err != nil {
			return fmt.Errorf("pre-peer verification failed: %w", err)
		}
	}

	peer := []string{
		"set", labWGInterface,
		"peer", cfg.peerPublicKey,
		"endpoint", plan.endpoint.String(),
		"allowed-ips", "0.0.0.0/0",
	}

	if cfg.keepalive > 0 {
		peer = append(peer, "persistent-keepalive", strconv.Itoa(int(cfg.keepalive)))
	}

	if _, err := l.runWG(ctx, name, nil, peer...); err != nil {
		return fmt.Errorf("set tunnel peer: %w", err)
	}

	if len(cfg.peerPresharedKey) != 0 {
		if _, err := l.runWG(ctx, name, cfg.peerPresharedKey,
			"set", labWGInterface, "peer", cfg.peerPublicKey, "preshared-key", "/dev/stdin",
		); err != nil {
			return fmt.Errorf("set tunnel preshared key: %w", err)
		}
	}

	var steps [][]string
	for _, address := range plan.addresses {
		steps = append(steps, []string{"-n", name, "addr", "add", address.String(), "dev", labWGInterface})
	}

	if cfg.mtu > 0 {
		steps = append(steps, []string{"-n", name, "link", "set", labWGInterface, "mtu", strconv.Itoa(cfg.mtu)})
	}

	steps = append(steps,
		[]string{"-n", name, "link", "set", labWGInterface, "up"},
		[]string{"-n", name, "-4", "route", "add", "default", "dev", labWGInterface},
	)

	for _, step := range steps {
		if err := l.ip(ctx, step...); err != nil {
			return fmt.Errorf("configure tunnel: %w", err)
		}
	}

	return nil
}

func (l *VPNEgressLab) DropPeer(ctx context.Context, name string, cfg *ImportedWireGuardConfig) error {
	if !labNamePattern.MatchString(name) || cfg == nil {
		return errors.New("invalid tunnel removal request")
	}

	l.manager.mu.Lock()
	defer l.manager.mu.Unlock()

	if err := l.requireSealedLocked(name); err != nil {
		return err
	}

	if _, err := l.runWG(ctx, name, nil, "set", labWGInterface, "peer", cfg.peerPublicKey, "remove"); err != nil {
		return fmt.Errorf("remove tunnel peer: %w", err)
	}

	return nil
}

func (l *VPNEgressLab) LatestHandshake(ctx context.Context, name string) (time.Time, error) {
	if !labNamePattern.MatchString(name) {
		return time.Time{}, errors.New("invalid lab namespace name")
	}

	output, err := l.runWG(ctx, name, nil, "show", labWGInterface, "latest-handshakes")
	if err != nil {
		return time.Time{}, err
	}

	fields := strings.Fields(output)
	if len(fields) != 2 {
		return time.Time{}, errors.New("unexpected handshake output")
	}

	seconds, err := strconv.ParseInt(fields[1], 10, 64)
	if err != nil || seconds < 0 {
		return time.Time{}, errors.New("unexpected handshake timestamp")
	}

	if seconds == 0 {
		return time.Time{}, nil
	}

	return time.Unix(seconds, 0), nil
}

func (l *VPNEgressLab) Probe(ctx context.Context, namespace string, target EgressProbeTarget) (netip.Addr, error) {
	if namespace != "" && !labNamePattern.MatchString(namespace) {
		return netip.Addr{}, errors.New("invalid lab namespace name")
	}

	body, err := l.probe(ctx, namespace, target.URL)
	if err != nil {
		return netip.Addr{}, err
	}

	return parseTraceIP(body)
}

func (l *VPNEgressLab) requireSealedLocked(name string) error {
	if _, ok := l.manager.owned[name]; !ok {
		return fmt.Errorf("namespace %s is not owned by this session", name)
	}

	if !l.firewall.sealed[name] {
		return fmt.Errorf("namespace %s must be sealed before the tunnel is configured", name)
	}

	return nil
}

func (l *VPNEgressLab) ip(ctx context.Context, args ...string) error {
	commandCtx, cancel := context.WithTimeout(ctx, netNSCommandTimeout)
	defer cancel()

	_, err := l.manager.run(commandCtx, args...)
	return err
}
