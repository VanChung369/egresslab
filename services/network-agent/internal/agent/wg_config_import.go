package agent

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"runtime"
	"strconv"
	"strings"
)

const (
	maxWireGuardConfigBytes = 64 << 10
	maxWireGuardAddresses   = 8
	maxWireGuardDNS         = 8
	maxWireGuardAllowedIPs  = 32
	redactedWireGuardConfig = "<WireGuard config: redacted>"
)

// ImportedWireGuardConfig holds secrets in memory; never log or serialize it. The only way to
// persist it is SealedWireGuardStore, which encrypts it. Key material is kept in byte slices so
// releaseWireGuardConfig can overwrite it; see that function for the limits of this.
type ImportedWireGuardConfig struct {
	privateKey       []byte
	addresses        []netip.Prefix
	dns              []netip.Addr
	mtu              int
	peerPublicKey    string
	peerPresharedKey []byte
	endpointHost     string
	endpointPort     uint16
	allowedIPs       []netip.Prefix
	keepalive        uint16
}

func (ImportedWireGuardConfig) String() string {
	return redactedWireGuardConfig
}

func (ImportedWireGuardConfig) GoString() string {
	return redactedWireGuardConfig
}

func (ImportedWireGuardConfig) Format(f fmt.State, _ rune) {
	_, _ = io.WriteString(f, redactedWireGuardConfig)
}

func (ImportedWireGuardConfig) MarshalJSON() ([]byte, error) {
	return nil, errors.New("WireGuard config must not be serialized; use Summary")
}

type WireGuardImportSummary struct {
	Status           string `json:"status"`
	EndpointHost     string `json:"endpoint_host"`
	EndpointPort     uint16 `json:"endpoint_port"`
	Addresses        int    `json:"address_count"`
	DNSServers       int    `json:"dns_servers"`
	AllowedRoutes    int    `json:"allowed_routes"`
	IPv4Default      bool   `json:"ipv4_default"`
	IPv6Default      bool   `json:"ipv6_default"`
	HasPresharedKey  bool   `json:"has_preshared_key"`
	MTU              int    `json:"mtu,omitempty"`
	KeepaliveSeconds uint16 `json:"keepalive_seconds,omitempty"`
	VPNLabCompatible bool   `json:"vpn_lab_compatible"`
	VPNLabIssue      string `json:"vpn_lab_issue,omitempty"`
	NetworkReady     bool   `json:"network_ready"`
}

func (c *ImportedWireGuardConfig) Summary() WireGuardImportSummary {
	summary := WireGuardImportSummary{
		Status:           "validated_not_connected",
		EndpointHost:     c.endpointHost,
		EndpointPort:     c.endpointPort,
		Addresses:        len(c.addresses),
		DNSServers:       len(c.dns),
		AllowedRoutes:    len(c.allowedIPs),
		HasPresharedKey:  len(c.peerPresharedKey) != 0,
		MTU:              c.mtu,
		KeepaliveSeconds: c.keepalive,
	}

	for _, route := range c.allowedIPs {
		if route.Bits() != 0 {
			continue
		}

		if route.Addr().Is4() {
			summary.IPv4Default = true
		} else {
			summary.IPv6Default = true
		}
	}

	if err := CheckVPNLabCompatibility(c); err != nil {
		summary.VPNLabIssue = strings.TrimPrefix(err.Error(), ErrUnsupportedTunnelConfig.Error()+": ")
	} else {
		summary.VPNLabCompatible = true
	}

	return summary
}

// CheckVPNLabCompatibility reports, at import time, whether the VPN egress lab can use cfg. The
// importer accepts a wider set (for example hostname endpoints) than the lab can connect.
func CheckVPNLabCompatibility(cfg *ImportedWireGuardConfig) error {
	_, err := planVPNTunnel(cfg)
	return err
}

func LoadWireGuardConfig(path string) (*ImportedWireGuardConfig, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, fmt.Errorf("inspect WireGuard file: %w", err)
	}

	if !info.Mode().IsRegular() {
		return nil, errors.New("WireGuard config must be a regular file, not a symlink")
	}

	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open WireGuard file: %w", err)
	}
	defer file.Close()

	opened, err := file.Stat()
	if err != nil {
		return nil, errors.New("could not inspect opened configuration")
	}

	if !opened.Mode().IsRegular() || !os.SameFile(info, opened) {
		return nil, errors.New("WireGuard file changed while it was being opened")
	}

	if runtime.GOOS != "windows" && opened.Mode().Perm()&0o077 != 0 {
		return nil, errors.New("WireGuard file is too accessible; run chmod 600 on the file")
	}

	return ParseWireGuardConfig(file)
}

func ParseWireGuardConfig(r io.Reader) (*ImportedWireGuardConfig, error) {
	data, err := io.ReadAll(io.LimitReader(r, maxWireGuardConfigBytes+1))
	if err != nil {
		return nil, errors.New("failed to read WireGuard configuration")
	}
	defer clear(data)

	if len(data) > maxWireGuardConfigBytes {
		return nil, errors.New("WireGuard configuration exceeds 64 KiB")
	}

	return parseWireGuardBytes(data)
}

// parseWireGuardBytes works on byte slices only, so key material never becomes an immutable
// string. The scanner buffer is as large as the input limit (it never reallocates) and is cleared.
func parseWireGuardBytes(data []byte) (cfg *ImportedWireGuardConfig, err error) {
	cfg = &ImportedWireGuardConfig{}
	defer func() {
		if err != nil {
			releaseWireGuardConfig(cfg)
			cfg = nil
		}
	}()

	section := ""
	sections := map[string]bool{}
	seen := map[string]map[string]bool{"Interface": {}, "Peer": {}}

	buffer := make([]byte, maxWireGuardConfigBytes+1)
	defer clear(buffer)

	scanner := bufio.NewScanner(bytes.NewReader(data))
	scanner.Buffer(buffer, len(buffer))

	for lineNo := 1; scanner.Scan(); lineNo++ {
		raw := bytes.TrimSpace(scanner.Bytes())
		if i := bytes.IndexByte(raw, '#'); i >= 0 {
			raw = bytes.TrimSpace(raw[:i])
		}

		if len(raw) == 0 {
			continue
		}

		if raw[0] == '[' {
			line := string(raw)
			if line != "[Interface]" && line != "[Peer]" {
				return nil, fmt.Errorf("unsupported section at line %d", lineNo)
			}

			next := strings.Trim(line, "[]")
			if next == "Peer" && sections["Peer"] {
				return nil, fmt.Errorf("multiple [Peer] sections at line %d: only single-peer configs are supported", lineNo)
			}

			if sections[next] || (next == "Interface" && sections["Peer"]) || (next == "Peer" && !sections["Interface"]) {
				return nil, fmt.Errorf("duplicate or out-of-order section at line %d", lineNo)
			}

			sections[next] = true
			section = next

			continue
		}

		rawKey, value, ok := bytes.Cut(raw, []byte("="))
		key := string(bytes.TrimSpace(rawKey))
		value = bytes.TrimSpace(value)

		if !ok || key == "" || len(value) == 0 || section == "" {
			return nil, fmt.Errorf("invalid configuration entry at line %d", lineNo)
		}

		if seen[section][key] && key != "Address" && key != "DNS" {
			return nil, fmt.Errorf("duplicate option at line %d", lineNo)
		}

		seen[section][key] = true

		option := section + "." + key

		var applyErr error
		if option == "Interface.PrivateKey" || option == "Peer.PresharedKey" {
			applyErr = cfg.applySecret(option, value)
		} else {
			applyErr = cfg.apply(option, string(value))
		}

		if applyErr != nil {
			return nil, fmt.Errorf("%s at line %d", applyErr, lineNo)
		}
	}

	if scanner.Err() != nil {
		return nil, errors.New("could not parse WireGuard configuration")
	}

	if !sections["Interface"] || !sections["Peer"] || len(cfg.privateKey) == 0 || len(cfg.addresses) == 0 ||
		cfg.peerPublicKey == "" || cfg.endpointHost == "" || len(cfg.allowedIPs) == 0 {
		return nil, errors.New("missing required WireGuard sections or fields")
	}

	return cfg, nil
}

// applySecret stores a copy of a key that the config owns and releaseWireGuardConfig clears.
func (c *ImportedWireGuardConfig) applySecret(option string, value []byte) error {
	switch option {
	case "Interface.PrivateKey":
		if !validSecretKey(value) {
			return errors.New("invalid interface key")
		}
		c.privateKey = bytes.Clone(value)

	case "Peer.PresharedKey":
		if !validSecretKey(value) {
			return errors.New("invalid peer preshared key")
		}
		c.peerPresharedKey = bytes.Clone(value)

	default:
		return errors.New("unsupported or unsafe option")
	}

	return nil
}

// validSecretKey is validImportKey for key material: canonical base64 of 32 bytes, decoded into
// fixed buffers that are cleared, without creating strings.
func validSecretKey(b []byte) bool {
	if len(b) != base64.StdEncoding.EncodedLen(32) {
		return false
	}

	var decoded [33]byte
	defer clear(decoded[:])

	n, err := base64.StdEncoding.Decode(decoded[:], b)
	if err != nil || n != 32 {
		return false
	}

	var canonical [44]byte
	defer clear(canonical[:])

	base64.StdEncoding.Encode(canonical[:], decoded[:32])

	return bytes.Equal(canonical[:], b)
}

func (c *ImportedWireGuardConfig) apply(option, value string) error {
	switch option {
	case "Interface.Address":
		prefixes, err := parsePrefixList(value, maxWireGuardAddresses-len(c.addresses))
		if err != nil {
			return errors.New("invalid interface addresses")
		}
		c.addresses = append(c.addresses, prefixes...)

	case "Interface.DNS":
		addrs, err := parseDNSList(value, maxWireGuardDNS-len(c.dns))
		if err != nil {
			return errors.New("unsupported DNS value")
		}
		c.dns = append(c.dns, addrs...)

	case "Interface.MTU":
		n, err := strconv.Atoi(value)
		if err != nil || n < 576 || n > 9000 {
			return errors.New("invalid MTU")
		}
		c.mtu = n

	case "Peer.PublicKey":
		if !validImportKey(value) {
			return errors.New("invalid peer public key")
		}
		c.peerPublicKey = value

	case "Peer.Endpoint":
		host, port, err := parseWGEndpoint(value)
		if err != nil {
			return errors.New("invalid peer endpoint")
		}
		c.endpointHost, c.endpointPort = host, port

	case "Peer.AllowedIPs":
		prefixes, err := parsePrefixList(value, maxWireGuardAllowedIPs)
		if err != nil {
			return errors.New("invalid allowed IPs")
		}
		c.allowedIPs = prefixes

	case "Peer.PersistentKeepalive":
		n, err := strconv.ParseUint(value, 10, 16)
		if err != nil {
			return errors.New("invalid keepalive")
		}
		c.keepalive = uint16(n)

	default:
		return errors.New("unsupported or unsafe option")
	}

	return nil
}

func validImportKey(s string) bool {
	b, err := base64.StdEncoding.DecodeString(s)
	return err == nil && len(b) == 32 && base64.StdEncoding.EncodeToString(b) == s
}

func parsePrefixList(value string, remaining int) ([]netip.Prefix, error) {
	parts := strings.Split(value, ",")
	if len(parts) > remaining {
		return nil, errors.New("too many addresses")
	}

	out := make([]netip.Prefix, 0, len(parts))

	for _, part := range parts {
		p, err := netip.ParsePrefix(strings.TrimSpace(part))
		if err != nil || p.Addr().Zone() != "" || p.Addr().Is4In6() {
			return nil, errors.New("invalid IP prefix")
		}

		out = append(out, p)
	}

	return out, nil
}

func parseDNSList(value string, remaining int) ([]netip.Addr, error) {
	parts := strings.Split(value, ",")
	if len(parts) > remaining {
		return nil, errors.New("too many DNS servers")
	}

	out := make([]netip.Addr, 0, len(parts))

	for _, part := range parts {
		a, err := netip.ParseAddr(strings.TrimSpace(part))
		if err != nil || a.Zone() != "" || a.Is4In6() {
			return nil, errors.New("DNS search domains unsupported")
		}

		out = append(out, a)
	}

	return out, nil
}

func parseWGEndpoint(raw string) (string, uint16, error) {
	host, rawPort, err := net.SplitHostPort(raw)
	if err != nil || host == "" {
		return "", 0, errors.New("invalid host or port")
	}

	n, err := strconv.ParseUint(rawPort, 10, 16)
	if err != nil || n == 0 {
		return "", 0, errors.New("invalid port")
	}

	if ip, err := netip.ParseAddr(host); err == nil {
		if ip.Zone() != "" {
			return "", 0, errors.New("zone addresses unsupported")
		}
	} else if !validWGHostname(host) {
		return "", 0, errors.New("invalid hostname")
	}

	return host, uint16(n), nil
}

func validWGHostname(host string) bool {
	if len(host) == 0 || len(host) > 253 {
		return false
	}

	for _, label := range strings.Split(host, ".") {
		if len(label) == 0 || len(label) > 63 {
			return false
		}

		for i, ch := range label {
			valid := (ch >= 'a' && ch <= 'z') ||
				(ch >= 'A' && ch <= 'Z') ||
				(ch >= '0' && ch <= '9') ||
				(ch == '-' && i != 0 && i != len(label)-1)

			if !valid {
				return false
			}
		}
	}

	return true
}
