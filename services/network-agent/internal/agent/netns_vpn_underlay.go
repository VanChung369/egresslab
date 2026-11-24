package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os/exec"
	"strconv"
	"strings"
)

// The encrypted WireGuard UDP socket stays in the namespace where the interface was created (the
// VM's root namespace), even after wg0 moves into the lab namespace. The lab firewall cannot see
// that traffic, so every tunnel gets its own root-namespace table:
//
//   - wg0 marks its encrypted packets with a per-tunnel fwmark (wg set ... fwmark);
//   - packets carrying that mark may only go to the configured IPv4 endpoint and port;
//   - every other packet with that mark (other address, IPv6, roamed endpoint) is dropped.
//
// The base chain has policy accept, so the VM's own unmarked traffic is unaffected.
const underlayTablePrefix = "egresslab_ul_"

type nftRootRunner func(ctx context.Context, script string, checkOnly bool) error

type nftRootLister func(ctx context.Context, table string) ([]byte, error)

type underlayNFT struct {
	run  nftRootRunner
	list nftRootLister
}

func newSystemUnderlayNFT() (underlayNFT, error) {
	nftPath, err := findSystemBinary("nft")
	if err != nil {
		return underlayNFT{}, err
	}

	run := func(ctx context.Context, script string, checkOnly bool) error {
		args := []string{"-f", "-"}
		if checkOnly {
			args = append([]string{"--check"}, args...)
		}

		cmd := exec.CommandContext(ctx, nftPath, args...)
		isolateFromTerminalSignals(cmd)
		cmd.Stdin = strings.NewReader(script)

		output, err := cmd.CombinedOutput()
		if err != nil {
			return fmt.Errorf("nft in the VM namespace: %w: %s", err, strings.TrimSpace(string(output)))
		}

		return nil
	}

	list := func(ctx context.Context, table string) ([]byte, error) {
		cmd := exec.CommandContext(ctx, nftPath, "-j", "list", "table", "inet", table)
		isolateFromTerminalSignals(cmd)

		var stderr bytes.Buffer
		cmd.Stderr = &stderr

		output, err := cmd.Output()
		if err != nil {
			return nil, fmt.Errorf("nft list %s: %w: %s", table, err, strings.TrimSpace(stderr.String()))
		}

		return output, nil
	}

	return underlayNFT{run: run, list: list}, nil
}

// underlayTableName ties the root-namespace table to its lab namespace by the namespace's id.
func underlayTableName(namespace string) (string, error) {
	if !labNamePattern.MatchString(namespace) {
		return "", errors.New("invalid lab namespace name")
	}

	return underlayTablePrefix + strings.TrimPrefix(namespace, "egresslab-lab-"), nil
}

// tunnelMark derives the fwmark from the random tunnel link name (egwg + 8 hex digits).
func tunnelMark(link string) (uint32, error) {
	if !tunnelLinkPattern.MatchString(link) {
		return 0, errors.New("invalid tunnel link name")
	}

	mark, err := strconv.ParseUint(strings.TrimPrefix(link, "egwg"), 16, 32)
	if err != nil || mark == 0 {
		return 0, errors.New("tunnel link name does not yield a usable fwmark")
	}

	return uint32(mark), nil
}

func underlayRules(table string, mark uint32, endpoint netip.AddrPort) (string, error) {
	if !strings.HasPrefix(table, underlayTablePrefix) || mark == 0 || !endpoint.Addr().Is4() || endpoint.Port() == 0 {
		return "", errors.New("invalid underlay policy parameters")
	}

	return fmt.Sprintf(`create table inet %[1]s
add chain inet %[1]s output { type filter hook output priority 0; policy accept; }
add rule inet %[1]s output meta mark 0x%08[2]x ip daddr %[3]s udp dport %[4]d accept
add rule inet %[1]s output meta mark 0x%08[2]x drop
`, table, mark, endpoint.Addr(), endpoint.Port()), nil
}

func (u underlayNFT) apply(ctx context.Context, script string) error {
	for _, checkOnly := range []bool{true, false} {
		commandCtx, cancel := context.WithTimeout(ctx, netNSCommandTimeout)
		err := u.run(commandCtx, script, checkOnly)
		cancel()

		if err != nil {
			return fmt.Errorf("apply underlay policy (check=%t): %w", checkOnly, err)
		}
	}

	return nil
}

type underlayTunnel struct {
	table    string
	mark     uint32
	endpoint netip.AddrPort
}

// verifyUnderlayRuleset checks `nft -j list table inet <table>` output against the policy.
func verifyUnderlayRuleset(data []byte, want underlayTunnel) error {
	var doc struct {
		Nftables []map[string]json.RawMessage `json:"nftables"`
	}

	if err := json.Unmarshal(data, &doc); err != nil {
		return fmt.Errorf("parse nft JSON: %w", err)
	}

	tables, chains := 0, 0
	var rules [][]any

	for _, raw := range doc.Nftables {
		encoded, _ := json.Marshal(raw)

		var obj nftObject
		if err := json.Unmarshal(encoded, &obj); err != nil {
			return err
		}

		switch {
		case raw["metainfo"] != nil:

		case obj.Table != nil:
			if obj.Table.Family != "inet" || obj.Table.Name != want.table || len(obj.Table.Flags) != 0 {
				return fmt.Errorf("unexpected table %s", obj.Table.Name)
			}
			tables++

		case obj.Chain != nil:
			c := obj.Chain
			if c.Table != want.table || c.Name != "output" || c.Type != "filter" || c.Hook != "output" ||
				c.Prio == nil || *c.Prio != 0 || c.Policy != "accept" {
				return fmt.Errorf("unexpected chain %s in %s", c.Name, want.table)
			}
			chains++

		case obj.Rule != nil:
			if obj.Rule.Table != want.table || obj.Rule.Chain != "output" {
				return fmt.Errorf("unexpected rule in %s chain %s", obj.Rule.Table, obj.Rule.Chain)
			}

			decoder := json.NewDecoder(bytes.NewReader(obj.Rule.Expr))
			decoder.UseNumber()

			var expr []any
			if err := decoder.Decode(&expr); err != nil {
				return err
			}

			rules = append(rules, expr)

		default:
			return errors.New("unexpected object in underlay table")
		}
	}

	if tables != 1 || chains != 1 || len(rules) != 2 {
		return fmt.Errorf("underlay table %s must hold one chain with two rules", want.table)
	}

	mark := strconv.FormatUint(uint64(want.mark), 10)

	allow, verdict := ruleMatches(rules[0])

	// Implicit dependencies nft may list for inet tables; they may only restate udp over IPv4.
	if value, exists := allow["meta:l4proto"]; exists && value != "udp" && value != "17" {
		return errors.New("unexpected underlay transport protocol")
	}

	if value, exists := allow["meta:nfproto"]; exists && value != "ipv4" && value != "2" {
		return errors.New("unexpected underlay address family")
	}

	delete(allow, "meta:l4proto")
	delete(allow, "meta:nfproto")

	if verdict != "accept" || len(allow) != 3 || allow["meta:mark"] != mark ||
		allow["payload:ip.daddr"] != want.endpoint.Addr().String() ||
		allow["payload:udp.dport"] != strconv.Itoa(int(want.endpoint.Port())) {
		return errors.New("underlay allow rule does not match the tunnel endpoint")
	}

	deny, verdict := ruleMatches(rules[1])
	if verdict != "drop" || len(deny) != 1 || deny["meta:mark"] != mark {
		return errors.New("underlay drop rule does not match the tunnel mark")
	}

	return nil
}

// ruleMatches flattens the "==" matches of a rule into key -> value, plus its verdict, which must
// be the last statement. Duplicate keys or anything else make the rule unreadable (nil, "").
func ruleMatches(expr []any) (map[string]string, string) {
	matches := map[string]string{}
	verdict := ""

	for i, element := range expr {
		statement, ok := element.(map[string]any)
		if !ok || len(statement) != 1 {
			return nil, ""
		}

		for kind, body := range statement {
			switch kind {
			case "accept", "drop":
				if i != len(expr)-1 || body != nil {
					return nil, ""
				}

				verdict = kind

			case "match":
				m, ok := body.(map[string]any)
				if !ok || m["op"] != "==" {
					return nil, ""
				}

				key := matchKey(m["left"])
				if key == "" {
					return nil, ""
				}

				if _, duplicate := matches[key]; duplicate {
					return nil, ""
				}

				value, exists := m["right"]
				if !exists || value == nil {
					return nil, ""
				}

				matches[key] = fmt.Sprint(value)

			default:
				return nil, ""
			}
		}
	}

	if verdict == "" {
		return nil, ""
	}

	return matches, verdict
}

func matchKey(left any) string {
	l, _ := left.(map[string]any)

	if meta, ok := l["meta"].(map[string]any); ok {
		return fmt.Sprintf("meta:%v", meta["key"])
	}

	if payload, ok := l["payload"].(map[string]any); ok {
		return fmt.Sprintf("payload:%v.%v", payload["protocol"], payload["field"])
	}

	return ""
}

// installUnderlayLocked creates the per-tunnel root-namespace policy before any tunnel exists.
func (l *VPNEgressLab) installUnderlayLocked(ctx context.Context, name string, tunnel underlayTunnel) error {
	if _, exists := l.underlay[name]; exists {
		return fmt.Errorf("namespace %s already has an underlay policy", name)
	}

	script, err := underlayRules(tunnel.table, tunnel.mark, tunnel.endpoint)
	if err != nil {
		return err
	}

	if err := l.rootNFT.apply(ctx, script); err != nil {
		return err
	}

	l.underlay[name] = tunnel

	return nil
}

// VerifyUnderlay reads back the root-namespace table and wg0's fwmark and checks both against
// the policy installed by Connect.
func (l *VPNEgressLab) VerifyUnderlay(ctx context.Context, name string) error {
	if !labNamePattern.MatchString(name) {
		return errors.New("invalid lab namespace name")
	}

	l.manager.mu.Lock()
	defer l.manager.mu.Unlock()

	return l.verifyUnderlayLocked(ctx, name)
}

// The caller must hold manager.mu.
func (l *VPNEgressLab) verifyUnderlayLocked(ctx context.Context, name string) error {
	tunnel, ok := l.underlay[name]
	if !ok {
		return fmt.Errorf("namespace %s has no underlay policy", name)
	}

	commandCtx, cancel := context.WithTimeout(ctx, netNSCommandTimeout)
	defer cancel()

	data, err := l.rootNFT.list(commandCtx, tunnel.table)
	if err != nil {
		return fmt.Errorf("read back underlay policy: %w", err)
	}

	if err := verifyUnderlayRuleset(data, tunnel); err != nil {
		return err
	}

	output, err := l.runWG(ctx, name, nil, "show", labWGInterface, "fwmark")
	if err != nil {
		return fmt.Errorf("read back tunnel fwmark: %w", err)
	}

	mark, err := strconv.ParseUint(strings.TrimSpace(output), 0, 32)
	if err != nil || uint32(mark) != tunnel.mark {
		return fmt.Errorf("tunnel fwmark is %q, expected 0x%x", strings.TrimSpace(output), tunnel.mark)
	}

	return nil
}

// Disconnect removes the tunnel link first (no more encrypted packets), then its underlay table.
// If the link cannot be removed, the table is kept so marked traffic stays restricted.
func (l *VPNEgressLab) Disconnect(ctx context.Context, name string) error {
	if !labNamePattern.MatchString(name) {
		return errors.New("invalid lab namespace name")
	}

	l.manager.mu.Lock()
	defer l.manager.mu.Unlock()

	tunnel, ok := l.underlay[name]
	if !ok {
		return nil
	}

	if _, owned := l.manager.owned[name]; owned {
		if err := l.ip(ctx, "-n", name, "link", "del", labWGInterface); err != nil && !linkMissing(err) {
			return fmt.Errorf("remove tunnel link before its underlay policy: %w", err)
		}
	}

	commandCtx, cancel := context.WithTimeout(ctx, netNSCommandTimeout)
	defer cancel()

	if err := l.rootNFT.run(commandCtx, fmt.Sprintf("delete table inet %s\n", tunnel.table), false); err != nil {
		return fmt.Errorf("remove underlay policy %s: %w", tunnel.table, err)
	}

	delete(l.underlay, name)

	return nil
}

func linkMissing(err error) bool {
	message := err.Error()
	return strings.Contains(message, "Cannot find device") || strings.Contains(message, "does not exist")
}
