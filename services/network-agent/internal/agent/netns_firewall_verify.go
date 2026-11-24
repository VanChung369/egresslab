package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
)

// ErrFirewallDrift means the kernel ruleset of a lab namespace no longer matches what this session
// installed. Operations that open traffic are refused until Reconcile succeeds.
var ErrFirewallDrift = errors.New("lab firewall drifted from the installed ruleset")

type nftRulesetLister func(ctx context.Context, namespace string) ([]byte, error)

type nftObject struct {
	Table *struct {
		Family string `json:"family"`
		Name   string `json:"name"`
		// Lab tables never set flags. "dormant" keeps the rules listed but stops enforcing them;
		// nft 1.0.2 prints it as broken JSON, later versions as a value.
		Flags json.RawMessage `json:"flags"`
	} `json:"table"`
	Chain *struct {
		Family string `json:"family"`
		Table  string `json:"table"`
		Name   string `json:"name"`
		Type   string `json:"type"`
		Hook   string `json:"hook"`
		Prio   *int   `json:"prio"`
		Policy string `json:"policy"`
	} `json:"chain"`
	Rule *struct {
		Family string          `json:"family"`
		Table  string          `json:"table"`
		Chain  string          `json:"chain"`
		Expr   json.RawMessage `json:"expr"`
	} `json:"rule"`
	Metainfo json.RawMessage `json:"metainfo"`
}

// labRulesetFingerprint parses `nft -j list ruleset` output from a lab namespace, checks the
// structure every sealed lab must have, and returns a stable fingerprint of all rules.
//
// Structure: exactly one table (inet egresslab_lab), exactly the input/output/forward filter base
// chains at priority 0 with policy drop, and nothing else (no sets, maps, objects or other tables).
func labRulesetFingerprint(data []byte) (string, error) {
	var doc struct {
		Nftables []map[string]json.RawMessage `json:"nftables"`
	}

	if err := json.Unmarshal(data, &doc); err != nil {
		return "", fmt.Errorf("parse nft JSON: %w", err)
	}

	tables := 0
	chains := map[string]bool{}
	var rules []string

	for _, raw := range doc.Nftables {
		if len(raw) != 1 {
			return "", errors.New("unexpected nft JSON object")
		}

		var kind string
		for key := range raw {
			kind = key
		}

		encoded, _ := json.Marshal(raw)

		var obj nftObject
		if err := json.Unmarshal(encoded, &obj); err != nil {
			return "", fmt.Errorf("parse nft %s: %w", kind, err)
		}

		switch kind {
		case "metainfo":

		case "table":
			if obj.Table == nil {
				return "", errors.New("missing nft table")
			}

			if obj.Table.Family != "inet" || obj.Table.Name != labNFTTable {
				return "", fmt.Errorf("unexpected table %s %s in lab namespace", obj.Table.Family, obj.Table.Name)
			}

			if len(obj.Table.Flags) != 0 {
				return "", fmt.Errorf("table %s has flags %s", obj.Table.Name, obj.Table.Flags)
			}
			tables++

		case "chain":
			if obj.Chain == nil {
				return "", errors.New("missing nft chain")
			}

			c := obj.Chain
			if c.Family != "inet" || c.Table != labNFTTable {
				return "", fmt.Errorf("unexpected chain %s in table %s", c.Name, c.Table)
			}

			switch c.Name {
			case "input", "output", "forward":
			default:
				return "", fmt.Errorf("unexpected chain %s", c.Name)
			}

			if chains[c.Name] {
				return "", fmt.Errorf("duplicate chain %s", c.Name)
			}

			if c.Type != "filter" || c.Hook != c.Name || c.Prio == nil || *c.Prio != 0 || c.Policy != "drop" {
				return "", fmt.Errorf("chain %s is not a priority-0 filter chain with policy drop", c.Name)
			}

			chains[c.Name] = true

		case "rule":
			if obj.Rule == nil {
				return "", errors.New("missing nft rule")
			}

			r := obj.Rule
			if r.Family != "inet" || r.Table != labNFTTable || !chains[r.Chain] {
				return "", fmt.Errorf("unexpected rule in %s %s chain %s", r.Family, r.Table, r.Chain)
			}

			expr, err := canonicalJSON(r.Expr)
			if err != nil {
				return "", fmt.Errorf("parse rule expression: %w", err)
			}

			rules = append(rules, r.Chain+" "+expr)

		default:
			return "", fmt.Errorf("unexpected nft object %q in lab namespace", kind)
		}
	}

	if tables != 1 {
		return "", fmt.Errorf("expected exactly one %s table, found %d", labNFTTable, tables)
	}

	if len(chains) != 3 {
		missing := []string{}
		for _, name := range []string{"input", "output", "forward"} {
			if !chains[name] {
				missing = append(missing, name)
			}
		}
		sort.Strings(missing)

		return "", fmt.Errorf("missing chains: %s", strings.Join(missing, ", "))
	}

	return strings.Join(rules, "\n"), nil
}

func canonicalJSON(raw json.RawMessage) (string, error) {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()

	var value any
	if err := decoder.Decode(&value); err != nil {
		return "", err
	}

	out, err := json.Marshal(value)
	if err != nil {
		return "", err
	}

	return string(out), nil
}

// readbackLocked reads the kernel ruleset of a lab namespace and returns its fingerprint.
func (f *LabFirewall) readbackLocked(ctx context.Context, name string) (string, error) {
	commandCtx, cancel := context.WithTimeout(ctx, netNSCommandTimeout)
	defer cancel()

	data, err := f.list(commandCtx, name)
	if err != nil {
		return "", fmt.Errorf("read back lab firewall in %s: %w", name, err)
	}

	return labRulesetFingerprint(data)
}

// recordLocked remembers a script that was applied and captures the resulting kernel state as the
// baseline. If the state cannot be read back, the namespace is marked drifted (fail closed).
func (f *LabFirewall) recordLocked(ctx context.Context, name, script string) error {
	f.applied[name] = append(f.applied[name], script)

	if f.list == nil {
		return nil
	}

	fingerprint, err := f.readbackLocked(ctx, name)
	if err != nil {
		f.drifted[name] = true
		return fmt.Errorf("%w: %w", ErrFirewallDrift, err)
	}

	f.baseline[name] = fingerprint
	delete(f.drifted, name)

	return nil
}

// verifyLocked re-reads the kernel ruleset and compares it with the baseline captured after the
// last change made by this session. Any difference marks the namespace drifted.
func (f *LabFirewall) verifyLocked(ctx context.Context, name string) error {
	if f.drifted[name] {
		return fmt.Errorf("%w in %s; call Reconcile before opening traffic", ErrFirewallDrift, name)
	}

	if f.list == nil {
		return nil
	}

	fingerprint, err := f.readbackLocked(ctx, name)
	if err != nil {
		f.drifted[name] = true
		return fmt.Errorf("%w in %s: %w", ErrFirewallDrift, name, err)
	}

	if fingerprint != f.baseline[name] {
		f.drifted[name] = true
		return fmt.Errorf("%w in %s: rules were changed outside this session", ErrFirewallDrift, name)
	}

	return nil
}

// requireVerifiedLocked is the gate for every operation that opens traffic in a lab namespace.
func (f *LabFirewall) requireVerifiedLocked(ctx context.Context, name string) error {
	if _, ok := f.manager.owned[name]; !ok {
		return fmt.Errorf("namespace %s is not owned by this session", name)
	}

	if !f.sealed[name] {
		return fmt.Errorf("namespace %s must be sealed first", name)
	}

	return f.verifyLocked(ctx, name)
}

// Verify checks that the kernel ruleset still matches what this session installed.
func (f *LabFirewall) Verify(ctx context.Context, name string) error {
	if !labNamePattern.MatchString(name) {
		return errors.New("invalid lab namespace name")
	}

	f.manager.mu.Lock()
	defer f.manager.mu.Unlock()

	return f.requireVerifiedLocked(ctx, name)
}

// Reconcile atomically replaces the lab table with every rule this session applied, then
// re-captures the baseline. It never touches other tables.
func (f *LabFirewall) Reconcile(ctx context.Context, name string) error {
	if !labNamePattern.MatchString(name) {
		return errors.New("invalid lab namespace name")
	}

	f.manager.mu.Lock()
	defer f.manager.mu.Unlock()

	if _, ok := f.manager.owned[name]; !ok {
		return fmt.Errorf("namespace %s is not owned by this session", name)
	}

	if !f.sealed[name] || len(f.applied[name]) == 0 {
		return fmt.Errorf("namespace %s was never sealed by this session", name)
	}

	// Never rebuild a firewall around a live WireGuard interface. The manager lock is held, so
	// no other lab operation can attach a tunnel between this check and the apply below.
	if err := f.requireOfflineForReconcileLocked(ctx, name); err != nil {
		return err
	}

	// "add" makes the delete safe when the table vanished; the whole file is one nft transaction.
	script := fmt.Sprintf("add table inet %[1]s\ndelete table inet %[1]s\n", labNFTTable) +
		strings.Join(f.applied[name], "")

	if err := f.apply(ctx, name, script); err != nil {
		return err
	}

	if f.list == nil {
		delete(f.drifted, name)
		return nil
	}

	fingerprint, err := f.readbackLocked(ctx, name)
	if err != nil {
		f.drifted[name] = true
		return fmt.Errorf("%w after reconcile: %w", ErrFirewallDrift, err)
	}

	f.baseline[name] = fingerprint
	delete(f.drifted, name)

	return nil
}
