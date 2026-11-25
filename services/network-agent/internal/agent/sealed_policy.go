package agent

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
)

// intendedSealedRules is the rule set sealLabRules is meant to produce, written out instead of
// learned from the kernel, in the canonical form labRulesetFingerprint returns, and in order. It
// follows the real capture in testdata/nft-lab-sealed-v2.json (nft 1.0.9). Another nft version that
// prints an equivalent rule differently is refused: fail closed, not a parser for every nft release.
var intendedSealedRules = map[string][]string{
	"input": {
		`[{"match":{"left":{"meta":{"key":"nfproto"}},"op":"==","right":"ipv6"}},{"drop":null}]`,
		`[{"match":{"left":{"meta":{"key":"iifname"}},"op":"==","right":"lo"}},{"accept":null}]`,
	},
	"output": {
		`[{"match":{"left":{"meta":{"key":"nfproto"}},"op":"==","right":"ipv6"}},{"drop":null}]`,
		`[{"match":{"left":{"payload":{"field":"dport","protocol":"udp"}},"op":"==","right":53}},{"drop":null}]`,
		`[{"match":{"left":{"payload":{"field":"dport","protocol":"tcp"}},"op":"==","right":53}},{"drop":null}]`,
		`[{"match":{"left":{"payload":{"field":"dport","protocol":"tcp"}},"op":"==","right":853}},{"drop":null}]`,
		`[{"match":{"left":{"payload":{"field":"dport","protocol":"udp"}},"op":"==","right":853}},{"drop":null}]`,
		`[{"match":{"left":{"meta":{"key":"oifname"}},"op":"==","right":"lo"}},{"accept":null}]`,
	},
	"forward": {},
}

// verifySealedPolicy checks a lab ruleset against the intended policy. labRulesetFingerprint
// already checks the table, the base chains, their hooks, priorities and drop policies.
func verifySealedPolicy(data []byte) error {
	fingerprint, err := labRulesetFingerprint(data)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrFirewallDrift, err)
	}

	actual := make(map[string][]string)

	for _, line := range strings.Split(fingerprint, "\n") {
		chain, expr, ok := strings.Cut(line, " ")
		if !ok {
			return fmt.Errorf("%w: unreadable rule", ErrFirewallDrift)
		}

		if _, known := intendedSealedRules[chain]; !known {
			return fmt.Errorf("%w: unexpected chain %s", ErrFirewallDrift, chain)
		}

		actual[chain] = append(actual[chain], expr)
	}

	for chain, expected := range intendedSealedRules {
		if !slices.Equal(actual[chain], expected) {
			return fmt.Errorf("%w: unexpected %s rules", ErrFirewallDrift, chain)
		}
	}

	return nil
}

// requireSealedPolicyLocked requires the session baseline and, on a fresh readback, the intended
// sealed policy. A mismatch marks the namespace drifted. The caller must hold manager.mu.
func (f *LabFirewall) requireSealedPolicyLocked(ctx context.Context, name string) error {
	if err := f.requireVerifiedLocked(ctx, name); err != nil {
		return err
	}

	if f.list == nil {
		return errors.New("kernel firewall readback unavailable")
	}

	commandCtx, cancel := context.WithTimeout(ctx, netNSCommandTimeout)
	defer cancel()

	data, err := f.list(commandCtx, name)
	if err == nil {
		err = verifySealedPolicy(data)
	}

	if err != nil {
		f.drifted[name] = true

		if errors.Is(err, ErrFirewallDrift) {
			return err
		}

		return fmt.Errorf("%w: %w", ErrFirewallDrift, err)
	}

	return nil
}
