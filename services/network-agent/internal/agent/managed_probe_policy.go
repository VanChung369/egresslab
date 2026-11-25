package agent

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
)

const (
	managedProbeSet = "egresslab_probe4"
	managedProbeIP  = "1.1.1.1"
	probeTTLSeconds = 30
)

var ErrProbePolicyDrift = errors.New("managed probe firewall policy not verified")

// managedProbeRules is the single-source window of the 29B probe, for 1.1.1.1.
func managedProbeRules() string {
	script, err := managedProbeRulesFor(netip.MustParseAddr(managedProbeIP))
	if err != nil {
		panic("invalid built-in managed probe destination")
	}

	return script
}

// managedProbeRulesFor opens a probe window for exactly one public IPv4 destination as one nft
// transaction: a one-element set whose element the kernel expires on its own, and two permits that
// both match through that set, so neither direction outlives the element even if the helper dies.
// No general "ct state established" rule is added. The permits are the same for every destination;
// only the element differs.
func managedProbeRulesFor(destination netip.Addr) (string, error) {
	if _, err := parseCandidateIPv4(destination.String()); err != nil {
		return "", ErrProbeDestination
	}

	return fmt.Sprintf(`add set inet %[1]s %[2]s { type ipv4_addr; flags timeout; size 1; }
add element inet %[1]s %[2]s { %[3]s timeout %[4]ds }
add rule inet %[1]s output oifname "wg0" ip daddr @%[2]s tcp dport 443 accept
add rule inet %[1]s input iifname "wg0" ip saddr @%[2]s tcp sport 443 ct state established accept
`, labNFTTable, managedProbeSet, destination.String(), probeTTLSeconds), nil
}

// expectedProbeRules is the canonical form of the two permits as nft 1.0.9 prints them (real
// captures in testdata/nft-lab-probe-*.json). Another rendering is refused, as for the seal.
var expectedProbeRules = map[string]string{
	"output": `[{"match":{"left":{"meta":{"key":"oifname"}},"op":"==","right":"wg0"}},` +
		`{"match":{"left":{"payload":{"field":"daddr","protocol":"ip"}},"op":"==","right":"@egresslab_probe4"}},` +
		`{"match":{"left":{"payload":{"field":"dport","protocol":"tcp"}},"op":"==","right":443}},{"accept":null}]`,
	"input": `[{"match":{"left":{"meta":{"key":"iifname"}},"op":"==","right":"wg0"}},` +
		`{"match":{"left":{"payload":{"field":"saddr","protocol":"ip"}},"op":"==","right":"@egresslab_probe4"}},` +
		`{"match":{"left":{"payload":{"field":"sport","protocol":"tcp"}},"op":"==","right":443}},` +
		`{"match":{"left":{"ct":{"key":"state"}},"op":"in","right":"established"}},{"accept":null}]`,
}

func decodeProbeJSON(data []byte, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()

	if err := decoder.Decode(target); err != nil {
		return err
	}

	if decoder.More() {
		return errors.New("trailing JSON")
	}

	return nil
}

type managedProbeSetInfo struct {
	Family string          `json:"family"`
	Table  string          `json:"table"`
	Name   string          `json:"name"`
	Type   string          `json:"type"`
	Handle uint64          `json:"handle"`
	Size   int             `json:"size"`
	Flags  []string        `json:"flags"`
	Elem   json.RawMessage `json:"elem"`
}

type managedProbeElement struct {
	Elem struct {
		Val     string `json:"val"`
		Timeout *int   `json:"timeout"`
		Expires *int   `json:"expires"`
	} `json:"elem"`
}

// verifyManagedProbeSetFor requires the reserved set exactly as the window for destination creates
// it. An active window holds that one element with time left, never another address, public or
// not; once it expired the kernel lists no "elem" at all, which only cleanup accepts.
func verifyManagedProbeSetFor(raw []byte, requireActive bool, destination netip.Addr) error {
	if _, err := parseCandidateIPv4(destination.String()); err != nil {
		return ErrProbePolicyDrift
	}

	var set managedProbeSetInfo

	if err := decodeProbeJSON(raw, &set); err != nil {
		return ErrProbePolicyDrift
	}

	if set.Family != "inet" || set.Table != labNFTTable || set.Name != managedProbeSet || set.Type != "ipv4_addr" ||
		set.Handle == 0 || set.Size != 1 || len(set.Flags) != 1 || set.Flags[0] != "timeout" {
		return ErrProbePolicyDrift
	}

	if set.Elem == nil {
		if requireActive {
			return ErrProbePolicyDrift
		}

		return nil
	}

	var elements []managedProbeElement
	if err := decodeProbeJSON(set.Elem, &elements); err != nil || len(elements) != 1 {
		return ErrProbePolicyDrift
	}

	elem := elements[0].Elem

	if elem.Val != destination.String() || elem.Timeout == nil || *elem.Timeout != probeTTLSeconds ||
		elem.Expires == nil || *elem.Expires < 0 || *elem.Expires > probeTTLSeconds {
		return ErrProbePolicyDrift
	}

	if requireActive && *elem.Expires == 0 {
		return ErrProbePolicyDrift
	}

	return nil
}

type probeRuleHandles struct {
	input  uint64
	output uint64
}

func verifyManagedProbePolicy(data []byte, requireActive bool) (probeRuleHandles, error) {
	return verifyManagedProbePolicyFor(data, requireActive, netip.MustParseAddr(managedProbeIP))
}

// verifyManagedProbePolicyFor takes exactly the window's three objects (the set for destination
// and the two permits, each permit last in its chain) out of a readback, and requires everything
// left to be the sealed policy. It returns the permits' handles for a targeted removal.
func verifyManagedProbePolicyFor(data []byte, requireActive bool, destination netip.Addr) (probeRuleHandles, error) {
	if _, err := parseCandidateIPv4(destination.String()); err != nil {
		return probeRuleHandles{}, ErrProbePolicyDrift
	}

	var doc struct {
		Nftables []map[string]json.RawMessage `json:"nftables"`
	}

	var handles probeRuleHandles

	if err := json.Unmarshal(data, &doc); err != nil {
		return handles, ErrProbePolicyDrift
	}

	setSeen := false
	permitSeen := make(map[string]bool)
	sealed := make([]map[string]json.RawMessage, 0, len(doc.Nftables))

	for _, object := range doc.Nftables {
		if len(object) != 1 {
			return handles, ErrProbePolicyDrift
		}

		if raw, exists := object["set"]; exists {
			if setSeen || verifyManagedProbeSetFor(raw, requireActive, destination) != nil {
				return handles, ErrProbePolicyDrift
			}

			setSeen = true

			continue
		}

		if raw, exists := object["rule"]; exists {
			var rule struct {
				Family string          `json:"family"`
				Table  string          `json:"table"`
				Chain  string          `json:"chain"`
				Handle uint64          `json:"handle"`
				Expr   json.RawMessage `json:"expr"`
			}

			if err := json.Unmarshal(raw, &rule); err != nil {
				return handles, ErrProbePolicyDrift
			}

			expr, err := canonicalJSON(rule.Expr)
			if err != nil {
				return handles, ErrProbePolicyDrift
			}

			if expected, known := expectedProbeRules[rule.Chain]; known && expr == expected {
				if decodeProbeJSON(raw, &rule) != nil || rule.Family != "inet" || rule.Table != labNFTTable ||
					rule.Handle == 0 || permitSeen[rule.Chain] {
					return handles, ErrProbePolicyDrift
				}

				permitSeen[rule.Chain] = true

				if rule.Chain == "input" {
					handles.input = rule.Handle
				} else {
					handles.output = rule.Handle
				}

				continue
			}

			// Every sealed rule precedes the temporary permit in its chain.
			if permitSeen[rule.Chain] {
				return handles, ErrProbePolicyDrift
			}
		}

		sealed = append(sealed, object)
	}

	if !setSeen || handles.input == 0 || handles.output == 0 || handles.input == handles.output {
		return probeRuleHandles{}, ErrProbePolicyDrift
	}

	doc.Nftables = sealed

	sealedData, err := json.Marshal(doc)
	if err != nil {
		return probeRuleHandles{}, ErrProbePolicyDrift
	}

	if err := verifySealedPolicy(sealedData); err != nil {
		return probeRuleHandles{}, fmt.Errorf("%w: %w", ErrProbePolicyDrift, err)
	}

	return handles, nil
}
