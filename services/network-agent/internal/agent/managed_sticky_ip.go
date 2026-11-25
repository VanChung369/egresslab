package agent

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
)

const managedTunnelGenerationPrefix = "tunnelgen_"

var ErrManagedStickyIPChanged = errors.New("managed tunnel public IPv4 differs from its generation pin")

// newManagedTunnelGeneration names one managed tunnel lifetime with 128 random bits. It is an
// identifier, not a secret: a reconnect of the same profile, namespace and config gets a new one.
func newManagedTunnelGeneration() (string, error) {
	var id [16]byte

	if _, err := rand.Read(id[:]); err != nil {
		return "", fmt.Errorf("create tunnel generation: %w", err)
	}

	return managedTunnelGenerationPrefix + hex.EncodeToString(id[:]), nil
}

// acceptStickyConsensusLocked pins the generation's expected IPv4 at its first complete
// verification, and requires every later one to match it; the pin is never replaced. It takes
// only consensus from the current attempt on the active tunnel, and activates nothing. The caller
// must hold manager.mu.
func (b *ManagedTunnelBackend) acceptStickyConsensusLocked(t *managedTunnel, consensus managedProbeConsensus) error {
	if t == nil || b.active != t || t.generation == "" || t.faulted || t.linkRemoved {
		return ErrManagedTunnelUncertain
	}

	ip, err := parseCandidateIPv4(consensus.ipv4.String())
	if err != nil {
		return err
	}

	if consensus.observedAt.IsZero() ||
		len(consensus.sourceIDs) < minManagedProbeSources || len(consensus.sourceIDs) > maxManagedProbeSources {
		return ErrManagedProbeEvidenceIncomplete
	}

	if !t.expectedIPv4.IsValid() {
		t.expectedIPv4 = ip
		return nil
	}

	if t.expectedIPv4 != ip {
		return ErrManagedStickyIPChanged
	}

	return nil
}
