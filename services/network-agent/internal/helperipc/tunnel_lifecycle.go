package helperipc

import (
	"context"
	"errors"
	"fmt"

	"github.com/VanChung369/egresslab/services/network-agent/internal/helperauth"
)

const (
	OpDisconnect        = "Disconnect"
	LabTunnelConfigured = "tunnel_configured"
)

// TunnelBackend deliberately exposes no probe, proxy, command or raw configuration.
// ConnectStage wraps ErrStageNotFound only when it touched nothing.
type TunnelBackend interface {
	ConnectStage(ctx context.Context, profileID, namespace, stageID string) error
	VerifyConfigured(ctx context.Context, namespace string) error
	CleanupStage(ctx context.Context, namespace string) error
}

// NewTunnelLifecycle shares one mutex and ownership registry between labs and the tunnel.
func NewTunnelLifecycle(backend LabBackend, tunnels TunnelBackend) *LabLifecycle {
	l := NewLabLifecycle(backend)
	l.tunnels = tunnels

	return l
}

// errTunnelSlotBusy is LAB_BUSY that does not clear on its own: Disconnect or DeleteLab frees it.
var errTunnelSlotBusy = fmt.Errorf("%w: the managed tunnel slot is held", errLabBusy)

// The caller must hold l.mu.
func (l *LabLifecycle) connectTunnelLocked(
	ctx context.Context,
	lab LabInfo,
	intent helperauth.Intent,
	capability *helperauth.SignedCapability,
	v *helperauth.Verifier,
) (LabInfo, error) {
	if l.tunnels == nil {
		return LabInfo{}, errLabUnavailable
	}

	if capability == nil || v == nil {
		return LabInfo{}, errLabAuthorization
	}

	if l.blockCreation {
		return LabInfo{}, errLabUncertain
	}

	// All refusals come before the capability is consumed.
	switch {
	case lab.State == LabTunnelConfigured:
		return LabInfo{}, errTunnelSlotBusy
	case lab.State != LabSealed:
		return LabInfo{}, errLabFaulted
	case l.tunnelProfile != "":
		return LabInfo{}, errTunnelSlotBusy
	}

	// A candidate-bearing generation still in the slot must be retired first.
	if l.candidateGeneration != "" {
		return LabInfo{}, errLabUncertain
	}

	if err := v.VerifyAndConsume(*capability, intent); err != nil {
		return LabInfo{}, fmt.Errorf("%w: %w", errLabAuthorization, err)
	}

	// A new tunnel inherits no evidence, candidate or prepared lease.
	l.verifiedEvidence = nil
	l.localCandidate = nil
	l.preparedLease = nil

	// Tracked before any kernel change.
	l.tunnelProfile = lab.ProfileID
	sealed := lab
	lab.State = LabFaulted
	l.labs[lab.ProfileID] = lab

	if err := l.tunnels.ConnectStage(ctx, lab.ProfileID, lab.Namespace, intent.StageID); err != nil {
		// The vault refused the stage before anything ran: the lab is untouched.
		if errors.Is(err, ErrStageNotFound) {
			l.tunnelProfile = ""
			l.labs[lab.ProfileID] = sealed

			return LabInfo{}, err
		}

		// Even a clean rollback leaves the lab faulted: only DeleteLab clears it.
		return LabInfo{}, fmt.Errorf("%w: connect tunnel: %w", errLabUncertain, err)
	}

	lab.State = LabTunnelConfigured
	l.labs[lab.ProfileID] = lab

	return lab, nil
}

// clearTunnelLocked releases the tunnel slot if lab holds it. A failed cleanup faults the lab and
// keeps the slot. Only a confirmed cleanup retires the slot's candidate-bearing generation, and
// not when the backend names another generation. The caller must hold l.mu.
func (l *LabLifecycle) clearTunnelLocked(ctx context.Context, lab LabInfo) error {
	// Before the cleanup, whatever its outcome; dropping authorization proves no cleanup.
	l.invalidateEvidenceLocked(lab.ProfileID)

	if l.tunnelProfile != lab.ProfileID {
		return nil
	}

	if l.tunnels == nil {
		return errLabUncertain
	}

	generation := l.candidateGeneration
	proofAllowed := true

	// A removed or faulted tunnel has no readable generation; that alone does not refuse proof, but
	// a contradiction seen now or by any earlier read does.
	if generation != "" {
		if l.generationProbes != nil {
			_, _ = l.currentGenerationLocked(lab.Namespace)
		}

		proofAllowed = l.generationProbes != nil && !l.candidateGenerationContradicted
	}

	if err := l.tunnels.CleanupStage(ctx, lab.Namespace); err != nil {
		lab.State = LabFaulted
		l.labs[lab.ProfileID] = lab

		return fmt.Errorf("%w: tunnel cleanup: %w", errLabUncertain, err)
	}

	if generation != "" && proofAllowed {
		l.markCandidateGenerationRetiredLocked(lab, generation)
	}

	l.tunnelProfile = ""
	l.candidateGeneration = ""
	l.candidateGenerationContradicted = false

	if !proofAllowed {
		lab.State = LabFaulted
		l.labs[lab.ProfileID] = lab

		return fmt.Errorf("%w: contradictory tunnel generation", errLabUncertain)
	}

	return nil
}

// disconnectTunnelLocked keeps the namespace. A configured lab goes back to sealed (and is
// verified as such); a faulted one stays faulted for DeleteLab. The caller must hold l.mu.
func (l *LabLifecycle) disconnectTunnelLocked(ctx context.Context, lab LabInfo) (LabInfo, error) {
	if l.tunnelProfile != lab.ProfileID {
		if lab.State == LabSealed {
			return l.verifyLocked(ctx, lab)
		}

		return LabInfo{}, errLabFaulted
	}

	if err := l.clearTunnelLocked(ctx, lab); err != nil {
		return LabInfo{}, err
	}

	if lab.State == LabFaulted {
		return lab, nil
	}

	lab.State = LabSealed
	l.labs[lab.ProfileID] = lab

	return l.verifyLocked(ctx, lab)
}

// verifyTunnelLocked faults the lab on any failed check and removes the tunnel right away, with a
// fresh bounded context. The caller must hold l.mu.
func (l *LabLifecycle) verifyTunnelLocked(ctx context.Context, lab LabInfo) (LabInfo, error) {
	if l.tunnels == nil || l.tunnelProfile != lab.ProfileID {
		l.invalidateEvidenceLocked(lab.ProfileID)
		lab.State = LabFaulted
		l.labs[lab.ProfileID] = lab

		return LabInfo{}, errLabUncertain
	}

	err := l.tunnels.VerifyConfigured(ctx, lab.Namespace)
	if err == nil {
		return lab, nil
	}

	l.invalidateEvidenceLocked(lab.ProfileID)
	lab.State = LabFaulted
	l.labs[lab.ProfileID] = lab

	cleanupCtx, cancel := context.WithTimeout(context.Background(), tunnelCleanupTimeout)
	defer cancel()

	if cleanupErr := l.clearTunnelLocked(cleanupCtx, lab); cleanupErr != nil {
		return LabInfo{}, errors.Join(errLabUncertain, err, cleanupErr)
	}

	return LabInfo{}, fmt.Errorf("%w: tunnel verification: %w", errLabFaulted, err)
}

func ConnectTunnel(
	ctx context.Context,
	socketPath, profileID, namespace, stageID string,
	capability helperauth.SignedCapability,
) (Response, error) {
	intent := helperauth.Intent{
		Operation: helperauth.OpConnectTunnel,
		ProfileID: profileID,
		Namespace: namespace,
		StageID:   stageID,
	}

	return callRequest(ctx, socketPath, Request{
		Version:    Version,
		Operation:  intent.Operation,
		Intent:     &intent,
		Capability: &capability,
	})
}

// DisconnectTunnel needs no capability, so a tunnel can be removed while the controller is
// unreachable.
func DisconnectTunnel(ctx context.Context, socketPath, profileID, namespace string) (Response, error) {
	intent := helperauth.Intent{Operation: OpDisconnect, ProfileID: profileID, Namespace: namespace}

	return callRequest(ctx, socketPath, Request{Version: Version, Operation: OpDisconnect, Intent: &intent})
}
