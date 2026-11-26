package helperipc

import (
	"context"
	"errors"
	"net/netip"
	"time"

	"github.com/VanChung369/egresslab/services/network-agent/internal/helperauth"
)

const (
	OpMultiProbeTarget = "MultiProbeTarget"

	// Short on purpose, ahead of the candidate reservation of Step 31.
	verifiedProbeEvidenceTTL = 60 * time.Second
)

var errVerifiedEvidenceExpired = errors.New("verified multi-source evidence expired")

// GenerationProbeTunnelBackend adds the generation-bound probe to the multi-source backend.
type GenerationProbeTunnelBackend interface {
	MultiProbeTunnelBackend

	CurrentTunnelGeneration(namespace string) (string, error)
	ProbeConfiguredMultiForGeneration(ctx context.Context, namespace, generation string) (MultiProbeObservation, error)
}

// NewGenerationProbeLifecycle enables PermitMultiProbeV2 only: PermitMultiProbeV1 and the
// single-source probe stay disabled, so nothing falls back to an unbound probe.
func NewGenerationProbeLifecycle(backend LabBackend, tunnels GenerationProbeTunnelBackend) *LabLifecycle {
	l := NewMultiProbeLifecycle(backend, tunnels)
	l.generationProbes = tunnels

	return l
}

func (l *LabLifecycle) multiProbeOperationEnabled(op string) bool {
	if l == nil || l.multiProbes == nil {
		return false
	}

	switch op {
	case helperauth.OpPermitMultiProbe:
		return l.generationProbes == nil
	case helperauth.OpPermitMultiProbeV2:
		return l.generationProbes != nil
	default:
		return false
	}
}

// MultiProbeTargetInfo is one snapshot of a lab's tracked tunnel generation and the V2 policy of
// the helper generation that tracks it. It reports helper state, not a verified kernel, and
// authorizes nothing.
type MultiProbeTargetInfo struct {
	ProfileID        string `json:"profile_id"`
	Namespace        string `json:"namespace"`
	TunnelGeneration string `json:"tunnel_generation"`

	MultiProbePolicyInfo
}

func (p *MultiProbeTargetInfo) valid() bool {
	return p != nil &&
		helperauth.ValidProfileID(p.ProfileID) &&
		helperauth.ValidLabNamespace(p.Namespace) &&
		helperauth.ValidTunnelGeneration(p.TunnelGeneration) &&
		p.Policy == helperauth.OpPermitMultiProbeV2 &&
		p.MultiProbePolicyInfo.valid()
}

// validMultiProbeTargetIntent: a read-only request names the lab, and nothing else.
func validMultiProbeTargetIntent(intent *helperauth.Intent) bool {
	return intent != nil &&
		helperauth.ValidProfileID(intent.ProfileID) &&
		helperauth.ValidLabNamespace(intent.Namespace) &&
		*intent == helperauth.Intent{Operation: OpMultiProbeTarget, ProfileID: intent.ProfileID, Namespace: intent.Namespace}
}

func validMultiProbeTargetResponse(req Request, resp Response) bool {
	if req.Operation != OpMultiProbeTarget || !resp.OK {
		return resp.MultiProbeTarget == nil
	}

	return req.Capability == nil &&
		validMultiProbeTargetIntent(req.Intent) &&
		resp.MultiProbeTarget.valid() &&
		resp.MultiProbeTarget.ProfileID == req.Intent.ProfileID &&
		resp.MultiProbeTarget.Namespace == req.Intent.Namespace
}

// readMultiProbeTarget reads the lab's configured tunnel generation and the policy, without
// verifying the kernel, opening a window or consuming anything. It does not wait behind a running
// operation.
func (l *LabLifecycle) readMultiProbeTarget(
	ctx context.Context,
	intent *helperauth.Intent,
	v *helperauth.Verifier,
	runtimeID string,
) (MultiProbeTargetInfo, error) {
	if !validMultiProbeTargetIntent(intent) {
		return MultiProbeTargetInfo{}, errLabInvalid
	}

	if l == nil || l.generationProbes == nil || l.multiProbes == nil || v == nil || ctx.Err() != nil {
		return MultiProbeTargetInfo{}, errLabUnavailable
	}

	if !l.mu.TryLock() {
		return MultiProbeTargetInfo{}, errLabBusy
	}
	defer l.mu.Unlock()

	if l.closed || ctx.Err() != nil {
		return MultiProbeTargetInfo{}, errLabUnavailable
	}

	if l.blockCreation {
		return MultiProbeTargetInfo{}, errLabUncertain
	}

	lab, exists := l.labs[intent.ProfileID]
	if !exists {
		return MultiProbeTargetInfo{}, errLabNotFound
	}

	if lab.Namespace != intent.Namespace {
		return MultiProbeTargetInfo{}, errLabOwnership
	}

	// A sealed lab is healthy but has no tunnel to target; only a faulted one must be deleted.
	switch lab.State {
	case LabTunnelConfigured:
	case LabSealed:
		return MultiProbeTargetInfo{}, errLabInvalid
	default:
		return MultiProbeTargetInfo{}, errLabFaulted
	}

	if l.tunnelProfile != lab.ProfileID {
		return MultiProbeTargetInfo{}, errLabUncertain
	}

	generation, err := l.currentGenerationLocked(lab.Namespace)
	if err != nil {
		return MultiProbeTargetInfo{}, errLabUncertain
	}

	policy, err := l.multiProbePolicyLocked(v, runtimeID)
	if err != nil {
		return MultiProbeTargetInfo{}, err
	}

	if ctx.Err() != nil {
		return MultiProbeTargetInfo{}, errLabUnavailable
	}

	result := MultiProbeTargetInfo{
		ProfileID:            lab.ProfileID,
		Namespace:            lab.Namespace,
		TunnelGeneration:     generation,
		MultiProbePolicyInfo: policy,
	}

	if !result.valid() {
		return MultiProbeTargetInfo{}, errLabUncertain
	}

	return result, nil
}

// verifiedMultiProbeEvidence is helper-owned: it is made only from a V2 attempt this helper ran and
// checked, never from anything a client sends. It is neither a reservation nor a lease.
type verifiedMultiProbeEvidence struct {
	intent   helperauth.Intent
	helperID string
	nonce    string

	ipv4       netip.Addr
	observedAt time.Time

	recordedAt time.Time
	expiresAt  time.Time
}

// evidenceClockStable requires to after from, with wall-clock progress within 1 s of monotonic
// progress. Both must come from time.Now.
func evidenceClockStable(from, to time.Time) bool {
	elapsed := to.Sub(from)
	step := to.Round(0).Sub(from.Round(0)) - elapsed

	return elapsed >= 0 && step >= -time.Second && step <= time.Second
}

// newVerifiedMultiProbeEvidence records a checked V2 attempt. Its deadline is the earlier of 60 s
// after the helper accepted the capability and 60 s after the oldest source observation, on the
// monotonic clock.
func newVerifiedMultiProbeEvidence(
	info MultiProbeInfo,
	capability helperauth.SignedCapability,
	acceptedAt, now time.Time,
) (*verifiedMultiProbeEvidence, error) {
	intent := capability.Claims.Intent

	if intent.Operation != helperauth.OpPermitMultiProbeV2 ||
		!validMultiProbeForCapability(&info, &intent, &capability) ||
		!multiProbeWithin(&info, acceptedAt, now) ||
		!evidenceClockStable(acceptedAt, now) {
		return nil, errLabUncertain
	}

	age := now.Sub(info.ObservedAt)
	if age < 0 || age >= verifiedProbeEvidenceTTL {
		return nil, errVerifiedEvidenceExpired
	}

	expiresAt := acceptedAt.Add(verifiedProbeEvidenceTTL)
	if observedDeadline := now.Add(verifiedProbeEvidenceTTL - age); observedDeadline.Before(expiresAt) {
		expiresAt = observedDeadline
	}

	if !now.Before(expiresAt) {
		return nil, errVerifiedEvidenceExpired
	}

	return &verifiedMultiProbeEvidence{
		intent:     intent,
		helperID:   capability.Claims.HelperID,
		nonce:      capability.Claims.Nonce,
		ipv4:       info.IPv4,
		observedAt: info.ObservedAt,
		recordedAt: now,
		expiresAt:  expiresAt,
	}, nil
}

// fresh reports whether the evidence may still back a decision at now (from time.Now).
func (e *verifiedMultiProbeEvidence) fresh(now time.Time) bool {
	if e == nil || !evidenceClockStable(e.recordedAt, now) || !now.Before(e.expiresAt) {
		return false
	}

	age := now.Sub(e.observedAt)

	return age >= 0 && age < verifiedProbeEvidenceTTL
}

// invalidateEvidenceLocked drops the local authorization state of profileID: unconsumed evidence,
// the local candidate and the prepared lease. It is not durable IP ownership, and dropping it proves
// no kernel cleanup. The caller must hold l.mu.
func (l *LabLifecycle) invalidateEvidenceLocked(profileID string) {
	if l.proxyStream != nil && l.proxyStream.profileID == profileID {
		l.closeProxyStreamLocked()
	}

	if l.verifiedEvidence != nil && l.verifiedEvidence.intent.ProfileID == profileID {
		l.verifiedEvidence = nil
	}

	if l.localCandidate != nil && l.localCandidate.info.ProfileID == profileID {
		l.localCandidate = nil
	}

	if l.preparedLease != nil && l.preparedLease.info.ProfileID == profileID {
		l.preparedLease = nil
	}
}

// ReadMultiProbeTarget reads a lab's tunnel generation and the V2 policy. It sends no capability.
func ReadMultiProbeTarget(ctx context.Context, socketPath, profileID, namespace string) (Response, error) {
	intent := helperauth.Intent{Operation: OpMultiProbeTarget, ProfileID: profileID, Namespace: namespace}

	if !validMultiProbeTargetIntent(&intent) {
		return Response{}, &Error{Code: CodeInvalidRequest, Message: "invalid multi-source target"}
	}

	return callRequest(ctx, socketPath, Request{Version: Version, Operation: OpMultiProbeTarget, Intent: &intent})
}

// ProbeEgressMultiV2 asks for one generation-bound attempt. It never falls back to
// ProbeEgressMulti, and takes no destination or generation besides the signed ones.
func ProbeEgressMultiV2(
	ctx context.Context,
	socketPath, profileID, namespace string,
	capability helperauth.SignedCapability,
) (Response, error) {
	intent, err := helperauth.NewGenerationProbeIntent(profileID, namespace, capability.Claims.Intent.ProbeIPv4,
		capability.Claims.Intent.TunnelGeneration)
	if err != nil || capability.Claims.Intent != intent {
		return Response{}, &Error{Code: CodeInvalidRequest, Message: "invalid generation-bound capability"}
	}

	return callRequest(ctx, socketPath, Request{
		Version:    Version,
		Operation:  intent.Operation,
		Intent:     &intent,
		Capability: &capability,
	})
}
