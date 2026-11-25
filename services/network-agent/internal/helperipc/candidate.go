package helperipc

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"time"

	"github.com/VanChung369/egresslab/services/network-agent/internal/helperauth"
)

var errEvidenceUnavailable = errors.New("no matching fresh verified egress evidence")

// CandidateInfo is a local reservation receipt: one consumed V2 attempt's address, bound to its
// tunnel generation and helper. It is neither a global reservation nor a lease, and permits no
// traffic. ExpiresAt is the evidence's deadline as wall-clock metadata; the helper keeps the
// monotonic one.
type CandidateInfo struct {
	MultiProbeTargetInfo

	EvidenceNonce    string `json:"evidence_nonce"`    // the consumed PermitMultiProbeV2 attempt
	ReservationNonce string `json:"reservation_nonce"` // the ReserveEgressCandidateV1 capability

	IPv4       netip.Addr `json:"ipv4"`
	ObservedAt time.Time  `json:"observed_at"`
	ExpiresAt  time.Time  `json:"expires_at"`
}

// localEgressCandidate keeps the original evidence, and with it the monotonic deadline: a
// reservation never makes the evidence younger.
type localEgressCandidate struct {
	info     CandidateInfo
	evidence verifiedMultiProbeEvidence
}

func (c *localEgressCandidate) fresh(now time.Time) bool {
	return c != nil && c.evidence.fresh(now)
}

func (c *CandidateInfo) valid() bool {
	return c != nil &&
		c.MultiProbeTargetInfo.valid() &&
		helperauth.ValidPublicProbeIPv4(c.IPv4) &&
		helperauth.ValidCapabilityNonce(c.EvidenceNonce) &&
		helperauth.ValidCapabilityNonce(c.ReservationNonce) &&
		c.EvidenceNonce != c.ReservationNonce &&
		c.ObservedAt.Unix() > 0 &&
		c.ExpiresAt.After(c.ObservedAt) &&
		c.ExpiresAt.Sub(c.ObservedAt) <= verifiedProbeEvidenceTTL
}

func validCandidateIntent(intent *helperauth.Intent) bool {
	if intent == nil {
		return false
	}

	expected, err := helperauth.NewReserveEgressCandidateIntent(intent.ProfileID, intent.Namespace, intent.ProbeIPv4,
		intent.TunnelGeneration, intent.EvidenceNonce)

	return err == nil && *intent == expected
}

// candidateIntentFromEvidence rebuilds the only reservation intent the evidence can back. The
// request never chooses the address.
func candidateIntentFromEvidence(e *verifiedMultiProbeEvidence) (helperauth.Intent, error) {
	if e == nil || e.intent.Operation != helperauth.OpPermitMultiProbeV2 || !helperauth.ValidPublicProbeIPv4(e.ipv4) {
		return helperauth.Intent{}, errEvidenceUnavailable
	}

	return helperauth.NewReserveEgressCandidateIntent(e.intent.ProfileID, e.intent.Namespace, e.intent.ProbeIPv4,
		e.intent.TunnelGeneration, e.nonce)
}

// matchesCapability binds the receipt to the request structurally; the helper verified the
// signature.
func (c *CandidateInfo) matchesCapability(intent *helperauth.Intent, capability *helperauth.SignedCapability) bool {
	if !c.valid() || !validCandidateIntent(intent) || capability == nil {
		return false
	}

	expected, err := helperauth.NewReserveEgressCandidateIntent(c.ProfileID, c.Namespace, c.IdentIPv4,
		c.TunnelGeneration, c.EvidenceNonce)

	claims := capability.Claims

	return err == nil &&
		*intent == expected &&
		claims.Intent == expected &&
		claims.Version == helperauth.Version &&
		claims.HelperID == c.HelperID &&
		claims.Nonce == c.ReservationNonce
}

// reserveEgressCandidate consumes the helper's V2 evidence, once, under the lifecycle lock, and
// publishes a local candidate after a fresh tunnel verification. It opens no firewall, activates no
// lease and reserves nothing across runtimes.
//
// Refusals before the capability is accepted leave the evidence untouched. Once it is accepted,
// the evidence is gone for good: a failure never restores it, and a verification failure faults
// the lab and removes the tunnel as VerifyLab does.
func (l *LabLifecycle) reserveEgressCandidate(
	ctx context.Context,
	req Request,
	v *helperauth.Verifier,
	runtimeID string,
) (CandidateInfo, error) {
	if req.Version != Version || req.Operation != helperauth.OpReserveEgressCandidate || !validCandidateIntent(req.Intent) {
		return CandidateInfo{}, errLabInvalid
	}

	if l == nil || l.backend == nil || l.generationProbes == nil || l.multiProbes == nil {
		return CandidateInfo{}, errLabUnavailable
	}

	if v == nil || req.Capability == nil {
		return CandidateInfo{}, errLabAuthorization
	}

	if !l.mu.TryLock() {
		return CandidateInfo{}, errLabBusy
	}
	defer l.mu.Unlock()

	if l.closed || ctx.Err() != nil {
		return CandidateInfo{}, errLabUnavailable
	}

	if l.blockCreation {
		return CandidateInfo{}, errLabUncertain
	}

	requested := *req.Intent

	lab, exists := l.labs[requested.ProfileID]
	if !exists {
		return CandidateInfo{}, errLabNotFound
	}

	if lab.Namespace != requested.Namespace {
		return CandidateInfo{}, errLabOwnership
	}

	switch lab.State {
	case LabTunnelConfigured:
	case LabSealed:
		return CandidateInfo{}, errLabInvalid
	default:
		return CandidateInfo{}, errLabFaulted
	}

	if l.tunnelProfile != lab.ProfileID || l.tunnels == nil {
		return CandidateInfo{}, errLabUncertain
	}

	// The helper's evidence is the only source of the address.
	evidence := l.verifiedEvidence
	if !evidence.fresh(time.Now()) {
		return CandidateInfo{}, errEvidenceUnavailable
	}

	expected, err := candidateIntentFromEvidence(evidence)
	if err != nil {
		return CandidateInfo{}, errEvidenceUnavailable
	}

	if requested != expected {
		return CandidateInfo{}, errLabAuthorization
	}

	policy, err := l.multiProbePolicyLocked(v, runtimeID)
	if err != nil {
		return CandidateInfo{}, err
	}

	if policy.Policy != helperauth.OpPermitMultiProbeV2 || policy.HelperID != evidence.helperID ||
		policy.IdentIPv4 != expected.ProbeIPv4 {
		return CandidateInfo{}, errLabUncertain
	}

	generation, err := l.generationProbes.CurrentTunnelGeneration(lab.Namespace)
	if err != nil {
		return CandidateInfo{}, errLabUncertain
	}

	if generation != expected.TunnelGeneration {
		return CandidateInfo{}, errLabAuthorization
	}

	// A reservation is its own signed attempt, never the probe's capability again.
	if req.Capability.Claims.Nonce == evidence.nonce {
		return CandidateInfo{}, errLabAuthorization
	}

	if ctx.Err() != nil {
		return CandidateInfo{}, errLabUnavailable
	}

	if !evidence.fresh(time.Now()) {
		return CandidateInfo{}, errEvidenceUnavailable
	}

	if err := v.VerifyAndConsume(*req.Capability, expected); err != nil {
		return CandidateInfo{}, fmt.Errorf("%w: %w", errLabAuthorization, err)
	}

	// The consumption point: from here, no failure or timeout restores the evidence.
	l.verifiedEvidence = nil
	l.localCandidate = nil

	verifyCtx, cancel := context.WithDeadline(ctx, evidence.expiresAt)
	defer cancel()

	// Expired since the last check: nothing has run against the kernel, so the tunnel is left as
	// it is rather than faulted for a timing reason. A deadline passing during the verification
	// below does fault the lab, like any failed verification.
	if verifyCtx.Err() != nil || !evidence.fresh(time.Now()) {
		return CandidateInfo{}, errEvidenceUnavailable
	}

	if _, err := l.verifyTunnelLocked(verifyCtx, lab); err != nil {
		return CandidateInfo{}, err
	}

	// The tunnel verified; it must still be the generation the evidence names.
	current, err := l.generationProbes.CurrentTunnelGeneration(lab.Namespace)
	if err == nil && current != generation {
		err = errors.New("tunnel generation changed during the reservation")
	}

	if err != nil {
		faulted := lab
		faulted.State = LabFaulted
		l.labs[lab.ProfileID] = faulted

		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), tunnelCleanupTimeout)
		defer cleanupCancel()

		return CandidateInfo{}, errors.Join(errLabUncertain, err, l.clearTunnelLocked(cleanupCtx, faulted))
	}

	if !evidence.fresh(time.Now()) {
		return CandidateInfo{}, errEvidenceUnavailable
	}

	if verifyCtx.Err() != nil {
		return CandidateInfo{}, errLabUnavailable
	}

	result := CandidateInfo{
		MultiProbeTargetInfo: MultiProbeTargetInfo{
			ProfileID:            lab.ProfileID,
			Namespace:            lab.Namespace,
			TunnelGeneration:     current,
			MultiProbePolicyInfo: policy,
		},
		EvidenceNonce:    evidence.nonce,
		ReservationNonce: req.Capability.Claims.Nonce,
		IPv4:             evidence.ipv4,
		ObservedAt:       evidence.observedAt.UTC(),
		ExpiresAt:        evidence.expiresAt.UTC(),
	}

	if !result.matchesCapability(&expected, req.Capability) {
		return CandidateInfo{}, errLabUncertain
	}

	if !evidence.fresh(time.Now()) || verifyCtx.Err() != nil {
		return CandidateInfo{}, errEvidenceUnavailable
	}

	l.localCandidate = &localEgressCandidate{info: result, evidence: *evidence}

	return result, nil
}

func validCandidateResponse(req Request, resp Response, receivedAt time.Time) bool {
	if req.Operation != helperauth.OpReserveEgressCandidate || !resp.OK {
		return resp.Candidate == nil
	}

	return !resp.NetworkReady &&
		resp.Candidate.matchesCapability(req.Intent, req.Capability) &&
		!receivedAt.Before(resp.Candidate.ObservedAt) &&
		receivedAt.Before(resp.Candidate.ExpiresAt)
}

// ReserveEgressCandidate asks for a local candidate from one verified attempt. It takes no
// observed address: only the helper's evidence names one.
func ReserveEgressCandidate(
	ctx context.Context,
	socketPath, profileID, namespace string,
	capability helperauth.SignedCapability,
) (Response, error) {
	signed := capability.Claims.Intent

	intent, err := helperauth.NewReserveEgressCandidateIntent(profileID, namespace, signed.ProbeIPv4,
		signed.TunnelGeneration, signed.EvidenceNonce)
	if err != nil || signed != intent {
		return Response{}, &Error{Code: CodeInvalidRequest, Message: "invalid egress candidate capability"}
	}

	return callRequest(ctx, socketPath, Request{
		Version:    Version,
		Operation:  intent.Operation,
		Intent:     &intent,
		Capability: &capability,
	})
}
