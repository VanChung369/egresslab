package helperipc

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/VanChung369/egresslab/services/network-agent/internal/helperauth"
)

// PreparedLeaseInfo is the receipt of a sealed, generation-bound lease preparation. It is not an
// active lease and permits no traffic.
type PreparedLeaseInfo struct {
	CandidateInfo

	AuthorityID      string `json:"authority_id"`
	ReservationID    string `json:"reservation_id"`
	PreparationNonce string `json:"preparation_nonce"`
}

// preparedEgressLease keeps the candidate's original evidence, and with it the monotonic deadline:
// preparation never makes the evidence younger. The monitor renews only its own health.
type preparedEgressLease struct {
	info     PreparedLeaseInfo
	evidence verifiedMultiProbeEvidence
	monitor  egressMonitorHealth
}

func (p *preparedEgressLease) fresh(now time.Time) bool {
	return p != nil && p.evidence.fresh(now)
}

// prepareLeaseIntent rebuilds the only preparation intent a candidate can back; only the authority
// and reservation IDs come from the controller.
func prepareLeaseIntent(c CandidateInfo, authorityID, reservationID string) (helperauth.Intent, error) {
	if !c.valid() {
		return helperauth.Intent{}, errEvidenceUnavailable
	}

	return helperauth.NewPrepareEgressLeaseIntent(c.ProfileID, c.Namespace, c.IdentIPv4, c.TunnelGeneration,
		c.EvidenceNonce, c.ReservationNonce, c.RuntimeID, authorityID, reservationID, c.IPv4.String())
}

func validPrepareLeaseIntent(intent *helperauth.Intent) bool {
	if intent == nil {
		return false
	}

	expected, err := helperauth.NewPrepareEgressLeaseIntent(intent.ProfileID, intent.Namespace, intent.ProbeIPv4,
		intent.TunnelGeneration, intent.EvidenceNonce, intent.ReservationNonce, intent.RuntimeID, intent.AuthorityID,
		intent.ReservationID, intent.EgressIPv4)

	return err == nil && *intent == expected
}

func (p *PreparedLeaseInfo) valid() bool {
	if p == nil || !p.CandidateInfo.valid() || !helperauth.ValidCapabilityNonce(p.PreparationNonce) ||
		p.PreparationNonce == p.EvidenceNonce || p.PreparationNonce == p.ReservationNonce {
		return false
	}

	_, err := prepareLeaseIntent(p.CandidateInfo, p.AuthorityID, p.ReservationID)

	return err == nil
}

// matchesCapability binds the receipt to the request structurally; the helper verified the
// signature.
func (p *PreparedLeaseInfo) matchesCapability(intent *helperauth.Intent, capability *helperauth.SignedCapability) bool {
	if !p.valid() || !validPrepareLeaseIntent(intent) || capability == nil {
		return false
	}

	expected, err := prepareLeaseIntent(p.CandidateInfo, p.AuthorityID, p.ReservationID)
	claims := capability.Claims

	return err == nil &&
		*intent == expected &&
		claims.Intent == expected &&
		claims.Version == helperauth.Version &&
		claims.HelperID == p.HelperID &&
		claims.Nonce == p.PreparationNonce
}

// prepareEgressLease consumes the local candidate, once, under the lifecycle lock, and binds it to
// one signed durable reservation after a fresh tunnel verification. It opens no traffic. The
// helper cannot read the controller's journal: the controller must sign a preparation only after
// its durable uniqueness transaction committed.
//
// Refusals before the capability is accepted leave the candidate untouched; once accepted, it is
// gone for good, and a verification failure faults the lab and removes the tunnel.
func (l *LabLifecycle) prepareEgressLease(
	ctx context.Context,
	req Request,
	v *helperauth.Verifier,
	runtimeID string,
) (PreparedLeaseInfo, error) {
	if req.Version != Version || req.Operation != helperauth.OpPrepareEgressLease || !validPrepareLeaseIntent(req.Intent) {
		return PreparedLeaseInfo{}, errLabInvalid
	}

	if l == nil || l.backend == nil || l.generationProbes == nil || l.multiProbes == nil {
		return PreparedLeaseInfo{}, errLabUnavailable
	}

	if v == nil || req.Capability == nil {
		return PreparedLeaseInfo{}, errLabAuthorization
	}

	if !l.mu.TryLock() {
		return PreparedLeaseInfo{}, errLabBusy
	}
	defer l.mu.Unlock()

	if l.closed || ctx.Err() != nil {
		return PreparedLeaseInfo{}, errLabUnavailable
	}

	if l.blockCreation {
		return PreparedLeaseInfo{}, errLabUncertain
	}

	requested := *req.Intent

	lab, exists := l.labs.get(requested.ProfileID)
	if !exists {
		return PreparedLeaseInfo{}, errLabNotFound
	}

	if lab.Namespace != requested.Namespace {
		return PreparedLeaseInfo{}, errLabOwnership
	}

	switch lab.State {
	case LabTunnelConfigured:
	case LabSealed:
		return PreparedLeaseInfo{}, errLabInvalid
	default:
		return PreparedLeaseInfo{}, errLabFaulted
	}

	if l.tunnelProfile != lab.ProfileID || l.tunnels == nil {
		return PreparedLeaseInfo{}, errLabUncertain
	}

	// One prepared lease per tunnel slot; not even an expired one is replaced.
	if l.preparedLease != nil {
		return PreparedLeaseInfo{}, errLabBusy
	}

	candidate := l.localCandidate
	if !candidate.fresh(time.Now()) {
		return PreparedLeaseInfo{}, errEvidenceUnavailable
	}

	expected, err := prepareLeaseIntent(candidate.info, requested.AuthorityID, requested.ReservationID)
	if err != nil || requested != expected {
		return PreparedLeaseInfo{}, errLabAuthorization
	}

	record := l.candidateRetirements[candidate.info.ReservationNonce]
	if record == nil || record.retired || record.candidate != candidate.info ||
		!record.bindingMatches(requested.AuthorityID, requested.ReservationID) {
		return PreparedLeaseInfo{}, errLabUncertain
	}

	policy, err := l.multiProbePolicyLocked(v, runtimeID)
	if err != nil {
		return PreparedLeaseInfo{}, err
	}

	if policy != candidate.info.MultiProbePolicyInfo {
		return PreparedLeaseInfo{}, errLabUncertain
	}

	generation, err := l.currentGenerationLocked(lab.Namespace)
	if err != nil || l.candidateGenerationContradicted {
		return PreparedLeaseInfo{}, errLabUncertain
	}

	if generation != expected.TunnelGeneration {
		return PreparedLeaseInfo{}, errLabAuthorization
	}

	// A preparation is its own signed attempt, never an earlier phase's capability again.
	nonce := req.Capability.Claims.Nonce
	if nonce == candidate.info.EvidenceNonce || nonce == candidate.info.ReservationNonce {
		return PreparedLeaseInfo{}, errLabAuthorization
	}

	if ctx.Err() != nil {
		return PreparedLeaseInfo{}, errLabUnavailable
	}

	if !candidate.fresh(time.Now()) {
		return PreparedLeaseInfo{}, errEvidenceUnavailable
	}

	if err := v.VerifyAndConsume(*req.Capability, expected); err != nil {
		return PreparedLeaseInfo{}, fmt.Errorf("%w: %w", errLabAuthorization, err)
	}

	// Bound on acceptance, so a failed verification or a lost receipt still names the reservation.
	record.bind(expected.AuthorityID, expected.ReservationID)
	record.preparationNonce = nonce

	// The consumption point: from here, no failure or timeout restores the candidate.
	l.localCandidate = nil
	l.verifiedEvidence = nil

	verifyCtx, cancel := context.WithDeadline(ctx, candidate.evidence.expiresAt)
	defer cancel()

	// Expired since the last check: nothing has run against the kernel, so the tunnel stays.
	if verifyCtx.Err() != nil || !candidate.fresh(time.Now()) {
		return PreparedLeaseInfo{}, errEvidenceUnavailable
	}

	// The full kernel check, the sealed firewall included.
	if _, err := l.verifyTunnelLocked(verifyCtx, lab); err != nil {
		return PreparedLeaseInfo{}, err
	}

	current, err := l.currentGenerationLocked(lab.Namespace)
	if err == nil && current != generation {
		err = errors.New("tunnel generation changed during lease preparation")
	}

	if err != nil {
		faulted := lab
		faulted.State = LabFaulted
		l.labs.set(lab.ProfileID, faulted)

		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), tunnelCleanupTimeout)
		defer cleanupCancel()

		return PreparedLeaseInfo{}, errors.Join(errLabUncertain, err, l.clearTunnelLocked(cleanupCtx, faulted))
	}

	result := PreparedLeaseInfo{
		CandidateInfo:    candidate.info,
		AuthorityID:      expected.AuthorityID,
		ReservationID:    expected.ReservationID,
		PreparationNonce: nonce,
	}

	if !result.matchesCapability(&expected, req.Capability) {
		return PreparedLeaseInfo{}, errLabUncertain
	}

	if !candidate.fresh(time.Now()) || verifyCtx.Err() != nil {
		return PreparedLeaseInfo{}, errEvidenceUnavailable
	}

	l.preparedLease = &preparedEgressLease{
		info:     result,
		evidence: candidate.evidence,
		monitor: egressMonitorHealth{
			observedAt: candidate.evidence.observedAt,
			checkedAt:  candidate.evidence.recordedAt,
			expiresAt:  candidate.evidence.expiresAt,
		},
	}

	return result, nil
}

func validPreparedLeaseResponse(req Request, resp Response, receivedAt time.Time) bool {
	if req.Operation != helperauth.OpPrepareEgressLease || !resp.OK {
		return resp.PreparedLease == nil
	}

	return !resp.NetworkReady &&
		resp.PreparedLease.matchesCapability(req.Intent, req.Capability) &&
		!receivedAt.Before(resp.PreparedLease.ObservedAt) &&
		receivedAt.Before(resp.PreparedLease.ExpiresAt)
}

// PrepareEgressLease submits one signed preparation for the lab and durable reservation it names.
// It never activates traffic.
func PrepareEgressLease(
	ctx context.Context,
	socketPath, profileID, namespace string,
	capability helperauth.SignedCapability,
) (Response, error) {
	signed := capability.Claims.Intent

	if !validPrepareLeaseIntent(&signed) || signed.ProfileID != profileID || signed.Namespace != namespace {
		return Response{}, &Error{Code: CodeInvalidRequest, Message: "invalid lease preparation capability"}
	}

	return callRequest(ctx, socketPath, Request{
		Version:    Version,
		Operation:  signed.Operation,
		Intent:     &signed,
		Capability: &capability,
	})
}
