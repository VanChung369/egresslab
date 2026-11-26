package helperipc

import (
	"context"
	"fmt"
	"log"

	"github.com/VanChung369/egresslab/services/network-agent/internal/helperauth"
)

const maxCandidateRetirements = 1024

// candidateRetirementRecord outlives the candidate and the prepared lease: retired turns true only
// after a confirmed cleanup of the candidate's managed tunnel generation. It keeps no capability.
type candidateRetirementRecord struct {
	candidate CandidateInfo

	authorityID      string
	reservationID    string
	preparationNonce string

	retired bool
}

// canTrackCandidateLocked refuses rather than evicts: an old record may still back a durable hold.
// The caller must hold l.mu.
func (l *LabLifecycle) canTrackCandidateLocked(generation, nonce string) error {
	// A generation that can never be proven retired gets no new authorization.
	if l.candidateGenerationContradicted || l.candidateGeneration != "" && l.candidateGeneration != generation {
		return errLabUncertain
	}

	if _, exists := l.candidateRetirements[nonce]; exists {
		return errLabAuthorization
	}

	if len(l.candidateRetirements) >= maxCandidateRetirements {
		return fmt.Errorf("%w: candidate retirement records", errLabLimit)
	}

	return nil
}

// The caller must hold l.mu.
func (l *LabLifecycle) rememberCandidateLocked(candidate CandidateInfo) error {
	if !candidate.valid() || l.tunnelProfile != candidate.ProfileID {
		return errLabUncertain
	}

	if err := l.canTrackCandidateLocked(candidate.TunnelGeneration, candidate.ReservationNonce); err != nil {
		return err
	}

	if l.candidateRetirements == nil {
		l.candidateRetirements = make(map[string]*candidateRetirementRecord)
	}

	l.candidateRetirements[candidate.ReservationNonce] = &candidateRetirementRecord{candidate: candidate}
	l.candidateGeneration = candidate.TunnelGeneration

	return nil
}

// bindingMatches: the authority and reservation are bound by the first accepted preparation or
// revocation, and never change afterwards.
func (r *candidateRetirementRecord) bindingMatches(authorityID, reservationID string) bool {
	if r == nil {
		return false
	}

	if r.authorityID == "" && r.reservationID == "" {
		return true
	}

	return r.authorityID == authorityID && r.reservationID == reservationID
}

func (r *candidateRetirementRecord) bind(authorityID, reservationID string) {
	r.authorityID = authorityID
	r.reservationID = reservationID
}

// currentGenerationLocked reads the backend's generation and remembers one that contradicts the
// slot's candidate-bearing generation, so that a later unreadable (faulted) tunnel cannot turn the
// contradiction into retirement proof. The caller must hold l.mu.
func (l *LabLifecycle) currentGenerationLocked(namespace string) (string, error) {
	if l.generationProbes == nil {
		return "", errLabUnavailable
	}

	current, err := l.generationProbes.CurrentTunnelGeneration(namespace)
	if err == nil && l.candidateGeneration != "" && current != l.candidateGeneration {
		l.candidateGenerationContradicted = true
	}

	return current, err
}

// The caller must hold l.mu.
func (l *LabLifecycle) markCandidateGenerationRetiredLocked(lab LabInfo, generation string) {
	for _, record := range l.candidateRetirements {
		c := record.candidate

		if c.ProfileID == lab.ProfileID && c.Namespace == lab.Namespace && c.TunnelGeneration == generation {
			record.retired = true
		}
	}
}

// RevokedLeaseInfo confirms the retirement of exactly one candidate-bearing managed tunnel
// generation, within the helper backend's cleanup contract. It says nothing about other traffic in
// the runtime, and carries no deadline: a retired generation never becomes active again.
type RevokedLeaseInfo struct {
	Intent helperauth.Intent `json:"intent"`

	HelperID          string `json:"helper_id"`
	PublicKeySHA256   string `json:"public_key_sha256"`
	RevocationNonce   string `json:"revocation_nonce"`
	GenerationRetired bool   `json:"generation_retired"`

	// RecoverRetiredGenerationV1 only: the kernel boots of the original and the recovering epoch.
	OriginalBootID string `json:"original_boot_id,omitempty"`
	CurrentBootID  string `json:"current_boot_id,omitempty"`
}

func (r *RevokedLeaseInfo) valid() bool {
	if r == nil ||
		!r.GenerationRetired ||
		!helperauth.ValidRetirementIntent(r.Intent) ||
		!helperauth.ValidCapabilityNonce(r.RevocationNonce) ||
		r.RevocationNonce == r.Intent.EvidenceNonce ||
		r.RevocationNonce == r.Intent.ReservationNonce {
		return false
	}

	identity := HelperInfo{
		AuthorizationConfigured: true,
		HelperID:                r.HelperID,
		PublicKeySHA256:         r.PublicKeySHA256,
		RuntimeID:               r.Intent.RuntimeID,
	}

	return identity.valid() && r.validRecoveryBoundary()
}

// matchesCapability binds the receipt to the request structurally; the helper verified the
// signature.
func (r *RevokedLeaseInfo) matchesCapability(intent *helperauth.Intent, capability *helperauth.SignedCapability) bool {
	if !r.valid() || intent == nil || capability == nil {
		return false
	}

	claims := capability.Claims

	return r.Intent == *intent &&
		claims.Intent == r.Intent &&
		claims.Version == helperauth.Version &&
		claims.HelperID == r.HelperID &&
		claims.Nonce == r.RevocationNonce
}

// revokeEgressLease retires the managed tunnel generation of one candidate, prepared or not,
// expired or not, under the lifecycle lock. It never needs fresh evidence. An already retired
// generation is confirmed without touching the tunnel slot, which may hold a newer generation. A
// failed cleanup yields no proof; a lost receipt can be confirmed again with a new signed request.
func (l *LabLifecycle) revokeEgressLease(
	ctx context.Context,
	req Request,
	v *helperauth.Verifier,
	runtimeID string,
) (RevokedLeaseInfo, error) {
	if req.Version != Version || req.Operation != helperauth.OpRevokeEgressLease || req.Intent == nil ||
		!helperauth.ValidRevokeEgressLeaseIntent(*req.Intent) {
		return RevokedLeaseInfo{}, errLabInvalid
	}

	if l == nil || l.backend == nil || l.tunnels == nil || l.generationProbes == nil {
		return RevokedLeaseInfo{}, errLabUnavailable
	}

	if v == nil || req.Capability == nil {
		return RevokedLeaseInfo{}, errLabAuthorization
	}

	if !l.mu.TryLock() {
		return RevokedLeaseInfo{}, errLabBusy
	}

	// Logged off the lock and off the response path: stalled log output must hold up neither the
	// lifecycle nor a confirmed receipt.
	var labFault error
	var faultedNamespace string

	logf := l.logf
	if logf == nil {
		logf = log.Printf
	}

	defer func() {
		l.mu.Unlock()

		if labFault != nil {
			go logf("egress lease revocation: generation retired, lab %s faulted: %v", faultedNamespace, labFault)
		}
	}()

	// blockCreation does not apply: this removes resources, for exactly their owner.
	if l.closed || ctx.Err() != nil {
		return RevokedLeaseInfo{}, errLabUnavailable
	}

	requested := *req.Intent

	// A helper restart loses the records; a missing one never implies retirement.
	record := l.candidateRetirements[requested.ReservationNonce]
	if record == nil {
		return RevokedLeaseInfo{}, errLabAuthorization
	}

	candidate := record.candidate
	helperID, fingerprint := v.Identity()

	if candidate.RuntimeID != runtimeID || candidate.HelperID != helperID || candidate.PublicKeySHA256 != fingerprint ||
		!record.bindingMatches(requested.AuthorityID, requested.ReservationID) {
		return RevokedLeaseInfo{}, errLabAuthorization
	}

	// Every network-related field comes from the helper's own candidate.
	binding, err := prepareLeaseIntent(candidate, requested.AuthorityID, requested.ReservationID)
	if err != nil {
		return RevokedLeaseInfo{}, errLabAuthorization
	}

	expected, err := helperauth.NewRevokeEgressLeaseIntent(binding)
	if err != nil || requested != expected {
		return RevokedLeaseInfo{}, errLabAuthorization
	}

	nonce := req.Capability.Claims.Nonce
	if nonce == candidate.EvidenceNonce || nonce == candidate.ReservationNonce || nonce == record.preparationNonce {
		return RevokedLeaseInfo{}, errLabAuthorization
	}

	var lab LabInfo

	if !record.retired {
		var exists bool

		lab, exists = l.labs[candidate.ProfileID]
		if !exists || lab.Namespace != candidate.Namespace || l.tunnelProfile != candidate.ProfileID ||
			l.candidateGeneration != candidate.TunnelGeneration {
			return RevokedLeaseInfo{}, errLabUncertain
		}

		switch lab.State {
		case LabTunnelConfigured, LabFaulted:
		default:
			return RevokedLeaseInfo{}, errLabUncertain
		}

		// The helper tracks this generation, so a backend naming another one, now or earlier, is a
		// contradiction no cleanup can turn into proof.
		_, err := l.currentGenerationLocked(lab.Namespace)
		if l.candidateGenerationContradicted {
			return RevokedLeaseInfo{}, fmt.Errorf("%w: backend reported another tunnel generation", errLabUncertain)
		}

		if err != nil && lab.State == LabTunnelConfigured {
			return RevokedLeaseInfo{}, errLabUncertain
		}
	}

	if ctx.Err() != nil {
		return RevokedLeaseInfo{}, errLabUnavailable
	}

	// Signed even when the generation is already retired.
	if err := v.VerifyAndConsume(*req.Capability, expected); err != nil {
		return RevokedLeaseInfo{}, fmt.Errorf("%w: %w", errLabAuthorization, err)
	}

	record.bind(expected.AuthorityID, expected.ReservationID)

	// The receipt rests on the confirmed retirement alone: a sealed lab failing its check afterwards,
	// or the operation running out of time there, leaves the lab faulted but does not withhold it.
	if !record.retired {
		if _, err := l.disconnectTunnelLocked(ctx, lab); err != nil {
			if !record.retired {
				return RevokedLeaseInfo{}, fmt.Errorf("%w: revoke managed generation: %w", errLabUncertain, err)
			}

			labFault, faultedNamespace = err, lab.Namespace
		}
	}

	if !record.retired {
		return RevokedLeaseInfo{}, errLabUncertain
	}

	result := RevokedLeaseInfo{
		Intent:            expected,
		HelperID:          helperID,
		PublicKeySHA256:   fingerprint,
		RevocationNonce:   nonce,
		GenerationRetired: true,
	}

	if !result.matchesCapability(&expected, req.Capability) {
		return RevokedLeaseInfo{}, errLabUncertain
	}

	return result, nil
}

func validRevokedLeaseResponse(req Request, resp Response) bool {
	if (req.Operation != helperauth.OpRevokeEgressLease && req.Operation != helperauth.OpRecoverRetiredGeneration) ||
		!resp.OK {
		return resp.RevokedLease == nil
	}

	return !resp.NetworkReady &&
		req.Intent != nil &&
		req.Intent.Operation == req.Operation &&
		resp.RevokedLease.matchesCapability(req.Intent, req.Capability)
}

// RevokeEgressLease submits one signed revocation, or reboot-bound recovery, for the lab and durable
// reservation it names. It releases no durable reservation.
func RevokeEgressLease(
	ctx context.Context,
	socketPath, profileID, namespace string,
	capability helperauth.SignedCapability,
) (Response, error) {
	signed := capability.Claims.Intent

	if !helperauth.ValidRetirementIntent(signed) || signed.ProfileID != profileID || signed.Namespace != namespace {
		return Response{}, &Error{Code: CodeInvalidRequest, Message: "invalid lease revocation capability"}
	}

	return callRequest(ctx, socketPath, Request{
		Version:    Version,
		Operation:  signed.Operation,
		Intent:     &signed,
		Capability: &capability,
	})
}
