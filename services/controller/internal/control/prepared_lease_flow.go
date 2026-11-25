package control

import (
	"context"
	"errors"
	"fmt"
	"time"
)

// labPreparationBudget is the eligibility a preparation must still have when it is signed and
// sent: the helper verifies the tunnel under the evidence deadline, and a deadline passing during
// that verification faults the lab. It comes on top of the 5 s clock-skew margin.
const labPreparationBudget = 5 * time.Second

var ErrLeasePreparationUnconfirmed = errors.New("durable reservation committed; lease preparation unconfirmed")

// LeasePreparationTransport extends ReservationTransport; labruntime.HelperTransport implements it.
type LeasePreparationTransport interface {
	ReservationTransport

	PrepareEgressLease(ctx context.Context, profileID, namespace string, capability LabCapability) (LabPreparedLeaseInfo, error)
}

// PreparedEgressResult reports one uninterrupted controller operation. It is not a reusable
// activation capability.
type PreparedEgressResult struct {
	Reservation   EgressReservation
	PreparedLease LabPreparedLeaseInfo
}

// preparationHoldValid requires the live hold of this operation: FreshAt refuses a recovered one.
// normalizeReservationRecord must not be used here; it strips the monotonic readings.
func preparationHoldValid(authority ReservationAuthorityInfo, hold EgressReservation, trust ReservationContext,
	now time.Time) bool {
	return authority.valid() &&
		trust.validAt(now) &&
		validateStoredReservation(hold) &&
		hold.FreshAt(now.Add(labPreparationBudget)) &&
		hold.PublicKeySHA256 == authority.PublicKeySHA256 &&
		hold.PublicKeySHA256 == trust.Runtime.PublicKeySHA256 &&
		hold.Owner.ProfileID == trust.Profile.ID &&
		hold.Owner.RuntimeID == trust.Runtime.ID &&
		hold.Owner.HelperEpoch == trust.Helper.HelperID &&
		hold.Owner.Namespace == trust.Binding.Namespace
}

// confirmPreparationHold requires the hold to be in this authority's journal. The stored record is
// only compared, never used as the source of an authorization.
func confirmPreparationHold(journal reservationJournalSpec, hold EgressReservation) error {
	if journal.authority == nil || hold.recovered {
		return ErrReservationCandidateInvalid
	}

	items, err := inspectReservationJournalSpec(journal)
	if err != nil {
		return err
	}

	for _, item := range items {
		if item.ID != hold.ID {
			continue
		}

		if normalizeReservationRecord(item) != normalizeReservationRecord(hold) {
			return ErrReservationAuthorityMismatch
		}

		return nil
	}

	return ErrReservationAuthorityMismatch
}

// mintPreparedLeaseAfterCommit is the signing gate: both the live hold of this operation and its
// matching durable record. It is unexported: nothing signs a preparation for a reservation ID taken
// from the CLI, the HTTP API or the journal. With no release yet, a cooperating controller cannot
// free the hold between this check and the submission; release (Steps 31D.3c and 31D.3d) must also
// revoke outstanding preparations.
func mintPreparedLeaseAfterCommit(journal reservationJournalSpec, hold EgressReservation, signer LabSigner,
	trust ReservationContext, now time.Time) (LabCapability, error) {
	if journal.authority == nil || signer == nil {
		return LabCapability{}, ErrReservationUnavailable
	}

	authority := *journal.authority

	if !preparationHoldValid(authority, hold, trust, now) {
		return LabCapability{}, ErrReservationCandidateInvalid
	}

	if err := confirmPreparationHold(journal, hold); err != nil {
		return LabCapability{}, err
	}

	intent, err := NewLabPrepareEgressLeaseIntent(hold.Owner.ProfileID, hold.Owner.Namespace, hold.IdentIPv4,
		hold.Owner.TunnelGeneration, hold.EvidenceNonce, hold.ReservationNonce, hold.Owner.RuntimeID, authority.ID,
		hold.ID, hold.IPv4.String())
	if err != nil {
		return LabCapability{}, err
	}

	capability, err := mintLabCapability(signer, intent, trust.Helper, now)
	if err != nil {
		return LabCapability{}, err
	}

	if capability.Claims.Nonce == hold.EvidenceNonce || capability.Claims.Nonce == hold.ReservationNonce {
		return LabCapability{}, ErrReservationCandidateInvalid
	}

	return capability, nil
}

// ReserveAndPrepareEgress runs verification, candidate consumption, the durable reservation and
// the signed lease preparation as one approved operation. Nothing is retried, released or
// activated.
func (a *ReservationAuthority) ReserveAndPrepareEgress(
	ctx context.Context,
	transport LeasePreparationTransport,
	signer LabSigner,
	trust ReservationContext,
) (PreparedEgressResult, error) {
	return a.reserveAndPrepareEgressAt(ctx, transport, signer, trust, time.Now)
}

func (a *ReservationAuthority) reserveAndPrepareEgressAt(
	ctx context.Context,
	transport LeasePreparationTransport,
	signer LabSigner,
	trust ReservationContext,
	now func() time.Time,
) (PreparedEgressResult, error) {
	if ctx == nil || transport == nil || signer == nil || now == nil {
		return PreparedEgressResult{}, ErrReservationUnavailable
	}

	journal, err := a.journal()
	if err != nil {
		return PreparedEgressResult{}, err
	}

	if trust.Runtime.PublicKeySHA256 != a.info.PublicKeySHA256 {
		return PreparedEgressResult{}, ErrReservationAuthorityMismatch
	}

	hold, err := reserveVerifiedEgressJournalAt(ctx, journal, transport, signer, trust, now)
	if err != nil {
		return PreparedEgressResult{}, err
	}

	// Everything below runs after the durable commit; no path releases the hold.
	receipt, err := prepareCommittedEgressLease(ctx, journal, hold, transport, signer, trust, now)
	if err != nil {
		return PreparedEgressResult{}, fmt.Errorf("%w: reservation %s: %w", ErrLeasePreparationUnconfirmed, hold.ID, err)
	}

	return PreparedEgressResult{Reservation: hold, PreparedLease: receipt}, nil
}

// prepareCommittedEgressLease signs and submits one preparation for the hold this operation just
// committed. An error here does not prove the helper made no prepared lease, only that the
// controller did not receive and verify it.
func prepareCommittedEgressLease(
	ctx context.Context,
	journal reservationJournalSpec,
	hold EgressReservation,
	transport LeasePreparationTransport,
	signer LabSigner,
	trust ReservationContext,
	now func() time.Time,
) (LabPreparedLeaseInfo, error) {
	if err := ctx.Err(); err != nil {
		return LabPreparedLeaseInfo{}, err
	}

	mintedAt := now()
	if !hold.FreshAt(mintedAt.Add(labPreparationBudget)) {
		return LabPreparedLeaseInfo{}, ErrReservationCandidateExpired
	}

	capability, err := mintPreparedLeaseAfterCommit(journal, hold, signer, trust, mintedAt)
	if err != nil {
		return LabPreparedLeaseInfo{}, err
	}

	// The key store and the journal inspection may have used up the remaining time.
	sentAt := now()
	if !reservationCapabilitySendValid(capability, mintedAt, sentAt) || !hold.FreshAt(sentAt.Add(labPreparationBudget)) {
		return LabPreparedLeaseInfo{}, ErrReservationCandidateExpired
	}

	if err := ctx.Err(); err != nil {
		return LabPreparedLeaseInfo{}, err
	}

	receipt, err := transport.PrepareEgressLease(ctx, hold.Owner.ProfileID, hold.Owner.Namespace, capability)
	receivedAt := now()

	if err != nil {
		return LabPreparedLeaseInfo{}, fmt.Errorf("prepare egress lease: %w", err)
	}

	if !receipt.MatchesCapability(capability) || !receipt.matchesReservation(*journal.authority, hold) {
		return LabPreparedLeaseInfo{}, ErrReservationCandidateInvalid
	}

	if !stableReservationClock(sentAt, receivedAt) || !hold.FreshAt(receivedAt) {
		return LabPreparedLeaseInfo{}, ErrReservationCandidateExpired
	}

	if err := ctx.Err(); err != nil {
		return LabPreparedLeaseInfo{}, err
	}

	return receipt, nil
}
