package control

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"time"
)

var (
	ErrLeaseRevocationUnconfirmed    = errors.New("managed generation retirement unconfirmed")
	ErrReservationReleaseUnconfirmed = errors.New("generation retired; durable release unconfirmed")
)

// The helper may have retired the generation, and the journal may or may not hold the reservation:
// only the helper's record, which a restart loses, lets a new release confirm it.
const releaseRecoveryAdvice = "check list-reservations; if the reservation is still listed, keep the helper " +
	"running (a restart loses its retirement record) and confirm with a newly approved release-egress"

const rebootRecoveryAdvice = "check list-reservations; recovery requires the original epoch witness and a " +
	"confirmed guest kernel reboot"

// LeaseRevocationTransport is all a release needs from the runtime: no probe, candidate or tunnel.
type LeaseRevocationTransport interface {
	HelperInfo(ctx context.Context) (LabHelperInfo, error)
	RevokeEgressLease(ctx context.Context, profileID, namespace string, capability LabCapability) (
		LabRevokedLeaseInfo, error)
}

// ReleasedEgressResult is the released hold and the retirement that backs it. It authorizes nothing.
type ReleasedEgressResult struct {
	Reservation  EgressReservation   `json:"reservation"`
	RevokedLease LabRevokedLeaseInfo `json:"revoked_lease"`
	ReleasedAt   time.Time           `json:"released_at"`
}

func ValidReservationID(id string) bool { return reservationIDPattern.MatchString(id) }

// Lookup returns a hold the authority currently holds; a released reservation is not one.
func (a *ReservationAuthority) Lookup(reservationID string) (EgressReservation, error) {
	if !ValidReservationID(reservationID) {
		return EgressReservation{}, ErrReservationReleaseInvalid
	}

	items, err := a.List()
	if err != nil {
		return EgressReservation{}, err
	}

	for _, hold := range items {
		if hold.ID == reservationID {
			return hold, nil
		}
	}

	return EgressReservation{}, ErrReservationNotFound
}

// releaseRuntimeMatchesHold: the runtime ID names the trusted Linux runtime, which outlives helper
// restarts, so it is necessary but not sufficient.
func releaseRuntimeMatchesHold(authority ReservationAuthorityInfo, hold EgressReservation, rt TrustedRuntime,
	now time.Time) bool {
	return authority.valid() &&
		validateStoredReservation(hold) &&
		rt.ID == hold.Owner.RuntimeID &&
		rt.PublicKeySHA256 == hold.PublicKeySHA256 &&
		authority.PublicKeySHA256 == hold.PublicKeySHA256 &&
		validRuntimeTarget(rt.Provider, rt.Target) &&
		!rt.TrustedAt.IsZero() &&
		!rt.TrustedAt.After(now)
}

// releaseHelperMatchesHold requires the very helper process that held the generation: a restarted
// helper cannot attest the retirement of its predecessor's tunnel.
func releaseHelperMatchesHold(hold EgressReservation, helper LabHelperInfo) bool {
	return helper.Valid() &&
		helper.AuthorizationConfigured &&
		helper.RuntimeID == hold.Owner.RuntimeID &&
		helper.HelperID == hold.Owner.HelperEpoch &&
		helper.PublicKeySHA256 == hold.PublicKeySHA256
}

// ReleaseEgress revokes the exact tunnel generation of one durable hold and commits its release. The
// caller supplies the trusted runtime and the transport of the same provider.
func (a *ReservationAuthority) ReleaseEgress(ctx context.Context, reservationID string,
	transport LeaseRevocationTransport, signer LabSigner, rt TrustedRuntime) (ReleasedEgressResult, error) {
	return a.releaseEgressAt(ctx, reservationID, transport, signer, rt, time.Now)
}

// RecoverEgress releases a hold whose original helper epoch is gone: a later epoch of the same
// runtime and key attests, from its boot-bound witnesses, that a kernel reboot ended the original
// generation. It is never a fallback for a failed release.
func (a *ReservationAuthority) RecoverEgress(ctx context.Context, reservationID string,
	transport LeaseRevocationTransport, signer LabSigner, rt TrustedRuntime) (ReleasedEgressResult, error) {
	return a.retireEgressAt(ctx, reservationID, transport, signer, rt, time.Now, true)
}

func (a *ReservationAuthority) releaseEgressAt(ctx context.Context, reservationID string,
	transport LeaseRevocationTransport, signer LabSigner, rt TrustedRuntime, now func() time.Time) (
	ReleasedEgressResult, error) {
	return a.retireEgressAt(ctx, reservationID, transport, signer, rt, now, false)
}

// retireEgressAt never holds the journal lock across the runtime call. Every failure before the
// receipt keeps the hold untouched; a lost receipt or a busy journal after the retirement keeps it
// too, and a newly approved command confirms the retirement with a fresh capability. Nothing is
// retried, forced or replaced by an unsigned disconnect.
func (a *ReservationAuthority) retireEgressAt(ctx context.Context, reservationID string,
	transport LeaseRevocationTransport, signer LabSigner, rt TrustedRuntime, now func() time.Time,
	recovering bool) (ReleasedEgressResult, error) {
	advice := releaseRecoveryAdvice
	if recovering {
		advice = rebootRecoveryAdvice
	}

	if ctx == nil || transport == nil || signer == nil || now == nil {
		return ReleasedEgressResult{}, ErrReservationUnavailable
	}

	if err := ctx.Err(); err != nil {
		return ReleasedEgressResult{}, err
	}

	journal, err := a.journal()
	if err != nil {
		return ReleasedEgressResult{}, err
	}

	// Phase 1: the exact durable hold, and the runtime that holds it.
	hold, err := a.Lookup(reservationID)
	if err != nil {
		return ReleasedEgressResult{}, err
	}

	startedAt := now()

	if !releaseRuntimeMatchesHold(a.info, hold, rt, startedAt) {
		return ReleasedEgressResult{}, fmt.Errorf("%w: the original trusted runtime is required", ErrReservationReleaseInvalid)
	}

	public, err := signer.PublicKey()
	if err != nil {
		return ReleasedEgressResult{}, err
	}

	if len(public) != ed25519.PublicKeySize || LabPublicKeySHA256(public) != hold.PublicKeySHA256 {
		return ReleasedEgressResult{}, ErrReservationAuthorityMismatch
	}

	if err := ctx.Err(); err != nil {
		return ReleasedEgressResult{}, err
	}

	// Phase 2: the original helper epoch, or for a recovery a later one of the same runtime and key.
	helper, err := transport.HelperInfo(ctx)
	if err != nil {
		return ReleasedEgressResult{}, err
	}

	if recovering {
		if !helper.Valid() || !helper.AuthorizationConfigured || helper.RuntimeID != hold.Owner.RuntimeID ||
			helper.PublicKeySHA256 != hold.PublicKeySHA256 || helper.HelperID == hold.Owner.HelperEpoch {
			return ReleasedEgressResult{}, fmt.Errorf(
				"%w: recovery requires a later helper epoch of the original runtime; the original epoch uses release-egress",
				ErrReservationReleaseInvalid)
		}
	} else if !releaseHelperMatchesHold(hold, helper) {
		return ReleasedEgressResult{}, fmt.Errorf("%w: the original helper epoch is required", ErrReservationReleaseInvalid)
	}

	intent, err := revokeIntentFromHold(a.info, hold)
	if err != nil {
		return ReleasedEgressResult{}, err
	}

	if recovering {
		if intent, err = NewLabRecoverRetiredGenerationIntent(intent, hold.Owner.HelperEpoch); err != nil {
			return ReleasedEgressResult{}, err
		}
	}

	// Phase 3: one new signed revocation.
	mintedAt := now()

	if !stableReservationClock(startedAt, mintedAt) || mintedAt.Round(0).Before(hold.ReservedAt.Round(0)) {
		return ReleasedEgressResult{}, ErrReservationReleaseInvalid
	}

	if err := ctx.Err(); err != nil {
		return ReleasedEgressResult{}, err
	}

	capability, err := mintLabCapability(signer, intent, helper, mintedAt)
	if err != nil {
		return ReleasedEgressResult{}, err
	}

	sentAt := now()

	if !reservationCapabilitySendValid(capability, mintedAt, sentAt) || !verifyIssuedLabCapability(public, capability) ||
		capability.Claims.Nonce == hold.EvidenceNonce || capability.Claims.Nonce == hold.ReservationNonce {
		return ReleasedEgressResult{}, ErrReservationReleaseInvalid
	}

	if err := ctx.Err(); err != nil {
		return ReleasedEgressResult{}, err
	}

	// Phase 4: the helper retires the exact generation.
	receipt, err := transport.RevokeEgressLease(ctx, hold.Owner.ProfileID, hold.Owner.Namespace, capability)
	receivedAt := now()

	if err != nil {
		return ReleasedEgressResult{}, fmt.Errorf("%w: reservation %s: %s: %w", ErrLeaseRevocationUnconfirmed, hold.ID,
			advice, err)
	}

	admission := releaseAdmission{
		hold:       hold,
		runtime:    rt,
		helper:     helper,
		publicKey:  public,
		capability: capability,
		receipt:    receipt,
		mintedAt:   mintedAt,
		sentAt:     sentAt,
		receivedAt: receivedAt,
	}

	// The runtime's answer, checked before the storage transaction; the transaction checks it again
	// against the hold it reloads under the lock.
	if err := validateReleaseAdmission(a.info, admission, receivedAt); err != nil {
		return ReleasedEgressResult{}, fmt.Errorf("%w: reservation %s: %s: %w", ErrLeaseRevocationUnconfirmed, hold.ID,
			advice, err)
	}

	// Phase 5: the durable release.
	record, err := releaseDurableEgressJournal(ctx, journal, admission, now)
	if err != nil {
		return ReleasedEgressResult{}, fmt.Errorf("%w: reservation %s: %s: %w", ErrReservationReleaseUnconfirmed, hold.ID,
			advice, err)
	}

	return ReleasedEgressResult{Reservation: hold, RevokedLease: record.Receipt, ReleasedAt: record.ReleasedAt}, nil
}
