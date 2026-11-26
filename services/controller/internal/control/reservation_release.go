package control

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"time"
)

const reservationReleaseType = "release"

// releaseAdmission is assembled only by the trusted controller revocation workflow, from the
// trusted runtime's transport. It is never decoded from external JSON: the controller's signature
// authorizes the request, it does not authenticate the helper's receipt.
type releaseAdmission struct {
	hold EgressReservation

	runtime TrustedRuntime
	helper  LabHelperInfo

	publicKey ed25519.PublicKey

	capability LabCapability
	receipt    LabRevokedLeaseInfo

	mintedAt   time.Time
	sentAt     time.Time
	receivedAt time.Time
}

// validateReleaseAdmission requires the receipt for exactly this hold, from the helper epoch that
// held it (or, for a reboot-bound recovery, a later one), the runtime and key that held it,
// answering a capability this controller signed and submitted while it was valid. The cleanup may
// outlast the capability: its lifetime is checked at submission. Fresh probe evidence is not
// required.
func validateReleaseAdmission(authority ReservationAuthorityInfo, a releaseAdmission, now time.Time) error {
	hold := a.hold

	if !authority.valid() || !validateStoredReservation(hold) {
		return ErrReservationReleaseInvalid
	}

	if !a.helper.AuthorizationConfigured ||
		!a.helper.Valid() ||
		a.helper.RuntimeID != hold.Owner.RuntimeID ||
		a.runtime.ID != hold.Owner.RuntimeID ||
		a.helper.PublicKeySHA256 != hold.PublicKeySHA256 ||
		a.runtime.PublicKeySHA256 != hold.PublicKeySHA256 ||
		authority.PublicKeySHA256 != hold.PublicKeySHA256 ||
		!validRuntimeTarget(a.runtime.Provider, a.runtime.Target) ||
		a.runtime.TrustedAt.IsZero() ||
		a.runtime.TrustedAt.After(a.mintedAt) {
		return ErrReservationReleaseInvalid
	}

	if a.receipt.HelperID != a.helper.HelperID || a.capability.Claims.HelperID != a.helper.HelperID {
		return ErrReservationReleaseInvalid
	}

	// Only the original epoch attests a revocation; only a later one, from a later kernel boot, a
	// recovery.
	switch a.receipt.Intent.Operation {
	case LabRevokeEgressLeaseOp:
		if a.helper.HelperID != hold.Owner.HelperEpoch {
			return ErrReservationReleaseInvalid
		}

	case LabRecoverRetiredGenerationOp:
		if a.helper.HelperID == hold.Owner.HelperEpoch {
			return ErrReservationReleaseInvalid
		}

	default:
		return ErrReservationReleaseInvalid
	}

	if len(a.publicKey) != ed25519.PublicKeySize ||
		LabPublicKeySHA256(a.publicKey) != hold.PublicKeySHA256 ||
		!verifyIssuedLabCapability(a.publicKey, a.capability) {
		return ErrReservationReleaseInvalid
	}

	if !a.receipt.MatchesCapability(a.capability) || !a.receipt.matchesReservation(authority, hold) {
		return ErrReservationReleaseInvalid
	}

	if !reservationCapabilitySendValid(a.capability, a.mintedAt, a.sentAt) ||
		!stableReservationClock(a.sentAt, a.receivedAt) ||
		!stableReservationClock(a.mintedAt, a.receivedAt) ||
		!stableReservationClock(a.receivedAt, now) ||
		!stableReservationClock(a.sentAt, now) ||
		a.mintedAt.Round(0).Before(hold.ReservedAt.Round(0)) ||
		now.Round(0).Before(hold.ReservedAt.Round(0)) {
		return ErrReservationReleaseInvalid
	}

	return nil
}

// reservationReleaseRecord is the durable release: the retirement receipt and when it was
// committed. It holds no key and no reusable authorization.
type reservationReleaseRecord struct {
	Type       string              `json:"type"`
	Receipt    LabRevokedLeaseInfo `json:"receipt"`
	ReleasedAt time.Time           `json:"released_at"`
}

func normalizeReleaseRecord(record reservationReleaseRecord) reservationReleaseRecord {
	record.ReleasedAt = record.ReleasedAt.UTC()

	return record
}

func validReleaseRecord(record reservationReleaseRecord) bool {
	return record.Type == reservationReleaseType && record.Receipt.Valid() && record.ReleasedAt.Unix() > 0
}

func encodeReleaseFrame(record reservationReleaseRecord, previous [sha256.Size]byte) ([]byte, error) {
	record = normalizeReleaseRecord(record)
	if !validReleaseRecord(record) {
		return nil, ErrReservationReleaseInvalid
	}

	payload, err := json.Marshal(record)
	if err != nil {
		return nil, err
	}

	return encodeJournalPayload(payload, previous)
}

// decodeReleasePayload accepts exactly the bytes the writer produces: the canonical re-encoding
// refuses unknown, duplicated or differently cased keys and any other hand edit.
func decodeReleasePayload(payload []byte) (reservationReleaseRecord, error) {
	var record reservationReleaseRecord

	if err := json.Unmarshal(payload, &record); err != nil || !validReleaseRecord(record) {
		return reservationReleaseRecord{}, ErrReservationJournalCorrupt
	}

	canonical, err := json.Marshal(normalizeReleaseRecord(record))
	if err != nil || !bytes.Equal(canonical, payload) {
		return reservationReleaseRecord{}, ErrReservationJournalCorrupt
	}

	return record, nil
}

// releaseDurableEgressJournal commits one release of an exact current hold, under the journal's
// OS lock: reload and validate the journal, compare the hold, validate the retirement, apply the
// release to the private replayed state, append and flush. It never takes receipt JSON from
// outside, and holds no lock while the helper cleans up. After the write began, a failure is
// uncertain: the journal must be inspected, nothing is retried or rolled back.
func releaseDurableEgressJournal(ctx context.Context, journal reservationJournalSpec, admission releaseAdmission,
	now func() time.Time) (result reservationReleaseRecord, resultErr error) {
	if ctx == nil || now == nil || journal.authority == nil {
		return reservationReleaseRecord{}, ErrReservationUnavailable
	}

	if err := ctx.Err(); err != nil {
		return reservationReleaseRecord{}, err
	}

	handle, err := journal.open()
	if err != nil {
		return reservationReleaseRecord{}, err
	}

	defer func() {
		if err := handle.Close(); err != nil {
			result = reservationReleaseRecord{}
			resultErr = errors.Join(resultErr, ErrReservationStateUncertain, err)
		}
	}()

	state, err := journal.read(handle.File)
	if err != nil {
		return reservationReleaseRecord{}, err
	}

	current, exists := state.registry.lookupByID(admission.hold.ID)
	if !exists {
		return reservationReleaseRecord{}, ErrReservationNotFound
	}

	if normalizeReservationRecord(current) != normalizeReservationRecord(admission.hold) {
		return reservationReleaseRecord{}, ErrReservationReleaseInvalid
	}

	if err := syncReservationDirectory(journal.directory); err != nil {
		return reservationReleaseRecord{}, errors.Join(ErrReservationUnavailable, err)
	}

	releasedAt := now()

	if err := validateReleaseAdmission(*journal.authority, admission, releasedAt); err != nil {
		return reservationReleaseRecord{}, err
	}

	record := reservationReleaseRecord{
		Type:       reservationReleaseType,
		Receipt:    admission.receipt,
		ReleasedAt: releasedAt.UTC(),
	}

	// On the private replayed state only: nothing is visible to another process before the append.
	if err := state.applyRelease(record, journal.authority); err != nil {
		return reservationReleaseRecord{}, err
	}

	frame, err := encodeReleaseFrame(record, state.tail)
	if err != nil {
		return reservationReleaseRecord{}, err
	}

	if err := ctx.Err(); err != nil {
		return reservationReleaseRecord{}, err
	}

	if err := appendJournalFrame(handle.File, state, frame); err != nil {
		return reservationReleaseRecord{}, err
	}

	// Durable already: a cancellation cannot undo it.
	if err := ctx.Err(); err != nil {
		return reservationReleaseRecord{}, errors.Join(ErrReservationStateUncertain, err)
	}

	return record, nil
}
