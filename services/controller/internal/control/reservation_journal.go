package control

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"time"
)

const (
	reservationJournalFile  = "egress-reservations.journal"
	reservationJournalMagic = "egresslab-reservations/v1\n"

	maxReservationRecordBytes  = 8 * 1024
	maxReservationJournalBytes = len(reservationJournalMagic) +
		maxEgressReservations*(4+maxReservationRecordBytes+sha256.Size)
)

var (
	ErrReservationBusy             = errors.New("egress reservation authority is busy")
	ErrReservationJournalCorrupt   = errors.New("egress reservation journal is corrupt")
	ErrReservationStateUncertain   = errors.New("egress reservation persistence outcome is uncertain")
	ErrReservationCommittedExpired = errors.New("reservation committed but eligibility expired")

	reservationIDPattern = regexp.MustCompile(`^reservation_[0-9a-f]{32}$`)
)

// The journal is the header followed by frames of
//
//	length (uint32, big-endian) | canonical JSON payload | SHA-256(previous digest | length | payload)
//
// chained from SHA-256(header). The chain detects damaged, reordered and torn records; it is not a
// signature, and it cannot detect a rollback to an earlier complete prefix.

func reservationJournalPath(dataDir string) (string, error) {
	if dataDir == "" || !filepath.IsAbs(dataDir) {
		return "", ErrReservationUnavailable
	}

	dir := filepath.Clean(dataDir)

	info, err := os.Stat(dir)
	if err != nil {
		return "", errors.Join(ErrReservationUnavailable, err)
	}

	if !info.IsDir() {
		return "", ErrReservationUnavailable
	}

	return filepath.Join(dir, reservationJournalFile), nil
}

// openLockedReservationJournal returns the journal holding its exclusive OS lock, or ErrReservationBusy
// (wrapped) at once if another handle holds it. flock on Unix is advisory: it binds only processes
// that follow this protocol.
func openLockedReservationJournal(path string, create bool) (*os.File, error) {
	file, err := openReservationFile(path, create)
	if err != nil {
		return nil, errors.Join(ErrReservationUnavailable, err)
	}

	success := false
	defer func() {
		if !success {
			file.Close()
		}
	}()

	info, err := file.Stat()
	if err != nil {
		return nil, errors.Join(ErrReservationUnavailable, err)
	}

	if !info.Mode().IsRegular() {
		return nil, ErrReservationUnavailable
	}

	if err := lockReservationFile(file); err != nil {
		return nil, errors.Join(ErrReservationUnavailable, err)
	}

	// The pathname must still name the file we locked.
	named, err := os.Lstat(path)
	if err != nil {
		return nil, errors.Join(ErrReservationUnavailable, err)
	}

	if !named.Mode().IsRegular() || !os.SameFile(info, named) {
		return nil, ErrReservationUnavailable
	}

	success = true

	return file, nil
}

// initializeReservationJournal provisions a new authority explicitly. It is never a fallback for a
// failed open: a missing journal is no proof that nothing was ever reserved. Tests only for now.
func initializeReservationJournal(dataDir string) (resultErr error) {
	path, err := reservationJournalPath(dataDir)
	if err != nil {
		return err
	}

	file, err := openLockedReservationJournal(path, true)
	if err != nil {
		return err
	}

	defer func() {
		if err := file.Close(); err != nil {
			resultErr = errors.Join(resultErr, ErrReservationStateUncertain, err)
		}
	}()

	header := []byte(reservationJournalMagic)

	n, err := file.Write(header)
	if err == nil && n != len(header) {
		err = io.ErrShortWrite
	}

	if err != nil {
		return errors.Join(ErrReservationStateUncertain, err)
	}

	if err := file.Sync(); err != nil {
		return errors.Join(ErrReservationStateUncertain, err)
	}

	if err := syncReservationDirectory(filepath.Dir(path)); err != nil {
		return errors.Join(ErrReservationStateUncertain, err)
	}

	return nil
}

// normalizeReservationRecord drops monotonic readings and gives stored timestamps one encoding.
func normalizeReservationRecord(r EgressReservation) EgressReservation {
	r.ObservedAt = r.ObservedAt.UTC()
	r.CandidateExpiresAt = r.CandidateExpiresAt.UTC()
	r.ReservedAt = r.ReservedAt.UTC()
	r.EligibleUntil = r.EligibleUntil.UTC()
	r.recovered = false

	return r
}

// validateStoredReservation checks structure, not freshness: an expired record is still a hold.
func validateStoredReservation(r EgressReservation) bool {
	return reservationIDPattern.MatchString(r.ID) &&
		r.Owner.Valid() &&
		validLabPublicIPv4(r.IPv4) &&
		ValidLabMultiProbePin(r.IdentIPv4) &&
		labFingerprintPattern.MatchString(r.PublicKeySHA256) &&
		labProbeNoncePattern.MatchString(r.EvidenceNonce) &&
		labProbeNoncePattern.MatchString(r.ReservationNonce) &&
		r.EvidenceNonce != r.ReservationNonce &&
		r.ObservedAt.Unix() > 0 &&
		r.ReservedAt.Unix() > 0 &&
		r.CandidateExpiresAt.After(r.ObservedAt) &&
		r.CandidateExpiresAt.Sub(r.ObservedAt) <= labGenerationProbeFreshness &&
		r.EligibleUntil.After(r.ReservedAt) &&
		!r.EligibleUntil.After(r.CandidateExpiresAt.Add(-labProbeClockSkew))
}

func reservationFrameDigest(previous [sha256.Size]byte, body []byte) [sha256.Size]byte {
	hash := sha256.New()
	hash.Write(previous[:])
	hash.Write(body)

	var digest [sha256.Size]byte
	copy(digest[:], hash.Sum(nil))

	return digest
}

func encodeReservationFrame(reservation EgressReservation, previous [sha256.Size]byte) ([]byte, error) {
	reservation = normalizeReservationRecord(reservation)
	if !validateStoredReservation(reservation) {
		return nil, ErrReservationCandidateInvalid
	}

	payload, err := json.Marshal(reservation)
	if err != nil {
		return nil, err
	}

	if len(payload) == 0 || len(payload) > maxReservationRecordBytes {
		return nil, ErrReservationUnavailable
	}

	bodyEnd := 4 + len(payload)
	frame := make([]byte, bodyEnd+sha256.Size)
	binary.BigEndian.PutUint32(frame[:4], uint32(len(payload)))
	copy(frame[4:], payload)

	digest := reservationFrameDigest(previous, frame[:bodyEnd])
	copy(frame[bodyEnd:], digest[:])

	return frame, nil
}

// decodeReservationPayload accepts exactly the bytes the writer produces. DisallowUnknownFields
// alone would take the last of duplicated keys; the canonical re-encoding refuses them, and any
// other hand edit.
func decodeReservationPayload(payload []byte) (EgressReservation, error) {
	var reservation EgressReservation

	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()

	if err := decoder.Decode(&reservation); err != nil {
		return EgressReservation{}, ErrReservationJournalCorrupt
	}

	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return EgressReservation{}, ErrReservationJournalCorrupt
	}

	if !validateStoredReservation(reservation) {
		return EgressReservation{}, ErrReservationJournalCorrupt
	}

	canonical, err := json.Marshal(normalizeReservationRecord(reservation))
	if err != nil || !bytes.Equal(canonical, payload) {
		return EgressReservation{}, ErrReservationJournalCorrupt
	}

	reservation.recovered = true

	return reservation, nil
}

type reservationJournalState struct {
	registry *egressReservationRegistry

	tail   [sha256.Size]byte
	length int64
}

// restoreJournalHold fills a registry not yet visible to other goroutines; the caller holds the
// journal's OS lock. It bypasses reserve on purpose: a stored hold stays a hold after its evidence
// expired or its helper is gone.
func restoreJournalHold(registry *egressReservationRegistry, reservation EgressReservation) error {
	if !validateStoredReservation(reservation) || len(registry.byOwner) >= maxEgressReservations {
		return ErrReservationJournalCorrupt
	}

	owner := reservation.Owner

	if _, exists := registry.byOwner[owner]; exists {
		return ErrReservationJournalCorrupt
	}

	if _, exists := registry.byIP[reservation.IPv4]; exists {
		return ErrReservationJournalCorrupt
	}

	if _, exists := registry.byProfile[owner.ProfileID]; exists {
		return ErrReservationJournalCorrupt
	}

	if _, exists := registry.byID[reservation.ID]; exists {
		return ErrReservationJournalCorrupt
	}

	reservation.recovered = true

	registry.byOwner[owner] = reservation
	registry.byIP[reservation.IPv4] = owner
	registry.byProfile[owner.ProfileID] = owner
	registry.byID[reservation.ID] = owner

	return nil
}

// parseReservationJournal validates the whole journal before returning anything: a damaged record
// 15 never yields the first 14 as a usable registry.
func parseReservationJournal(data []byte) (reservationJournalState, error) {
	header := []byte(reservationJournalMagic)

	if len(data) > maxReservationJournalBytes || !bytes.HasPrefix(data, header) {
		return reservationJournalState{}, ErrReservationJournalCorrupt
	}

	state := reservationJournalState{
		registry: newEgressReservationRegistry(),
		tail:     sha256.Sum256(header),
		length:   int64(len(data)),
	}

	remaining := data[len(header):]

	for len(remaining) != 0 {
		corrupt := fmt.Errorf("%w at byte %d", ErrReservationJournalCorrupt, len(data)-len(remaining))

		if len(remaining) < 4+sha256.Size {
			return reservationJournalState{}, corrupt
		}

		size := binary.BigEndian.Uint32(remaining[:4])
		if size == 0 || size > maxReservationRecordBytes {
			return reservationJournalState{}, corrupt
		}

		bodyEnd := 4 + int(size)
		frameEnd := bodyEnd + sha256.Size

		if len(remaining) < frameEnd {
			return reservationJournalState{}, corrupt
		}

		digest := reservationFrameDigest(state.tail, remaining[:bodyEnd])
		if !bytes.Equal(digest[:], remaining[bodyEnd:frameEnd]) {
			return reservationJournalState{}, corrupt
		}

		reservation, err := decodeReservationPayload(remaining[4:bodyEnd])
		if err != nil {
			return reservationJournalState{}, errors.Join(corrupt, err)
		}

		if err := restoreJournalHold(state.registry, reservation); err != nil {
			return reservationJournalState{}, errors.Join(corrupt, err)
		}

		state.tail = digest
		remaining = remaining[frameEnd:]
	}

	return state, nil
}

// readReservationJournal reads through the locked handle.
func readReservationJournal(file *os.File) (reservationJournalState, error) {
	info, err := file.Stat()
	if err != nil {
		return reservationJournalState{}, errors.Join(ErrReservationUnavailable, err)
	}

	if info.Size() < int64(len(reservationJournalMagic)) || info.Size() > int64(maxReservationJournalBytes) {
		return reservationJournalState{}, ErrReservationJournalCorrupt
	}

	// A writer that died before its own Sync can leave a complete frame in the cache only; flush it
	// first, so everything read below is durable.
	if err := file.Sync(); err != nil {
		return reservationJournalState{}, errors.Join(ErrReservationUnavailable, err)
	}

	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return reservationJournalState{}, errors.Join(ErrReservationUnavailable, err)
	}

	data, err := io.ReadAll(io.LimitReader(file, int64(maxReservationJournalBytes)+1))
	if err != nil {
		return reservationJournalState{}, errors.Join(ErrReservationUnavailable, err)
	}

	if int64(len(data)) != info.Size() {
		return reservationJournalState{}, ErrReservationJournalCorrupt
	}

	return parseReservationJournal(data)
}

// appendReservationHold appends one complete frame and flushes it before reporting success. Once
// the write starts, a failure is uncertain: never truncate or try to roll back.
func appendReservationHold(file *os.File, state reservationJournalState, reservation EgressReservation) error {
	frame, err := encodeReservationFrame(reservation, state.tail)
	if err != nil {
		return err
	}

	if state.length+int64(len(frame)) > int64(maxReservationJournalBytes) {
		return ErrReservationLimit
	}

	end, err := file.Seek(0, io.SeekEnd)
	if err != nil {
		return errors.Join(ErrReservationUnavailable, err)
	}

	if end != state.length {
		return ErrReservationJournalCorrupt
	}

	n, err := file.Write(frame)
	if err == nil && n != len(frame) {
		err = io.ErrShortWrite
	}

	if err != nil {
		return errors.Join(ErrReservationStateUncertain, err)
	}

	if err := file.Sync(); err != nil {
		return errors.Join(ErrReservationStateUncertain, err)
	}

	return nil
}

func reserveDurableEgress(dataDir string, admission candidateAdmission) (EgressReservation, error) {
	return reserveDurableEgressAt(dataDir, admission, time.Now)
}

// reserveDurableEgressAt runs one transaction under the journal's OS lock: load and validate every
// stored hold, admit the candidate and check collisions (Step 31B), append and flush. It keeps no
// registry between calls. A failure does not prove that no hold exists: after an uncertain write
// the caller must inspect the journal, never retry with a new capability.
func reserveDurableEgressAt(dataDir string, admission candidateAdmission, now func() time.Time) (
	EgressReservation, error) {
	return reserveDurableEgressContext(context.Background(), dataDir, admission, now)
}

// reserveDurableEgressContext also refuses to append once ctx is done: before the write a
// cancellation leaves nothing durable; after it, the hold stays.
func reserveDurableEgressContext(ctx context.Context, dataDir string, admission candidateAdmission,
	now func() time.Time) (reservation EgressReservation, resultErr error) {
	if ctx == nil || now == nil {
		return EgressReservation{}, ErrReservationUnavailable
	}

	path, err := reservationJournalPath(dataDir)
	if err != nil {
		return EgressReservation{}, err
	}

	// Never create a missing journal here.
	file, err := openLockedReservationJournal(path, false)
	if err != nil {
		return EgressReservation{}, err
	}

	defer func() {
		if err := file.Close(); err != nil {
			reservation = EgressReservation{}
			resultErr = errors.Join(resultErr, ErrReservationStateUncertain, err)
		}
	}()

	state, err := readReservationJournal(file)
	if err != nil {
		return EgressReservation{}, err
	}

	// An interrupted initialization may not have flushed the journal's directory entry; a grant
	// must not rely on a name that a crash can still remove.
	if err := syncReservationDirectory(filepath.Dir(path)); err != nil {
		return EgressReservation{}, errors.Join(ErrReservationUnavailable, err)
	}

	state.registry.now = now

	hold, err := state.registry.reserve(admission)
	if err != nil {
		return EgressReservation{}, err
	}

	if !hold.FreshAt(now()) {
		return EgressReservation{}, ErrReservationCandidateExpired
	}

	if err := ctx.Err(); err != nil {
		return EgressReservation{}, err
	}

	if err := appendReservationHold(file, state, hold); err != nil {
		return EgressReservation{}, err
	}

	// Expired during the flush: the address stays durably held, but there is no usable grant.
	if !hold.FreshAt(now()) {
		return EgressReservation{}, ErrReservationCommittedExpired
	}

	return hold, nil
}

// inspectReservationJournal takes the same exclusive lock, so it never reads a half-written frame.
// A damaged journal is an error, never an empty list.
func inspectReservationJournal(dataDir string) (items []EgressReservation, resultErr error) {
	path, err := reservationJournalPath(dataDir)
	if err != nil {
		return nil, err
	}

	file, err := openLockedReservationJournal(path, false)
	if err != nil {
		return nil, err
	}

	defer func() {
		if err := file.Close(); err != nil {
			items = nil
			resultErr = errors.Join(resultErr, ErrReservationUnavailable, err)
		}
	}()

	state, err := readReservationJournal(file)
	if err != nil {
		return nil, err
	}

	return state.registry.snapshot(), nil
}

func lookupDurableReservationByIP(dataDir string, ip netip.Addr) (EgressReservation, bool, error) {
	if !validLabPublicIPv4(ip) {
		return EgressReservation{}, false, ErrReservationCandidateInvalid
	}

	items, err := inspectReservationJournal(dataDir)
	if err != nil {
		return EgressReservation{}, false, err
	}

	for _, reservation := range items {
		if reservation.IPv4 == ip {
			return reservation, true, nil
		}
	}

	return EgressReservation{}, false, nil
}
