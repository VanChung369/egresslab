package control

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
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

	maxReservationRecordBytes = 8 * 1024
	maxReservationHeaderBytes = 128

	// Every reservation ever held keeps its identity, and may add one release frame: room for all
	// the releases is reserved, so a full history refuses new holds, never a release.
	maxHistoricalReservations   = 4096
	maxReservationJournalFrames = 2 * maxHistoricalReservations
	maxReservationJournalBytes  = maxReservationHeaderBytes +
		maxReservationJournalFrames*(4+maxReservationRecordBytes+sha256.Size)
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
func initializeReservationJournal(dataDir string) error {
	return initializeReservationJournalWithHeader(dataDir, reservationJournalMagic)
}

func initializeReservationJournalWithHeader(dataDir, headerText string) error {
	if len(headerText) == 0 || len(headerText) > maxReservationHeaderBytes {
		return ErrReservationUnavailable
	}

	path, err := reservationJournalPath(dataDir)
	if err != nil {
		return err
	}

	return publishReservationFile(filepath.Dir(path), reservationJournalFile, []byte(headerText))
}

// publishReservationFile writes data to a private temporary file, flushes it and links it into place
// exclusively. The published name never shows an empty or partial file: if it did, a reader could
// lock it first, the creator would fail, and the leftover would block the authority for good.
func publishReservationFile(dir, name string, data []byte) error {
	var suffix [8]byte
	if _, err := rand.Read(suffix[:]); err != nil {
		return errors.Join(ErrReservationUnavailable, err)
	}

	tmp := filepath.Join(dir, "."+name+".tmp-"+hex.EncodeToString(suffix[:]))

	file, err := openReservationFile(tmp, true)
	if err != nil {
		return errors.Join(ErrReservationUnavailable, err)
	}

	// The temporary name is private to this call; the published one is never removed.
	defer os.Remove(tmp)

	n, err := file.Write(data)
	if err == nil && n != len(data) {
		err = io.ErrShortWrite
	}

	if err == nil {
		err = file.Sync()
	}

	if closeErr := file.Close(); err == nil {
		err = closeErr
	}

	if err != nil {
		return errors.Join(ErrReservationUnavailable, err)
	}

	// A hard link fails if the name exists: the exclusive step that arbitrates concurrent creators.
	if err := os.Link(tmp, filepath.Join(dir, name)); err != nil {
		return errors.Join(ErrReservationUnavailable, err)
	}

	_ = os.Remove(tmp)

	if err := syncReservationDirectory(dir); err != nil {
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

	return encodeJournalPayload(payload, previous)
}

// encodeJournalPayload frames one record, hold or release, on the shared checksum chain.
func encodeJournalPayload(payload []byte, previous [sha256.Size]byte) ([]byte, error) {
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

// reservationJournalState is the replayed journal: the registry holds the active ownership, and the
// historical indexes every reservation ID and owner ever held, which a release never removes.
type reservationJournalState struct {
	registry *egressReservationRegistry

	seenIDs    map[string]struct{}
	seenOwners map[LeaseOwner]struct{}

	tail   [sha256.Size]byte
	length int64
}

// checkNewHold refuses a hold whose owner or ID was ever held, released ones included, so stale
// authorization cannot resurrect them, and a hold beyond the history capacity.
func (s *reservationJournalState) checkNewHold(hold EgressReservation) error {
	if s.seenIDs == nil || s.seenOwners == nil {
		return ErrReservationUnavailable
	}

	if _, exists := s.seenOwners[hold.Owner]; exists {
		return ErrReservationOwnerRetired
	}

	if _, exists := s.seenIDs[hold.ID]; exists {
		return ErrReservationUnavailable
	}

	if len(s.seenIDs) >= maxHistoricalReservations {
		return ErrReservationLimit
	}

	return nil
}

// restoreHold replays one hold: the authority's key, the history, then the active indexes.
func (s *reservationJournalState) restoreHold(hold EgressReservation, authority *ReservationAuthorityInfo) error {
	if authority != nil && hold.PublicKeySHA256 != authority.PublicKeySHA256 {
		return ErrReservationAuthorityMismatch
	}

	if err := s.checkNewHold(hold); err != nil {
		return err
	}

	if err := restoreJournalHold(s.registry, hold); err != nil {
		return err
	}

	s.seenIDs[hold.ID] = struct{}{}
	s.seenOwners[hold.Owner] = struct{}{}

	return nil
}

// applyRelease removes exactly one active hold, matched by its retirement receipt, from a registry
// not yet visible to anyone else; the caller holds the journal's OS lock. The history stays.
func (s *reservationJournalState) applyRelease(record reservationReleaseRecord, authority *ReservationAuthorityInfo) error {
	if authority == nil || !validReleaseRecord(record) {
		return ErrReservationJournalCorrupt
	}

	id := record.Receipt.Intent.ReservationID
	registry := s.registry

	owner, exists := registry.byID[id]
	if !exists {
		return ErrReservationJournalCorrupt
	}

	hold, exists := registry.byOwner[owner]
	if !exists || hold.ID != id || hold.Owner != owner || !record.Receipt.matchesReservation(*authority, hold) ||
		record.ReleasedAt.Before(hold.ReservedAt) {
		return ErrReservationJournalCorrupt
	}

	// Every index must still name exactly this reservation.
	ipOwner, hasIP := registry.byIP[hold.IPv4]
	profileOwner, hasProfile := registry.byProfile[owner.ProfileID]

	if !hasIP || ipOwner != owner || !hasProfile || profileOwner != owner {
		return ErrReservationJournalCorrupt
	}

	if _, exists := s.seenIDs[id]; !exists {
		return ErrReservationJournalCorrupt
	}

	if _, exists := s.seenOwners[owner]; !exists {
		return ErrReservationJournalCorrupt
	}

	delete(registry.byOwner, owner)
	delete(registry.byIP, hold.IPv4)
	delete(registry.byProfile, owner.ProfileID)
	delete(registry.byID, id)

	return nil
}

// applyPayload dispatches on the record type; holds carry none. Unknown types are corruption, and
// a release is only meaningful against a provisioned authority.
func (s *reservationJournalState) applyPayload(payload []byte, authority *ReservationAuthorityInfo) error {
	var kind struct {
		Type string `json:"type"`
	}

	if err := json.Unmarshal(payload, &kind); err != nil {
		return ErrReservationJournalCorrupt
	}

	switch kind.Type {
	case "":
		hold, err := decodeReservationPayload(payload)
		if err != nil {
			return err
		}

		return s.restoreHold(hold, authority)

	case reservationReleaseType:
		if authority == nil {
			return ErrReservationJournalCorrupt
		}

		record, err := decodeReleasePayload(payload)
		if err != nil {
			return err
		}

		return s.applyRelease(record, authority)

	default:
		return ErrReservationJournalCorrupt
	}
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
	return parseReservationJournalWithHeader(data, reservationJournalMagic)
}

func parseReservationJournalWithHeader(data []byte, headerText string) (reservationJournalState, error) {
	return parseReservationJournalRecords(data, headerText, nil)
}

// parseReservationJournalRecords replays holds and, for a provisioned authority, releases.
func parseReservationJournalRecords(data []byte, headerText string, authority *ReservationAuthorityInfo) (
	reservationJournalState, error) {
	header := []byte(headerText)

	if authority != nil {
		expected, err := authorityJournalHeader(*authority)
		if err != nil || expected != headerText {
			return reservationJournalState{}, ErrReservationAuthorityMismatch
		}
	}

	if len(header) == 0 || len(header) > maxReservationHeaderBytes || len(data) > maxReservationJournalBytes ||
		!bytes.HasPrefix(data, header) {
		return reservationJournalState{}, ErrReservationJournalCorrupt
	}

	state := reservationJournalState{
		registry:   newEgressReservationRegistry(),
		seenIDs:    make(map[string]struct{}),
		seenOwners: make(map[LeaseOwner]struct{}),
		tail:       sha256.Sum256(header),
		length:     int64(len(data)),
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

		if err := state.applyPayload(remaining[4:bodyEnd], authority); err != nil {
			return reservationJournalState{}, errors.Join(corrupt, err)
		}

		state.tail = digest
		remaining = remaining[frameEnd:]
	}

	return state, nil
}

// readReservationJournal reads through the locked handle.
func readReservationJournal(file *os.File) (reservationJournalState, error) {
	return readReservationJournalRecords(file, reservationJournalMagic, nil)
}

func readReservationJournalRecords(file *os.File, headerText string, authority *ReservationAuthorityInfo) (
	reservationJournalState, error) {
	info, err := file.Stat()
	if err != nil {
		return reservationJournalState{}, errors.Join(ErrReservationUnavailable, err)
	}

	if info.Size() < int64(len(headerText)) || info.Size() > int64(maxReservationJournalBytes) {
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

	return parseReservationJournalRecords(data, headerText, authority)
}

// appendReservationHold appends a hold that passes the history checks.
func appendReservationHold(file *os.File, state reservationJournalState, reservation EgressReservation) error {
	if err := state.checkNewHold(reservation); err != nil {
		return err
	}

	frame, err := encodeReservationFrame(reservation, state.tail)
	if err != nil {
		return err
	}

	return appendJournalFrame(file, state, frame)
}

// appendJournalFrame appends one complete frame and flushes it before reporting success. Once the
// write starts, a failure is uncertain: never truncate or try to roll back.
func appendJournalFrame(file *os.File, state reservationJournalState, frame []byte) error {
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
	now func() time.Time) (EgressReservation, error) {
	return reserveDurableEgressJournal(ctx, legacyReservationJournal(dataDir), admission, now)
}

// reserveDurableEgressJournal is the transaction itself, against one journal format and, in
// production, one provisioned authority.
func reserveDurableEgressJournal(ctx context.Context, journal reservationJournalSpec, admission candidateAdmission,
	now func() time.Time) (reservation EgressReservation, resultErr error) {
	if ctx == nil || now == nil {
		return EgressReservation{}, ErrReservationUnavailable
	}

	if journal.authority != nil && admission.runtime.PublicKeySHA256 != journal.authority.PublicKeySHA256 {
		return EgressReservation{}, ErrReservationAuthorityMismatch
	}

	handle, err := journal.open()
	if err != nil {
		return EgressReservation{}, err
	}

	defer func() {
		if err := handle.Close(); err != nil {
			reservation = EgressReservation{}
			resultErr = errors.Join(resultErr, ErrReservationStateUncertain, err)
		}
	}()

	file := handle.File

	state, err := journal.read(file)
	if err != nil {
		return EgressReservation{}, err
	}

	// An interrupted initialization may not have flushed the journal's directory entry; a grant
	// must not rely on a name that a crash can still remove.
	if err := syncReservationDirectory(journal.directory); err != nil {
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
func inspectReservationJournal(dataDir string) ([]EgressReservation, error) {
	return inspectReservationJournalSpec(legacyReservationJournal(dataDir))
}

func inspectReservationJournalSpec(journal reservationJournalSpec) ([]EgressReservation, error) {
	state, err := loadReservationJournalState(journal)
	if err != nil {
		return nil, err
	}

	return state.registry.snapshot(), nil
}

// loadReservationJournalState replays the journal under its lock and releases the lock again; the
// state is a snapshot for inspection, never the basis of a write.
func loadReservationJournalState(journal reservationJournalSpec) (state reservationJournalState, resultErr error) {
	handle, err := journal.open()
	if err != nil {
		return reservationJournalState{}, err
	}

	defer func() {
		if err := handle.Close(); err != nil {
			state = reservationJournalState{}
			resultErr = errors.Join(resultErr, ErrReservationUnavailable, err)
		}
	}()

	return journal.read(handle.File)
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
