//go:build windows || linux || darwin

package control

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func newTestReservationJournal(t *testing.T) string {
	t.Helper()

	dir := t.TempDir()
	if err := initializeReservationJournal(dir); err != nil {
		t.Fatal(err)
	}

	return dir
}

func testJournalHold(t *testing.T, profile, runtime, generation int, ip string) EgressReservation {
	t.Helper()

	base := reservationTestBase
	registry := testRegistryAt(base.Add(11 * time.Second))

	hold, err := registry.reserve(testReservationAdmission(t, profile, runtime, generation, ip, base))
	if err != nil {
		t.Fatal(err)
	}

	return hold
}

func testJournalBytes(t *testing.T, holds ...EgressReservation) []byte {
	t.Helper()

	data := []byte(reservationJournalMagic)
	tail := sha256.Sum256(data)

	for _, hold := range holds {
		frame, err := encodeReservationFrame(hold, tail)
		if err != nil {
			t.Fatal(err)
		}

		copy(tail[:], frame[len(frame)-sha256.Size:])
		data = append(data, frame...)
	}

	return data
}

func TestReservationJournalInitialization(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, reservationJournalFile)

	// A missing authority must not look like an empty, healthy one.
	if _, err := inspectReservationJournal(dir); !errors.Is(err, ErrReservationUnavailable) {
		t.Fatalf("missing journal accepted: %v", err)
	}

	if _, err := reserveDurableEgressAt(dir, testReservationAdmission(t, 1, 1, 1, "8.8.4.4", reservationTestBase),
		func() time.Time { return reservationTestBase.Add(11 * time.Second) }); !errors.Is(err, ErrReservationUnavailable) {
		t.Fatalf("reservation without a journal: %v", err)
	}

	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("a normal operation created the journal")
	}

	for _, bad := range []string{"", "relative", filepath.Join(dir, "missing")} {
		if err := initializeReservationJournal(bad); !errors.Is(err, ErrReservationUnavailable) {
			t.Fatalf("initialized under %q: %v", bad, err)
		}
	}

	if err := initializeReservationJournal(dir); err != nil {
		t.Fatal(err)
	}

	data, err := os.ReadFile(path)
	if err != nil || string(data) != reservationJournalMagic {
		t.Fatal("invalid initialized journal")
	}

	if items, err := inspectReservationJournal(dir); err != nil || len(items) != 0 {
		t.Fatalf("new journal not empty: %v %v", items, err)
	}

	if err := initializeReservationJournal(dir); err == nil {
		t.Fatal("existing journal initialized again")
	}

	if after, err := os.ReadFile(path); err != nil || !bytes.Equal(data, after) {
		t.Fatal("refused initialization changed the journal")
	}

	// An empty file (an interrupted initialization) is not an empty registry.
	empty := t.TempDir()
	if err := os.WriteFile(filepath.Join(empty, reservationJournalFile), nil, 0o600); err != nil {
		t.Fatal(err)
	}

	if _, err := inspectReservationJournal(empty); !errors.Is(err, ErrReservationJournalCorrupt) {
		t.Fatalf("empty journal accepted: %v", err)
	}
}

func TestReservationJournalRefusesSymlink(t *testing.T) {
	target := newTestReservationJournal(t)
	dir := t.TempDir()

	if err := os.Symlink(filepath.Join(target, reservationJournalFile), filepath.Join(dir, reservationJournalFile)); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}

	if _, err := inspectReservationJournal(dir); !errors.Is(err, ErrReservationUnavailable) {
		t.Fatalf("journal opened through a symlink: %v", err)
	}
}

func TestReservationJournalPersistentOwnership(t *testing.T) {
	dir := newTestReservationJournal(t)
	base := reservationTestBase
	now := base.Add(11 * time.Second)
	clock := func() time.Time { return now }

	first, err := reserveDurableEgressAt(dir, testReservationAdmission(t, 1, 1, 1, "8.8.4.4", base), clock)
	if err != nil || !first.FreshAt(now) {
		t.Fatalf("initial reservation failed: %v", err)
	}

	// A new handle rebuilds ownership from disk, not from memory.
	items, err := inspectReservationJournal(dir)
	if err != nil || len(items) != 1 || !items[0].recovered || items[0].FreshAt(now) {
		t.Fatalf("recovered hold is eligible: %v", err)
	}

	if normalizeReservationRecord(items[0]) != normalizeReservationRecord(first) {
		t.Fatal("persisted ownership changed")
	}

	if _, err := reserveDurableEgressAt(dir, testReservationAdmission(t, 2, 2, 2, "8.8.4.4", base), clock); !errors.Is(err, ErrReservationIPCollision) {
		t.Fatalf("stored address allocated again: %v", err)
	}

	// Expiry does not release a durable hold.
	now = base.Add(2 * time.Minute)
	freshBase := now.Add(-11 * time.Second)

	if _, err := reserveDurableEgressAt(dir, testReservationAdmission(t, 3, 3, 3, "8.8.4.4", freshBase), clock); !errors.Is(err, ErrReservationIPCollision) {
		t.Fatalf("expired durable hold released: %v", err)
	}

	if _, err := reserveDurableEgressAt(dir, testReservationAdmission(t, 1, 5, 5, "8.8.8.8", freshBase), clock); !errors.Is(err, ErrReservationProfileHeld) {
		t.Fatalf("profile got a second durable hold: %v", err)
	}

	if _, err := reserveDurableEgressAt(dir, testReservationAdmission(t, 4, 4, 4, "8.8.8.8", freshBase), clock); err != nil {
		t.Fatal(err)
	}

	if items, err := inspectReservationJournal(dir); err != nil || len(items) != 2 {
		t.Fatalf("durable registry state: %d %v", len(items), err)
	}

	loaded, exists, err := lookupDurableReservationByIP(dir, netip.MustParseAddr("8.8.4.4"))
	if err != nil || !exists || loaded.ID != first.ID || !loaded.recovered {
		t.Fatalf("original reservation lost: %v", err)
	}

	if _, exists, err := lookupDurableReservationByIP(dir, netip.MustParseAddr("1.1.1.1")); err != nil || exists {
		t.Fatalf("unreserved address reported: %v", err)
	}

	if _, _, err := lookupDurableReservationByIP(dir, netip.MustParseAddr("10.0.0.1")); !errors.Is(err, ErrReservationCandidateInvalid) {
		t.Fatalf("private address looked up: %v", err)
	}
}

func TestReservationJournalFrameValidation(t *testing.T) {
	headerLen := len(reservationJournalMagic)
	valid := testJournalBytes(t, testJournalHold(t, 1, 1, 1, "8.8.4.4"))

	if state, err := parseReservationJournal(valid); err != nil || len(state.registry.snapshot()) != 1 {
		t.Fatalf("valid journal rejected: %v", err)
	}

	for name, mutate := range map[string]func([]byte) []byte{
		"empty file":     func([]byte) []byte { return nil },
		"invalid header": func(d []byte) []byte { d[0] ^= 1; return d },
		"invalid length": func(d []byte) []byte {
			binary.BigEndian.PutUint32(d[headerLen:], 0xffffffff)
			return d
		},
		"zero length": func(d []byte) []byte {
			binary.BigEndian.PutUint32(d[headerLen:], 0)
			return d
		},
		"payload corruption":  func(d []byte) []byte { d[headerLen+5] ^= 1; return d },
		"checksum corruption": func(d []byte) []byte { d[len(d)-1] ^= 1; return d },
		"truncated checksum":  func(d []byte) []byte { return d[:len(d)-1] },
		"partial next record": func(d []byte) []byte { return append(d, 0, 0) },
	} {
		t.Run(name, func(t *testing.T) {
			state, err := parseReservationJournal(mutate(bytes.Clone(valid)))
			if !errors.Is(err, ErrReservationJournalCorrupt) || state.registry != nil {
				t.Fatal("damaged journal exposed a registry")
			}
		})
	}
}

// Each digest covers the previous one, so frames cannot be dropped or reordered even though each
// frame is intact on its own.
func TestReservationJournalChainOrder(t *testing.T) {
	first := testJournalHold(t, 1, 1, 1, "8.8.4.4")
	second := testJournalHold(t, 2, 2, 2, "8.8.8.8")

	data := testJournalBytes(t, first, second)
	if _, err := parseReservationJournal(data); err != nil {
		t.Fatal(err)
	}

	headerLen := len(reservationJournalMagic)
	firstEnd := len(testJournalBytes(t, first))
	header, frameA, frameB := data[:headerLen], data[headerLen:firstEnd], data[firstEnd:]

	for name, bad := range map[string][]byte{
		"first dropped": append(bytes.Clone(header), frameB...),
		"reordered":     append(append(bytes.Clone(header), frameB...), frameA...),
	} {
		if _, err := parseReservationJournal(bad); !errors.Is(err, ErrReservationJournalCorrupt) {
			t.Fatalf("%s: chain accepted", name)
		}
	}
}

// A journal whose checksums are right can still break the ownership invariants.
func TestReservationJournalRejectsDuplicateOwnership(t *testing.T) {
	first := testJournalHold(t, 1, 1, 1, "8.8.4.4")

	cases := map[string]func() EgressReservation{
		"duplicate IPv4":    func() EgressReservation { return testJournalHold(t, 2, 2, 2, "8.8.4.4") },
		"duplicate owner":   func() EgressReservation { return testJournalHold(t, 1, 1, 1, "8.8.8.8") },
		"duplicate profile": func() EgressReservation { return testJournalHold(t, 1, 2, 2, "8.8.8.8") },
		"duplicate reservation ID": func() EgressReservation {
			second := testJournalHold(t, 2, 2, 2, "8.8.8.8")
			second.ID = first.ID
			return second
		},
	}

	for name, second := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := parseReservationJournal(testJournalBytes(t, first, second())); !errors.Is(err, ErrReservationJournalCorrupt) {
				t.Fatal("invalid ownership restored")
			}
		})
	}
}

// The writer refuses invalid records, so a test frame is assembled by hand around a canonical
// payload with a correct checksum.
func TestReservationJournalRejectsInvalidRecord(t *testing.T) {
	hold := normalizeReservationRecord(testJournalHold(t, 1, 1, 1, "8.8.4.4"))

	for name, mutate := range map[string]func(*EgressReservation){
		"private address":         func(r *EgressReservation) { r.IPv4 = netip.MustParseAddr("10.0.0.1") },
		"invalid ID":              func(r *EgressReservation) { r.ID = "reservation_1" },
		"reused nonce":            func(r *EgressReservation) { r.ReservationNonce = r.EvidenceNonce },
		"eligible past cutoff":    func(r *EgressReservation) { r.EligibleUntil = r.CandidateExpiresAt },
		"eligible before reserve": func(r *EgressReservation) { r.EligibleUntil = r.ReservedAt },
		"invalid owner":           func(r *EgressReservation) { r.Owner.TunnelGeneration = "" },
	} {
		t.Run(name, func(t *testing.T) {
			bad := hold
			mutate(&bad)

			payload, err := json.Marshal(bad)
			if err != nil {
				t.Fatal(err)
			}

			data := []byte(reservationJournalMagic)
			body := binary.BigEndian.AppendUint32(nil, uint32(len(payload)))
			body = append(body, payload...)
			digest := reservationFrameDigest(sha256.Sum256(data), body)
			data = append(append(data, body...), digest[:]...)

			if _, err := parseReservationJournal(data); !errors.Is(err, ErrReservationJournalCorrupt) {
				t.Fatal("invalid record restored")
			}
		})
	}
}

func TestReservationJournalCanonicalPayload(t *testing.T) {
	payload, err := json.Marshal(normalizeReservationRecord(testJournalHold(t, 1, 1, 1, "8.8.4.4")))
	if err != nil {
		t.Fatal(err)
	}

	decoded, err := decodeReservationPayload(payload)
	if err != nil || !decoded.recovered {
		t.Fatalf("canonical payload rejected: %v", err)
	}

	duplicate := bytes.Replace(payload, []byte(`"ipv4":"8.8.4.4"`), []byte(`"ipv4":"8.8.8.8","ipv4":"8.8.4.4"`), 1)
	unknown := append(bytes.Clone(payload[:len(payload)-1]), []byte(`,"override":true}`)...)
	indented, err := json.MarshalIndent(normalizeReservationRecord(decoded), "", " ")
	if err != nil {
		t.Fatal(err)
	}

	for name, bad := range map[string][]byte{
		"duplicate field":  duplicate,
		"unknown field":    unknown,
		"trailing JSON":    append(bytes.Clone(payload), []byte(` {}`)...),
		"extra whitespace": append(bytes.Clone(payload), ' '),
		"indented":         indented,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := decodeReservationPayload(bad); !errors.Is(err, ErrReservationJournalCorrupt) {
				t.Fatal("noncanonical payload accepted")
			}
		})
	}
}

func TestReservationJournalCorruptionBlocksAllocation(t *testing.T) {
	dir := newTestReservationJournal(t)
	base := reservationTestBase
	clock := func() time.Time { return base.Add(11 * time.Second) }

	if _, err := reserveDurableEgressAt(dir, testReservationAdmission(t, 1, 1, 1, "8.8.4.4", base), clock); err != nil {
		t.Fatal(err)
	}

	path := filepath.Join(dir, reservationJournalFile)

	original, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}

	// A torn append, simulated in the test directory only.
	damaged := append(bytes.Clone(original), 0, 0, 0, 100, '{')
	if err := os.WriteFile(path, damaged, 0o600); err != nil {
		t.Fatal(err)
	}

	result, err := reserveDurableEgressAt(dir, testReservationAdmission(t, 2, 2, 2, "8.8.8.8", base), clock)
	if !errors.Is(err, ErrReservationJournalCorrupt) || result != (EgressReservation{}) {
		t.Fatalf("corrupt authority granted ownership: %v", err)
	}

	if items, err := inspectReservationJournal(dir); !errors.Is(err, ErrReservationJournalCorrupt) || items != nil {
		t.Fatal("corrupt journal exposed partial state")
	}

	if after, err := os.ReadFile(path); err != nil || !bytes.Equal(damaged, after) {
		t.Fatal("damaged journal modified")
	}
}

func TestReservationJournalCommitDeadline(t *testing.T) {
	for _, afterFlush := range []bool{false, true} {
		name := "before append"
		if afterFlush {
			name = "after flush"
		}

		t.Run(name, func(t *testing.T) {
			dir := newTestReservationJournal(t)
			base := reservationTestBase

			// reserve reads the clock twice; the durable path again before the append and after
			// the flush.
			expireAt := 3
			if afterFlush {
				expireAt = 4
			}

			calls := 0
			clock := func() time.Time {
				calls++
				if calls >= expireAt {
					return base.Add(55 * time.Second)
				}
				return base.Add(11 * time.Second)
			}

			result, err := reserveDurableEgressAt(dir, testReservationAdmission(t, 1, 1, 1, "8.8.4.4", base), clock)

			expected, holds := ErrReservationCandidateExpired, 0
			if afterFlush {
				expected, holds = ErrReservationCommittedExpired, 1
			}

			if !errors.Is(err, expected) || result != (EgressReservation{}) {
				t.Fatalf("unexpected result: %v", err)
			}

			if items, err := inspectReservationJournal(dir); err != nil || len(items) != holds {
				t.Fatalf("committed state: %d %v", len(items), err)
			}
		})
	}
}

// The lock spans the whole transaction: another handle is refused while the writer sits between
// validation and append, and between the flush and its return. Separate handles conflict in one
// process too (LockFileEx per handle, flock per open file description).
func TestReservationJournalLockSpansTransaction(t *testing.T) {
	dir := newTestReservationJournal(t)
	base := reservationTestBase
	writer := testReservationAdmission(t, 1, 1, 1, "8.8.4.4", base)
	contender := testReservationAdmission(t, 2, 2, 2, "8.8.4.4", base)
	clock := func() time.Time { return base.Add(11 * time.Second) }

	reached := make(chan int, 2)
	release := make(chan struct{})
	done := make(chan error, 1)

	calls := 0
	pausing := func() time.Time {
		calls++
		// Calls 3 and 4: before the append and after the flush (reserve itself reads 1 and 2).
		if calls == 3 || calls == 4 {
			reached <- calls
			<-release
		}

		return clock()
	}

	go func() {
		_, err := reserveDurableEgressAt(dir, writer, pausing)
		done <- err
	}()

	finished := false
	defer func() {
		if !finished {
			close(release)
			<-done
		}
	}()

	for _, point := range []int{3, 4} {
		select {
		case got := <-reached:
			if got != point {
				t.Fatalf("paused at clock call %d, want %d", got, point)
			}
		case <-time.After(10 * time.Second):
			t.Fatal("writer did not reach its pause point")
		}

		if _, err := inspectReservationJournal(dir); !errors.Is(err, ErrReservationBusy) {
			t.Fatalf("inspection during the transaction (call %d): %v", point, err)
		}

		if _, err := reserveDurableEgressAt(dir, contender, clock); !errors.Is(err, ErrReservationBusy) {
			t.Fatalf("second reservation during the transaction (call %d): %v", point, err)
		}

		release <- struct{}{}
	}

	err := <-done
	finished = true

	if err != nil {
		t.Fatal(err)
	}

	if _, err := reserveDurableEgressAt(dir, contender, clock); !errors.Is(err, ErrReservationIPCollision) {
		t.Fatalf("contender after the commit: %v", err)
	}
}

func TestReservationJournalAppendFailures(t *testing.T) {
	dir := newTestReservationJournal(t)
	path := filepath.Join(dir, reservationJournalFile)

	empty, err := parseReservationJournal([]byte(reservationJournalMagic))
	if err != nil {
		t.Fatal(err)
	}

	hold := testJournalHold(t, 1, 1, 1, "8.8.4.4")

	// A failed write is uncertain, not a clean refusal.
	readOnly, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}

	err = appendReservationHold(readOnly, empty, hold)
	readOnly.Close()

	if !errors.Is(err, ErrReservationStateUncertain) {
		t.Fatalf("failed write not uncertain: %v", err)
	}

	if _, err := reserveDurableEgressAt(dir, testReservationAdmission(t, 2, 2, 2, "8.8.8.8", reservationTestBase),
		func() time.Time { return reservationTestBase.Add(11 * time.Second) }); err != nil {
		t.Fatal(err)
	}

	grown, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}

	// State read before the journal grew must not be appended to.
	file, err := openLockedReservationJournal(path, false)
	if err != nil {
		t.Fatal(err)
	}

	err = appendReservationHold(file, empty, hold)
	file.Close()

	if !errors.Is(err, ErrReservationJournalCorrupt) {
		t.Fatalf("stale state appended: %v", err)
	}

	if after, err := os.ReadFile(path); err != nil || !bytes.Equal(grown, after) {
		t.Fatal("refused append changed the journal")
	}
}
