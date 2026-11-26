//go:build windows || linux || darwin

package control

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

type releaseTestFixture struct {
	dir       string
	authority *ReservationAuthority
	journal   reservationJournalSpec
	signer    *seedSigner

	admission releaseAdmission
	now       time.Time
}

// releaseAdmissionFor signs a revocation for hold, from the helper and runtime of candidate, and
// fakes the helper's receipt; no kernel cleanup runs.
func releaseAdmissionFor(t *testing.T, authority ReservationAuthorityInfo, signer *seedSigner, hold EgressReservation,
	candidate candidateAdmission, mintedAt time.Time) releaseAdmission {
	t.Helper()

	intent, err := revokeIntentFromHold(authority, hold)
	if err != nil {
		t.Fatal(err)
	}

	capability, err := mintLabCapability(signer, intent, candidate.helper, mintedAt)
	if err != nil {
		t.Fatal(err)
	}

	return releaseAdmission{
		hold:      hold,
		runtime:   candidate.runtime,
		helper:    candidate.helper,
		publicKey: candidate.publicKey,

		capability: capability,
		receipt: LabRevokedLeaseInfo{
			Intent:            intent,
			HelperID:          candidate.helper.HelperID,
			PublicKeySHA256:   candidate.helper.PublicKeySHA256,
			RevocationNonce:   capability.Claims.Nonce,
			GenerationRetired: true,
		},

		mintedAt: mintedAt,
		sentAt:   mintedAt.Add(time.Second),
		// The cleanup can outlast the capability's 30 s.
		receivedAt: mintedAt.Add(40 * time.Second),
	}
}

func newReleaseTestFixture(t *testing.T) releaseTestFixture {
	t.Helper()

	dir, authority, signer := newTestAuthority(t)

	journal, err := authority.journal()
	if err != nil {
		t.Fatal(err)
	}

	base := reservationTestBase
	candidate := testReservationAdmission(t, 1, 1, 1, "8.8.4.4", base)

	hold, err := reserveDurableEgressJournal(context.Background(), journal, candidate,
		func() time.Time { return base.Add(11 * time.Second) })
	if err != nil {
		t.Fatal(err)
	}

	items, err := authority.List()
	if err != nil || len(items) != 1 || items[0].ID != hold.ID || !items[0].recovered {
		t.Fatal("missing recovered reservation")
	}

	// Revoked after the original evidence expired, from the recovered hold.
	admission := releaseAdmissionFor(t, authority.Info(), signer, items[0], candidate, base.Add(2*time.Minute))

	return releaseTestFixture{
		dir:       dir,
		authority: authority,
		journal:   journal,
		signer:    signer,
		admission: admission,
		now:       admission.receivedAt.Add(time.Second),
	}
}

func (f releaseTestFixture) clock() time.Time { return f.now }

func (f releaseTestFixture) release() (reservationReleaseRecord, error) {
	return releaseDurableEgressJournal(context.Background(), f.journal, f.admission, f.clock)
}

func (f releaseTestFixture) journalBytes(t *testing.T) []byte {
	t.Helper()

	data, err := os.ReadFile(filepath.Join(f.dir, reservationJournalFile))
	if err != nil {
		t.Fatal(err)
	}

	return data
}

func TestRevokeIntentAndReceipt(t *testing.T) {
	f := newReleaseTestFixture(t)
	receipt := f.admission.receipt
	intent := receipt.Intent

	if !ValidLabRevokeEgressLeaseIntent(intent) || intent.Operation != LabRevokeEgressLeaseOp ||
		intent.AuthorityID != f.authority.Info().ID || intent.ReservationID != f.admission.hold.ID {
		t.Fatalf("invalid revocation intent: %+v", intent)
	}

	preparation := intent
	preparation.Operation = LabPrepareEgressLeaseOp

	if ValidLabRevokeEgressLeaseIntent(preparation) {
		t.Fatal("a preparation intent is a revocation")
	}

	if _, err := NewLabRevokeEgressLeaseIntent(intent); !errors.Is(err, ErrReservationReleaseInvalid) {
		t.Fatal("revocation built from a revocation")
	}

	malformed := preparation
	malformed.EgressIPv4 = "10.0.0.1"

	if _, err := NewLabRevokeEgressLeaseIntent(malformed); !errors.Is(err, ErrReservationReleaseInvalid) {
		t.Fatal("revocation built from an invalid binding")
	}

	if !receipt.MatchesCapability(f.admission.capability) ||
		!receipt.matchesReservation(f.authority.Info(), f.admission.hold) {
		t.Fatal("valid receipt refused")
	}

	for name, mutate := range map[string]func(*LabRevokedLeaseInfo){
		"not retired":     func(r *LabRevokedLeaseInfo) { r.GenerationRetired = false },
		"evidence nonce":  func(r *LabRevokedLeaseInfo) { r.RevocationNonce = r.Intent.EvidenceNonce },
		"candidate nonce": func(r *LabRevokedLeaseInfo) { r.RevocationNonce = r.Intent.ReservationNonce },
		"malformed nonce": func(r *LabRevokedLeaseInfo) { r.RevocationNonce = "nonce" },
		"malformed epoch": func(r *LabRevokedLeaseInfo) { r.HelperID = "helper_1" },
		"malformed key":   func(r *LabRevokedLeaseInfo) { r.PublicKeySHA256 = "key" },
		"preparation":     func(r *LabRevokedLeaseInfo) { r.Intent.Operation = LabPrepareEgressLeaseOp },
	} {
		bad := receipt
		mutate(&bad)

		if bad.Valid() {
			t.Errorf("%s: invalid receipt valid", name)
		}
	}

	for name, mutate := range map[string]func(*LabCapability){
		"other nonce":   func(c *LabCapability) { c.Claims.Nonce = strings.Repeat("f", 32) },
		"other helper":  func(c *LabCapability) { c.Claims.HelperID = "helper_ffffffffffffffffffffffffffffffff" },
		"other version": func(c *LabCapability) { c.Claims.Version = 2 },
		"other intent":  func(c *LabCapability) { c.Claims.Intent.ReservationID = "reservation_ffffffffffffffffffffffffffffffff" },
	} {
		capability := f.admission.capability
		mutate(&capability)

		if receipt.MatchesCapability(capability) {
			t.Errorf("%s: receipt matched another capability", name)
		}
	}

	otherEpoch := receipt
	otherEpoch.HelperID = "helper_ffffffffffffffffffffffffffffffff"

	if otherEpoch.matchesReservation(f.authority.Info(), f.admission.hold) {
		t.Fatal("a receipt from another helper epoch matched the hold")
	}

	foreignKey := f.admission.hold
	foreignKey.PublicKeySHA256 = strings.Repeat("f", 64)

	if _, err := revokeIntentFromHold(f.authority.Info(), foreignKey); !errors.Is(err, ErrReservationReleaseInvalid) {
		t.Fatal("revocation built for a hold of another key")
	}
}

func TestReleaseAdmissionValidation(t *testing.T) {
	f := newReleaseTestFixture(t)

	if f.admission.hold.FreshAt(f.now) {
		t.Fatal("the fixture must use expired evidence")
	}

	if err := validateReleaseAdmission(f.authority.Info(), f.admission, f.now); err != nil {
		t.Fatalf("valid retirement refused: %v", err)
	}

	otherKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x24}, ed25519.SeedSize)).Public().(ed25519.PublicKey)

	for name, mutate := range map[string]func(*releaseAdmission){
		"not retired":     func(a *releaseAdmission) { a.receipt.GenerationRetired = false },
		"wrong authority": func(a *releaseAdmission) { a.receipt.Intent.AuthorityID = "authority_ffffffffffffffffffffffffffffffff" },
		"wrong generation": func(a *releaseAdmission) {
			a.receipt.Intent.TunnelGeneration = "tunnelgen_ffffffffffffffffffffffffffffffff"
		},
		"wrong reservation": func(a *releaseAdmission) {
			a.receipt.Intent.ReservationID = "reservation_ffffffffffffffffffffffffffffffff"
		},
		"wrong helper epoch": func(a *releaseAdmission) { a.helper.HelperID = "helper_ffffffffffffffffffffffffffffffff" },
		"receipt epoch":      func(a *releaseAdmission) { a.receipt.HelperID = "helper_ffffffffffffffffffffffffffffffff" },
		"wrong runtime":      func(a *releaseAdmission) { a.runtime.ID = "runtime_ffffffffffffffffffffffffffffffff" },
		"helper runtime":     func(a *releaseAdmission) { a.helper.RuntimeID = "runtime_ffffffffffffffffffffffffffffffff" },
		"wrong fingerprint":  func(a *releaseAdmission) { a.receipt.PublicKeySHA256 = strings.Repeat("f", 64) },
		"helper fingerprint": func(a *releaseAdmission) { a.helper.PublicKeySHA256 = strings.Repeat("f", 64) },
		"runtime key":        func(a *releaseAdmission) { a.runtime.PublicKeySHA256 = strings.Repeat("f", 64) },
		"helper unconfigured": func(a *releaseAdmission) {
			a.helper = LabHelperInfo{RuntimeID: a.helper.RuntimeID}
		},
		"untrusted target":       func(a *releaseAdmission) { a.runtime.Target = "" },
		"never trusted":          func(a *releaseAdmission) { a.runtime.TrustedAt = time.Time{} },
		"trusted after minting":  func(a *releaseAdmission) { a.runtime.TrustedAt = a.mintedAt.Add(time.Second) },
		"short key":              func(a *releaseAdmission) { a.publicKey = a.publicKey[:16] },
		"other key":              func(a *releaseAdmission) { a.publicKey = otherKey },
		"invalid signature":      func(a *releaseAdmission) { a.capability.Signature = "invalid" },
		"wrong revocation nonce": func(a *releaseAdmission) { a.receipt.RevocationNonce = strings.Repeat("f", 32) },
		"expired at submission":  func(a *releaseAdmission) { a.sentAt = a.mintedAt.Add(30 * time.Second) },
		"sent before minting":    func(a *releaseAdmission) { a.sentAt = a.mintedAt.Add(-time.Second) },
		"response before request": func(a *releaseAdmission) {
			a.receivedAt = a.sentAt.Add(-time.Second)
		},
		"minted before the hold": func(a *releaseAdmission) {
			*a = releaseAdmissionFor(t, f.authority.Info(), f.signer, a.hold, testReservationAdmission(t, 1, 1, 1, "8.8.4.4",
				reservationTestBase), a.hold.ReservedAt.Add(-time.Second))
		},
	} {
		t.Run(name, func(t *testing.T) {
			bad := f.admission
			mutate(&bad)

			if err := validateReleaseAdmission(f.authority.Info(), bad, f.now); !errors.Is(err, ErrReservationReleaseInvalid) {
				t.Fatalf("invalid retirement accepted: %v", err)
			}
		})
	}

	for name, now := range map[string]time.Time{
		"committed before the response": f.admission.receivedAt.Add(-time.Second),
		"committed before the hold":     f.admission.hold.ReservedAt.Add(-time.Second),
	} {
		if err := validateReleaseAdmission(f.authority.Info(), f.admission, now); !errors.Is(err,
			ErrReservationReleaseInvalid) {
			t.Errorf("%s accepted: %v", name, err)
		}
	}
}

// The central case: a confirmed release frees the address for a new owner, and neither the retired
// owner nor a late release of the old hold can touch it afterwards.
func TestReservationReleasePersistentOwnership(t *testing.T) {
	f := newReleaseTestFixture(t)

	record, err := f.release()
	if err != nil || record.Type != reservationReleaseType || !record.Receipt.GenerationRetired ||
		!record.ReleasedAt.Equal(f.now) {
		t.Fatalf("release failed: %+v %v", record, err)
	}

	reopened, err := OpenReservationAuthority(f.dir, f.signer)
	if err != nil {
		t.Fatal(err)
	}

	if items, err := reopened.List(); err != nil || len(items) != 0 {
		t.Fatal("released address remains actively held")
	}

	freshBase := f.now.Add(-11 * time.Second)

	stale := testReservationAdmission(t, 1, 1, 1, "8.8.4.4", freshBase)
	if _, err := reserveDurableEgressJournal(context.Background(), f.journal, stale, f.clock); !errors.Is(err,
		ErrReservationOwnerRetired) {
		t.Fatalf("retired generation resurrected: %v", err)
	}

	next := testReservationAdmission(t, 2, 2, 2, "8.8.4.4", freshBase)

	hold, err := reserveDurableEgressJournal(context.Background(), f.journal, next, f.clock)
	if err != nil {
		t.Fatal(err)
	}

	if hold.ID == f.admission.hold.ID {
		t.Fatal("reservation ID reused")
	}

	if _, err := f.release(); !errors.Is(err, ErrReservationNotFound) {
		t.Fatalf("old reservation released again: %v", err)
	}

	items, err := reopened.List()
	if err != nil || len(items) != 1 || items[0].ID != hold.ID || items[0].IPv4 != hold.IPv4 {
		t.Fatal("a stale release changed the new owner")
	}

	// The same profile on a new generation is a new owner too.
	sameProfile := testReservationAdmission(t, 1, 1, 3, "8.8.8.8", freshBase)
	if _, err := reserveDurableEgressJournal(context.Background(), f.journal, sameProfile, f.clock); err != nil {
		t.Fatalf("a new generation of the released profile refused: %v", err)
	}
}

func TestReservationReleaseRefusalDoesNotWrite(t *testing.T) {
	for name, mutate := range map[string]func(*releaseAdmission){
		"unconfirmed retirement": func(a *releaseAdmission) { a.receipt.GenerationRetired = false },
		"hold differs from the journal": func(a *releaseAdmission) {
			a.hold.EligibleUntil = a.hold.EligibleUntil.Add(-time.Second)
		},
	} {
		t.Run(name, func(t *testing.T) {
			f := newReleaseTestFixture(t)
			before := f.journalBytes(t)

			bad := f.admission
			mutate(&bad)

			if _, err := releaseDurableEgressJournal(context.Background(), f.journal, bad, f.clock); !errors.Is(err,
				ErrReservationReleaseInvalid) {
				t.Fatalf("invalid release accepted: %v", err)
			}

			if !bytes.Equal(before, f.journalBytes(t)) {
				t.Fatal("an invalid release changed the journal")
			}

			if items, err := f.authority.List(); err != nil || len(items) != 1 || items[0].ID != f.admission.hold.ID {
				t.Fatal("an invalid release removed the hold")
			}
		})
	}
}

// A frame with a correct checksum is not a valid record: the ownership transition is checked too.
func TestReservationReleaseReplayValidation(t *testing.T) {
	f := newReleaseTestFixture(t)
	original := f.journalBytes(t)

	state, err := parseReservationJournalRecords(original, f.journal.header, f.journal.authority)
	if err != nil {
		t.Fatal(err)
	}

	valid := reservationReleaseRecord{Type: reservationReleaseType, Receipt: f.admission.receipt, ReleasedAt: f.now}

	validPayload, err := json.Marshal(normalizeReleaseRecord(valid))
	if err != nil {
		t.Fatal(err)
	}

	appendPayload := func(t *testing.T, payload []byte) []byte {
		t.Helper()

		frame, err := encodeJournalPayload(payload, state.tail)
		if err != nil {
			t.Fatal(err)
		}

		return append(bytes.Clone(original), frame...)
	}

	invalid := map[string][]byte{}

	for name, mutate := range map[string]func(*reservationReleaseRecord){
		"unknown reservation": func(r *reservationReleaseRecord) {
			r.Receipt.Intent.ReservationID = "reservation_ffffffffffffffffffffffffffffffff"
		},
		"wrong authority": func(r *reservationReleaseRecord) {
			r.Receipt.Intent.AuthorityID = "authority_ffffffffffffffffffffffffffffffff"
		},
		"wrong generation": func(r *reservationReleaseRecord) {
			r.Receipt.Intent.TunnelGeneration = "tunnelgen_ffffffffffffffffffffffffffffffff"
		},
		"wrong helper epoch":     func(r *reservationReleaseRecord) { r.Receipt.HelperID = "helper_ffffffffffffffffffffffffffffffff" },
		"unconfirmed retirement": func(r *reservationReleaseRecord) { r.Receipt.GenerationRetired = false },
		"unknown record type":    func(r *reservationReleaseRecord) { r.Type = "force-release" },
		"no release time":        func(r *reservationReleaseRecord) { r.ReleasedAt = time.Time{} },
		"release before reservation": func(r *reservationReleaseRecord) {
			r.ReleasedAt = f.admission.hold.ReservedAt.Add(-time.Second)
		},
	} {
		record := valid
		mutate(&record)

		payload, err := json.Marshal(normalizeReleaseRecord(record))
		if err != nil {
			t.Fatal(err)
		}

		invalid[name] = payload
	}

	holdPayload, err := json.Marshal(normalizeReservationRecord(f.admission.hold))
	if err != nil {
		t.Fatal(err)
	}

	invalid["type in another case"] = bytes.Replace(validPayload, []byte(`"type"`), []byte(`"Type"`), 1)
	invalid["duplicated type"] = bytes.Replace(validPayload, []byte(`"type":"release"`),
		[]byte(`"type":"release","type":"release"`), 1)
	invalid["release with an extra field"] = append(bytes.Clone(validPayload[:len(validPayload)-1]),
		[]byte(`,"force":true}`)...)
	invalid["hold with an empty type"] = append([]byte(`{"type":"",`), holdPayload[1:]...)
	invalid["hold typed as a release"] = append([]byte(`{"type":"release",`), holdPayload[1:]...)
	invalid["indented release"], _ = json.MarshalIndent(normalizeReleaseRecord(valid), "", " ")

	for name, payload := range invalid {
		t.Run(name, func(t *testing.T) {
			restored, err := parseReservationJournalRecords(appendPayload(t, payload), f.journal.header,
				f.journal.authority)
			if !errors.Is(err, ErrReservationJournalCorrupt) || restored.registry != nil {
				t.Fatalf("invalid release restored: %v", err)
			}
		})
	}

	released := appendPayload(t, validPayload)

	replayed, err := parseReservationJournalRecords(released, f.journal.header, f.journal.authority)
	if err != nil || len(replayed.registry.snapshot()) != 0 || len(replayed.seenIDs) != 1 ||
		len(replayed.seenOwners) != 1 {
		t.Fatalf("invalid released journal state: %v", err)
	}

	if _, err := parseReservationJournalWithHeader(released, f.journal.header); !errors.Is(err,
		ErrReservationJournalCorrupt) {
		t.Fatal("a release accepted without its authority")
	}

	duplicate, err := encodeReleaseFrame(valid, replayed.tail)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := parseReservationJournalRecords(append(bytes.Clone(released), duplicate...), f.journal.header,
		f.journal.authority); !errors.Is(err, ErrReservationJournalCorrupt) {
		t.Fatal("a second release of the same hold accepted")
	}

	// The same hold recorded again after its release.
	rehold, err := encodeReservationFrame(f.admission.hold, replayed.tail)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := parseReservationJournalRecords(append(bytes.Clone(released), rehold...), f.journal.header,
		f.journal.authority); !errors.Is(err, ErrReservationJournalCorrupt) {
		t.Fatal("a released hold recorded again")
	}

	if _, err := parseReservationJournalRecords(released[:len(released)-1], f.journal.header,
		f.journal.authority); !errors.Is(err, ErrReservationJournalCorrupt) {
		t.Fatal("a torn release accepted")
	}

	if _, err := encodeReleaseFrame(reservationReleaseRecord{Type: reservationReleaseType, Receipt: f.admission.receipt},
		state.tail); !errors.Is(err, ErrReservationReleaseInvalid) {
		t.Fatal("an invalid release encoded")
	}
}

func TestReservationReleaseCanonicalPayload(t *testing.T) {
	f := newReleaseTestFixture(t)

	payload, err := json.Marshal(normalizeReleaseRecord(reservationReleaseRecord{Type: reservationReleaseType,
		Receipt: f.admission.receipt, ReleasedAt: f.now}))
	if err != nil {
		t.Fatal(err)
	}

	if _, err := decodeReleasePayload(payload); err != nil {
		t.Fatalf("canonical release rejected: %v", err)
	}

	if !bytes.HasPrefix(payload, []byte(`{"type":"release","receipt":{"intent":{"operation":"RevokeEgressLeaseV1",`)) ||
		!bytes.Contains(payload, []byte(`"generation_retired":true},"released_at":"`)) {
		t.Fatalf("release record format changed: %s", payload)
	}

	for name, bad := range map[string][]byte{
		"trailing JSON":    append(bytes.Clone(payload), []byte(` {}`)...),
		"extra whitespace": append(bytes.Clone(payload), ' '),
		"local time":       bytes.Replace(payload, []byte(`Z"}`), []byte(`+00:00"}`), 1),
	} {
		if _, err := decodeReleasePayload(bad); !errors.Is(err, ErrReservationJournalCorrupt) {
			t.Errorf("%s accepted", name)
		}
	}
}

// Full history simulated in memory, without thousands of signed admissions.
func TestReservationReleaseAtHistoryLimit(t *testing.T) {
	f := newReleaseTestFixture(t)

	state, err := parseReservationJournalRecords(f.journalBytes(t), f.journal.header, f.journal.authority)
	if err != nil {
		t.Fatal(err)
	}

	for i := 100000; len(state.seenIDs) < maxHistoricalReservations; i++ {
		owner := f.admission.hold.Owner
		owner.TunnelGeneration = fmt.Sprintf("tunnelgen_%032x", i)

		state.seenIDs[fmt.Sprintf("reservation_%032x", i)] = struct{}{}
		state.seenOwners[owner] = struct{}{}
	}

	next := testJournalHold(t, 2, 2, 2, "8.8.8.8")

	if err := state.checkNewHold(next); !errors.Is(err, ErrReservationLimit) {
		t.Fatalf("history capacity ignored: %v", err)
	}

	record := reservationReleaseRecord{Type: reservationReleaseType, Receipt: f.admission.receipt, ReleasedAt: f.now}
	if err := state.applyRelease(record, f.journal.authority); err != nil {
		t.Fatal("the history limit prevented a release:", err)
	}

	if len(state.registry.snapshot()) != 0 || len(state.seenIDs) != maxHistoricalReservations {
		t.Fatal("a release discarded history")
	}

	if err := state.checkNewHold(next); !errors.Is(err, ErrReservationLimit) {
		t.Fatal("a release freed history capacity")
	}
}

// The real limits on disk: a journal of every historical hold and all but one released fits the
// byte budget, refuses a new hold early and late, and still releases the last hold.
func TestReservationJournalFullHistory(t *testing.T) {
	if testing.Short() {
		t.Skip("writes the largest valid journal")
	}

	dir, authority, signer := newTestAuthority(t)

	journal, err := authority.journal()
	if err != nil {
		t.Fatal(err)
	}

	info := authority.Info()
	base := reservationTestBase
	data := []byte(journal.header)

	state, err := parseReservationJournalRecords(data, journal.header, journal.authority)
	if err != nil {
		t.Fatal(err)
	}

	tail := state.tail

	var last EgressReservation
	var lastCandidate candidateAdmission

	for i := 1; i <= maxHistoricalReservations; i++ {
		candidate := testReservationAdmission(t, i, i, i, fmt.Sprintf("8.8.%d.%d", i/250, i%250+1), base)

		registry := testRegistryAt(base.Add(11 * time.Second))

		hold, err := registry.reserve(candidate)
		if err != nil {
			t.Fatal(err)
		}

		frame, err := encodeReservationFrame(hold, tail)
		if err != nil {
			t.Fatal(err)
		}

		data = append(data, frame...)
		tail = reservationFrameDigest(tail, frame[:len(frame)-len(tail)])

		if i == maxHistoricalReservations {
			last, lastCandidate = normalizeReservationRecord(hold), candidate
			break
		}

		intent, err := revokeIntentFromHold(info, hold)
		if err != nil {
			t.Fatal(err)
		}

		release, err := encodeReleaseFrame(reservationReleaseRecord{
			Type: reservationReleaseType,
			Receipt: LabRevokedLeaseInfo{Intent: intent, HelperID: hold.Owner.HelperEpoch,
				PublicKeySHA256: hold.PublicKeySHA256, RevocationNonce: fmt.Sprintf("ffff%028x", i),
				GenerationRetired: true},
			ReleasedAt: base.Add(time.Minute),
		}, tail)
		if err != nil {
			t.Fatal(err)
		}

		data = append(data, release...)
		tail = reservationFrameDigest(tail, release[:len(release)-len(tail)])
	}

	// Room is left for exactly the last release.
	if len(data)+4+maxReservationRecordBytes+len(tail) > maxReservationJournalBytes {
		t.Fatalf("full history of %d bytes leaves no room for a release", len(data))
	}

	if err := os.WriteFile(filepath.Join(dir, reservationJournalFile), data, 0o600); err != nil {
		t.Fatal(err)
	}

	items, err := authority.List()
	if err != nil || len(items) != 1 || items[0].ID != last.ID {
		t.Fatalf("full history not replayed: %v", err)
	}

	if err := reservationPreflight(journal, "profile_ffffffffffffffff"); !errors.Is(err, ErrReservationLimit) {
		t.Fatalf("preflight ignored the history limit: %v", err)
	}

	next := testReservationAdmission(t, maxHistoricalReservations+1, 1, maxHistoricalReservations+1, "9.9.8.8",
		base.Add(2*time.Minute))
	if _, err := reserveDurableEgressJournal(context.Background(), journal, next,
		func() time.Time { return base.Add(2*time.Minute + 11*time.Second) }); !errors.Is(err, ErrReservationLimit) {
		t.Fatalf("hold beyond the history limit: %v", err)
	}

	admission := releaseAdmissionFor(t, info, signer, items[0], lastCandidate, base.Add(3*time.Minute))
	if _, err := releaseDurableEgressJournal(context.Background(), journal, admission,
		func() time.Time { return admission.receivedAt.Add(time.Second) }); err != nil {
		t.Fatalf("release at the history limit: %v", err)
	}

	if items, err := authority.List(); err != nil || len(items) != 0 {
		t.Fatalf("last hold not released: %v", err)
	}
}

func TestReservationReleaseConcurrent(t *testing.T) {
	f := newReleaseTestFixture(t)

	start := make(chan struct{})
	results := make(chan error, 2)

	var wg sync.WaitGroup

	for i := 0; i < 2; i++ {
		wg.Add(1)

		go func() {
			defer wg.Done()
			<-start

			_, err := f.release()
			results <- err
		}()
	}

	close(start)
	wg.Wait()
	close(results)

	released, refused := 0, 0

	for err := range results {
		switch {
		case err == nil:
			released++
		case errors.Is(err, ErrReservationBusy), errors.Is(err, ErrReservationNotFound):
			refused++
		default:
			t.Fatalf("unexpected release result: %v", err)
		}
	}

	if released != 1 || refused != 1 {
		t.Fatalf("atomic release violated: released=%d refused=%d", released, refused)
	}

	state, err := parseReservationJournalRecords(f.journalBytes(t), f.journal.header, f.journal.authority)
	if err != nil || len(state.registry.snapshot()) != 0 || len(state.seenIDs) != 1 {
		t.Fatalf("incorrect final ownership: %v", err)
	}
}

func TestReservationReleaseCanceled(t *testing.T) {
	f := newReleaseTestFixture(t)
	before := f.journalBytes(t)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	if _, err := releaseDurableEgressJournal(ctx, f.journal, f.admission, f.clock); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled release proceeded: %v", err)
	}

	if !bytes.Equal(before, f.journalBytes(t)) {
		t.Fatal("a canceled release wrote")
	}

	if items, err := f.authority.List(); err != nil || len(items) != 1 || items[0].ID != f.admission.hold.ID {
		t.Fatal("cancellation removed the hold")
	}
}

// The legacy V1 journal has no authority: it can never carry or commit a release.
func TestReservationReleaseNeedsAuthority(t *testing.T) {
	f := newReleaseTestFixture(t)

	legacy := f.journal
	legacy.authority = nil

	if _, err := releaseDurableEgressJournal(context.Background(), legacy, f.admission, f.clock); !errors.Is(err,
		ErrReservationUnavailable) {
		t.Fatalf("release without an authority: %v", err)
	}
}

func TestReservationReleaseEdgeCases(t *testing.T) {
	t.Run("released ID held by another owner", func(t *testing.T) {
		f := newReleaseTestFixture(t)

		if _, err := f.release(); err != nil {
			t.Fatal(err)
		}

		released := f.journalBytes(t)

		state, err := parseReservationJournalRecords(released, f.journal.header, f.journal.authority)
		if err != nil {
			t.Fatal(err)
		}

		other := testJournalHold(t, 2, 2, 2, "8.8.8.8")
		other.ID = f.admission.hold.ID

		frame, err := encodeReservationFrame(other, state.tail)
		if err != nil {
			t.Fatal(err)
		}

		if _, err := parseReservationJournalRecords(append(released, frame...), f.journal.header,
			f.journal.authority); !errors.Is(err, ErrReservationJournalCorrupt) {
			t.Fatalf("a released ID was reused: %v", err)
		}
	})

	t.Run("release record of another type", func(t *testing.T) {
		f := newReleaseTestFixture(t)

		state, err := parseReservationJournalRecords(f.journalBytes(t), f.journal.header, f.journal.authority)
		if err != nil {
			t.Fatal(err)
		}

		record := reservationReleaseRecord{Type: "force-release", Receipt: f.admission.receipt, ReleasedAt: f.now}
		if err := state.applyRelease(record, f.journal.authority); !errors.Is(err, ErrReservationJournalCorrupt) ||
			len(state.registry.snapshot()) != 1 {
			t.Fatalf("a record of another type released the hold: %v", err)
		}
	})

	t.Run("canceled during the transaction", func(t *testing.T) {
		f := newReleaseTestFixture(t)
		before := f.journalBytes(t)

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		now := func() time.Time {
			cancel()
			return f.now
		}

		if _, err := releaseDurableEgressJournal(ctx, f.journal, f.admission, now); !errors.Is(err, context.Canceled) ||
			!bytes.Equal(before, f.journalBytes(t)) {
			t.Fatalf("a release canceled before its write was written: %v", err)
		}
	})

	t.Run("header of another journal", func(t *testing.T) {
		f := newReleaseTestFixture(t)

		legacy := append([]byte(reservationJournalMagic), f.journalBytes(t)[len(f.journal.header):]...)
		if _, err := parseReservationJournalRecords(legacy, reservationJournalMagic, f.journal.authority); !errors.Is(err,
			ErrReservationAuthorityMismatch) {
			t.Fatalf("an authority replayed a journal with another header: %v", err)
		}
	})

	t.Run("binding with a stage", func(t *testing.T) {
		f := newReleaseTestFixture(t)

		binding := f.admission.receipt.Intent
		binding.Operation = LabPrepareEgressLeaseOp
		binding.StageID = "wgstage_0123456789abcdef0123456789abcdef"

		if _, err := NewLabRevokeEgressLeaseIntent(binding); !errors.Is(err, ErrReservationReleaseInvalid) {
			t.Fatal("a revocation built from a binding with extra fields")
		}
	})
}
