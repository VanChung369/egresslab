//go:build windows || linux || darwin

package control

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
)

func newTestAuthority(t *testing.T) (string, *ReservationAuthority, *seedSigner) {
	t.Helper()

	dir := t.TempDir()
	signer := newSeedSigner()

	if _, err := InitializeReservationAuthority(dir, signer); err != nil {
		t.Fatal(err)
	}

	authority, err := OpenReservationAuthority(dir, signer)
	if err != nil {
		t.Fatal(err)
	}

	return dir, authority, signer
}

func TestReservationAuthorityInitialization(t *testing.T) {
	dir := t.TempDir()
	signer := newSeedSigner()

	if _, err := OpenReservationAuthority(dir, signer); err == nil {
		t.Fatal("missing authority accepted")
	}

	for _, bad := range []string{"", "relative"} {
		if _, err := InitializeReservationAuthority(bad, signer); !errors.Is(err, ErrReservationUnavailable) {
			t.Fatalf("initialized under %q: %v", bad, err)
		}
	}

	info, err := InitializeReservationAuthority(dir, signer)
	if err != nil || !info.valid() {
		t.Fatalf("initialization failed: %+v %v", info, err)
	}

	authority, err := OpenReservationAuthority(dir, signer)
	if err != nil || authority.Info() != info {
		t.Fatalf("authority identity changed: %v", err)
	}

	if items, err := authority.List(); err != nil || len(items) != 0 {
		t.Fatal("new authority is not empty")
	}

	marker, err := os.ReadFile(filepath.Join(dir, reservationAuthorityFile))
	if err != nil {
		t.Fatal(err)
	}

	header, err := authorityJournalHeader(info)
	if err != nil {
		t.Fatal(err)
	}

	journal, err := os.ReadFile(filepath.Join(dir, reservationJournalFile))
	if err != nil || string(journal) != header || !strings.HasPrefix(header, reservationAuthorityJournalMagic) {
		t.Fatalf("journal not bound to its marker: %q", journal)
	}

	if _, err := InitializeReservationAuthority(dir, signer); !errors.Is(err, ErrReservationAuthorityExists) {
		t.Fatalf("authority initialized twice: %v", err)
	}

	if again, err := os.ReadFile(filepath.Join(dir, reservationAuthorityFile)); err != nil || !bytes.Equal(again, marker) {
		t.Fatal("refused initialization changed the marker")
	}

	wrongSigner := &seedSigner{private: ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x99}, ed25519.SeedSize))}
	if _, err := OpenReservationAuthority(dir, wrongSigner); !errors.Is(err, ErrReservationAuthorityMismatch) {
		t.Fatalf("foreign controller key accepted: %v", err)
	}

	if signer.signs != 0 || wrongSigner.signs != 0 {
		t.Fatal("provisioning signed something")
	}
}

// Storage loss is refused, also by an authority opened before the loss, and never repaired.
func TestReservationAuthorityMissingFiles(t *testing.T) {
	for _, missing := range []string{reservationAuthorityFile, reservationJournalFile} {
		t.Run(missing, func(t *testing.T) {
			dir, authority, signer := newTestAuthority(t)
			path := filepath.Join(dir, missing)

			// Simulated loss, in a test directory only.
			if err := os.Remove(path); err != nil {
				t.Fatal(err)
			}

			if _, err := authority.List(); err == nil {
				t.Fatal("opened authority ignored the missing file")
			}

			if _, err := OpenReservationAuthority(dir, signer); err == nil {
				t.Fatal("incomplete authority reopened")
			}

			if _, err := InitializeReservationAuthority(dir, signer); !errors.Is(err, ErrReservationAuthorityExists) {
				t.Fatalf("incomplete authority recreated: %v", err)
			}

			if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("missing file recreated")
			}
		})
	}
}

// Two authorities with the same key, different IDs and directories: B's journal is not A's.
func TestReservationAuthorityForeignJournal(t *testing.T) {
	dirA, _, signer := newTestAuthority(t)
	dirB, _, _ := newTestAuthority(t)

	data, err := os.ReadFile(filepath.Join(dirB, reservationJournalFile))
	if err != nil {
		t.Fatal(err)
	}

	if err := os.WriteFile(filepath.Join(dirA, reservationJournalFile), data, 0o600); err != nil {
		t.Fatal(err)
	}

	if _, err := OpenReservationAuthority(dirA, signer); !errors.Is(err, ErrReservationJournalCorrupt) {
		t.Fatalf("foreign journal accepted: %v", err)
	}
}

// A marker and journal copied elsewhere name their original directory.
func TestReservationAuthorityDirectoryBinding(t *testing.T) {
	dir, _, signer := newTestAuthority(t)
	other := t.TempDir()

	for _, name := range []string{reservationAuthorityFile, reservationJournalFile} {
		data, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}

		if err := os.WriteFile(filepath.Join(other, name), data, 0o600); err != nil {
			t.Fatal(err)
		}
	}

	if _, err := OpenReservationAuthority(other, signer); !errors.Is(err, ErrReservationAuthorityMismatch) {
		t.Fatalf("copied authority opened in another directory: %v", err)
	}
}

func TestReservationAuthorityMarkerStrictness(t *testing.T) {
	for name, edit := range map[string]func([]byte) []byte{
		"empty":         func([]byte) []byte { return nil },
		"trailing byte": func(m []byte) []byte { return append(m, '\n') },
		"unknown field": func(m []byte) []byte { return append(m[:len(m)-1], []byte(`,"force":true}`)...) },
		"indented":      func(m []byte) []byte { var b bytes.Buffer; _ = json.Indent(&b, m, "", " "); return b.Bytes() },
		"other version": func(m []byte) []byte { return bytes.Replace(m, []byte(`"version":1`), []byte(`"version":2`), 1) },
		"duplicate id":  func(m []byte) []byte { return bytes.Replace(m, []byte(`"id":`), []byte(`"id":"authority_x","id":`), 1) },
		"not JSON":      func([]byte) []byte { return []byte("authority") },
	} {
		t.Run(name, func(t *testing.T) {
			dir, _, signer := newTestAuthority(t)
			path := filepath.Join(dir, reservationAuthorityFile)

			marker, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}

			if err := os.WriteFile(path, edit(bytes.Clone(marker)), 0o600); err != nil {
				t.Fatal(err)
			}

			if _, err := OpenReservationAuthority(dir, signer); !errors.Is(err, ErrReservationAuthorityMismatch) {
				t.Fatalf("malformed marker accepted: %v", err)
			}
		})
	}
}

// Every operation re-reads the marker: another valid identity in place of the one opened is refused.
func TestReservationAuthorityMarkerReplaced(t *testing.T) {
	dir, authority, _ := newTestAuthority(t)

	replaced := authority.Info()
	replaced.ID = "authority_ffffffffffffffffffffffffffffffff"

	payload, err := json.Marshal(replaced)
	if err != nil {
		t.Fatal(err)
	}

	if err := os.WriteFile(filepath.Join(dir, reservationAuthorityFile), payload, 0o600); err != nil {
		t.Fatal(err)
	}

	if _, err := authority.List(); !errors.Is(err, ErrReservationAuthorityMismatch) {
		t.Fatalf("replaced marker accepted: %v", err)
	}
}

func TestReservationAuthorityRejectsLegacyJournal(t *testing.T) {
	dir := newTestReservationJournal(t)
	signer := newSeedSigner()

	if _, err := InitializeReservationAuthority(dir, signer); !errors.Is(err, ErrReservationAuthorityExists) {
		t.Fatalf("existing V1 journal overwritten: %v", err)
	}

	if _, err := OpenReservationAuthority(dir, signer); err == nil {
		t.Fatal("V1 journal opened as a production authority")
	}
}

func TestReservationAuthorityConcurrentInitialization(t *testing.T) {
	dir := t.TempDir()

	const contenders = 8

	start := make(chan struct{})
	results := make(chan error, contenders)

	var wg sync.WaitGroup
	for range contenders {
		wg.Add(1)

		go func() {
			defer wg.Done()
			<-start

			_, err := InitializeReservationAuthority(dir, newSeedSigner())
			results <- err
		}()
	}

	close(start)
	wg.Wait()
	close(results)

	success := 0
	for err := range results {
		if err == nil {
			success++
		} else if !errors.Is(err, ErrReservationAuthorityExists) && !errors.Is(err, ErrReservationBusy) {
			t.Errorf("unexpected initializer failure: %v", err)
		}
	}

	if success != 1 {
		t.Fatalf("expected one initializer, got %d", success)
	}

	authority, err := OpenReservationAuthority(dir, newSeedSigner())
	if err != nil {
		t.Fatal(err)
	}

	if items, err := authority.List(); err != nil || len(items) != 0 {
		t.Fatal("invalid final authority state")
	}
}

func TestReservationAuthorityPersistentOwnership(t *testing.T) {
	dir, authority, signer := newTestAuthority(t)
	info := authority.Info()

	journal, err := authority.journal()
	if err != nil {
		t.Fatal(err)
	}

	base := reservationTestBase
	clock := func() time.Time { return base.Add(11 * time.Second) }

	first, err := reserveDurableEgressJournal(context.Background(), journal,
		testReservationAdmission(t, 1, 1, 1, "8.8.4.4", base), clock)
	if err != nil {
		t.Fatal(err)
	}

	reopened, err := OpenReservationAuthority(dir, signer)
	if err != nil || reopened.Info() != info {
		t.Fatalf("authority identity lost: %v", err)
	}

	items, err := reopened.List()
	if err != nil || len(items) != 1 || items[0].ID != first.ID || items[0].FreshAt(clock()) {
		t.Fatalf("incorrect recovered ownership: %v", err)
	}

	journal, err = reopened.journal()
	if err != nil {
		t.Fatal(err)
	}

	if _, err := reserveDurableEgressJournal(context.Background(), journal,
		testReservationAdmission(t, 2, 2, 2, "8.8.4.4", base), clock); !errors.Is(err, ErrReservationIPCollision) {
		t.Fatalf("persistent collision not enforced: %v", err)
	}

	// An admission for another controller key never reaches this authority's journal.
	foreign := testReservationAdmission(t, 3, 3, 3, "8.8.8.8", base)
	foreign.runtime.PublicKeySHA256 = strings.Repeat("f", 64)

	if _, err := reserveDurableEgressJournal(context.Background(), journal, foreign, clock); !errors.Is(err, ErrReservationAuthorityMismatch) {
		t.Fatalf("foreign-key admission: %v", err)
	}

	if items, err := reopened.List(); err != nil || len(items) != 1 {
		t.Fatalf("refused admissions changed the journal: %v", err)
	}
}

// A well-formed hold for another controller key makes the whole journal unusable.
func TestReservationAuthorityRejectsForeignKeyHold(t *testing.T) {
	dir, authority, _ := newTestAuthority(t)

	hold := testJournalHold(t, 1, 1, 1, "8.8.4.4")
	hold.PublicKeySHA256 = strings.Repeat("f", 64)

	journal, err := authority.journal()
	if err != nil {
		t.Fatal(err)
	}

	state, err := parseReservationJournalWithHeader([]byte(journal.header), journal.header)
	if err != nil {
		t.Fatal(err)
	}

	frame, err := encodeReservationFrame(hold, state.tail)
	if err != nil {
		t.Fatal(err)
	}

	if err := os.WriteFile(filepath.Join(dir, reservationJournalFile), append([]byte(journal.header), frame...), 0o600); err != nil {
		t.Fatal(err)
	}

	if _, err := authority.List(); !errors.Is(err, ErrReservationAuthorityMismatch) {
		t.Fatalf("foreign-key hold accepted: %v", err)
	}
}

// Every operation locks the marker, then the journal; either lock held elsewhere means busy.
func TestReservationAuthorityBusy(t *testing.T) {
	for _, name := range []string{reservationAuthorityFile, reservationJournalFile} {
		t.Run(name, func(t *testing.T) {
			dir, authority, signer := newTestAuthority(t)

			file, err := openLockedReservationJournal(filepath.Join(dir, name), false)
			if err != nil {
				t.Fatal(err)
			}
			defer file.Close()

			if _, err := authority.List(); !errors.Is(err, ErrReservationBusy) {
				t.Fatalf("list under a held lock: %v", err)
			}

			if _, err := OpenReservationAuthority(dir, signer); !errors.Is(err, ErrReservationBusy) {
				t.Fatalf("open under a held lock: %v", err)
			}
		})
	}
}

// Readers share both locks; a reader still excludes every writer.
func TestReservationAuthorityReadersShare(t *testing.T) {
	for _, name := range []string{reservationAuthorityFile, reservationJournalFile} {
		t.Run(name, func(t *testing.T) {
			dir, authority, signer := newTestAuthority(t)

			file, err := openLockedReservationFile(filepath.Join(dir, name), false, true)
			if err != nil {
				t.Fatal(err)
			}
			defer file.Close()

			if _, err := authority.List(); err != nil {
				t.Fatalf("list beside a reader: %v", err)
			}

			if _, err := OpenReservationAuthority(dir, signer); err != nil {
				t.Fatalf("open beside a reader: %v", err)
			}

			journal, err := authority.journal()
			if err != nil {
				t.Fatal(err)
			}

			if handle, err := journal.open(); !errors.Is(err, ErrReservationBusy) {
				if err == nil {
					_ = handle.Close()
				}

				t.Fatalf("write lock beside a reader: %v", err)
			}
		})
	}
}

// Concurrent reservations through one authority, with the marker and journal locks in turn. A
// contender that finds the authority busy tries again (tests only; production never retries), so
// exactly one is granted and every other one ends in a collision.
func TestReservationAuthorityConcurrentReservations(t *testing.T) {
	_, authority, _ := newTestAuthority(t)
	base := reservationTestBase
	clock := func() time.Time { return base.Add(11 * time.Second) }

	const contenders = 8

	admissions := make([]candidateAdmission, contenders)
	for i := range admissions {
		admissions[i] = testReservationAdmission(t, i+1, i+1, i+1, "8.8.4.4", base)
	}

	journal, err := authority.journal()
	if err != nil {
		t.Fatal(err)
	}

	start := make(chan struct{})
	results := make(chan error, contenders)

	var wg sync.WaitGroup
	for _, a := range admissions {
		wg.Add(1)

		go func() {
			defer wg.Done()
			<-start

			for attempt := 0; ; attempt++ {
				_, err := reserveDurableEgressJournal(context.Background(), journal, a, clock)
				if !errors.Is(err, ErrReservationBusy) || attempt == 10000 {
					results <- err
					return
				}

				time.Sleep(time.Millisecond)
			}
		}()
	}

	close(start)
	wg.Wait()
	close(results)

	granted, collisions := 0, 0
	for err := range results {
		switch {
		case err == nil:
			granted++
		case errors.Is(err, ErrReservationIPCollision):
			collisions++
		default:
			t.Errorf("unexpected contender result: %v", err)
		}
	}

	if items, err := authority.List(); err != nil || granted != 1 || collisions != contenders-1 || len(items) != 1 {
		t.Fatalf("granted %d, collisions %d, holds %d: %v", granted, collisions, len(items), err)
	}
}

// Readers polling the authority while it is provisioned never make the initializer fail or leave a
// partial marker or journal behind.
func TestReservationAuthorityInitializationWithReaders(t *testing.T) {
	dir := t.TempDir()
	signer := newSeedSigner()

	done := make(chan struct{})

	var wg sync.WaitGroup
	for range 4 {
		wg.Add(1)

		go func() {
			defer wg.Done()

			for {
				select {
				case <-done:
					return
				default:
					_, _ = OpenReservationAuthority(dir, signer)
				}
			}
		}()
	}

	_, err := InitializeReservationAuthority(dir, signer)
	close(done)
	wg.Wait()

	if err != nil {
		t.Fatalf("initialization failed under readers: %v", err)
	}

	if _, err := OpenReservationAuthority(dir, signer); err != nil {
		t.Fatalf("authority unusable after initialization: %v", err)
	}

	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) != 2 {
		t.Fatalf("leftover files after initialization: %v %v", entries, err)
	}
}

// An operation holds the marker as well as the journal for its whole duration.
func TestReservationAuthorityHoldsMarker(t *testing.T) {
	dir, authority, _ := newTestAuthority(t)

	journal, err := authority.journal()
	if err != nil {
		t.Fatal(err)
	}

	handle, err := journal.open()
	if err != nil {
		t.Fatal(err)
	}
	defer handle.Close()

	if _, err := loadReservationAuthorityInfo(dir); !errors.Is(err, ErrReservationBusy) {
		t.Fatalf("marker not held during the operation: %v", err)
	}

	// Without FILE_SHARE_DELETE, Windows refuses to rename a marker that is open.
	if runtime.GOOS == "windows" {
		if err := os.Rename(filepath.Join(dir, reservationAuthorityFile), filepath.Join(dir, "moved.json")); err == nil {
			t.Fatal("marker renamed during an operation")
		}
	}
}

// A trust context for another controller key is refused before any runtime call, even when it is
// consistent in itself and the signer holds that key.
func TestReservationAuthorityRefusesForeignKeyFlow(t *testing.T) {
	_, authority, _ := newTestAuthority(t)
	transport, trust, _ := newReservationFlowFixture(t, 1, "8.8.4.4")

	other := &seedSigner{private: ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x24}, ed25519.SeedSize))}
	public, err := other.PublicKey()
	if err != nil {
		t.Fatal(err)
	}

	trust.Runtime.PublicKeySHA256 = LabPublicKeySHA256(public)
	trust.Helper.PublicKeySHA256 = trust.Runtime.PublicKeySHA256

	_, err = authority.ReserveVerifiedEgress(context.Background(), transport, other, trust)
	if !errors.Is(err, ErrReservationAuthorityMismatch) || len(transport.calls) != 0 || other.signs != 0 {
		t.Fatalf("foreign-key flow: %v after %v", err, transport.calls)
	}
}
