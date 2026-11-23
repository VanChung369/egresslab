package agent

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func activate(t *testing.T, registry *EgressCandidateRegistry, profile string) EgressCandidateStatus {
	t.Helper()

	status, err := registry.Activate(profile)
	if err != nil {
		t.Fatalf("activate %s: %v", profile, err)
	}

	if status.Status != "active" || status.NetworkReady {
		t.Fatalf("unexpected activation: %+v", status)
	}

	return status
}

func TestActivateRequiresCandidate(t *testing.T) {
	registry, _ := newTestCandidateRegistry(t)

	if _, err := registry.Activate(candidateProfileA); !errors.Is(err, ErrNoEgressCandidate) {
		t.Fatalf("activation without candidate: %v", err)
	}

	if _, err := registry.Activate("profile_bad"); !errors.Is(err, ErrInvalidObservation) {
		t.Fatalf("invalid profile accepted: %v", err)
	}
}

func TestStickyIPRejectsChangedObservation(t *testing.T) {
	registry, now := newTestCandidateRegistry(t)

	observe(t, registry, candidateProfileA, "1.1.1.1", *now)
	if pinned := activate(t, registry, candidateProfileA); pinned.PinnedIP != "1.1.1.1" {
		t.Fatalf("unexpected pin: %+v", pinned)
	}

	if again := observe(t, registry, candidateProfileA, "1.1.1.1", *now); again.Status != "active" {
		t.Fatalf("matching observation not reported active: %+v", again)
	}

	result, err := registry.Evaluate(EgressObservation{
		ProfileID: candidateProfileA, ObservedIP: "8.8.8.8", ObservedAt: *now,
	})
	if !errors.Is(err, ErrEgressIPChanged) || result.Status != "ip_changed" || result.PinnedIP != "1.1.1.1" ||
		result.CandidateIP != "8.8.8.8" || result.NetworkReady {
		t.Fatalf("changed IP not blocked: %+v %v", result, err)
	}

	// The lease survives the mismatch; the profile stays pinned to its original IP.
	if snap := registry.Snapshot(candidateProfileA); snap.Status != "active" || snap.PinnedIP != "1.1.1.1" {
		t.Fatalf("lease lost after mismatch: %+v", snap)
	}

	// The rejected IP was not recorded for anyone.
	observe(t, registry, candidateProfileB, "8.8.8.8", *now)
}

func TestActiveLeaseOutlivesCandidateTTL(t *testing.T) {
	registry, now := newTestCandidateRegistry(t)

	observe(t, registry, candidateProfileA, "1.1.1.1", *now)
	activate(t, registry, candidateProfileA)

	*now = now.Add(time.Hour)

	if snap := registry.Snapshot(candidateProfileA); snap.Status != "active" || snap.CandidateIP != "" {
		t.Fatalf("unexpected snapshot after TTL: %+v", snap)
	}

	if _, err := registry.Evaluate(EgressObservation{
		ProfileID: candidateProfileB, ObservedIP: "1.1.1.1", ObservedAt: *now,
	}); !errors.Is(err, ErrEgressIPCollision) {
		t.Fatalf("leased IP was handed to another profile: %v", err)
	}

	// An invalid refresh drops the candidate (existing fail-closed rule) but never the lease.
	if _, err := registry.Evaluate(EgressObservation{
		ProfileID: candidateProfileA, ObservedIP: "10.0.0.1", ObservedAt: *now,
	}); !errors.Is(err, ErrInvalidObservation) {
		t.Fatal(err)
	}

	if _, err := registry.Evaluate(EgressObservation{
		ProfileID: candidateProfileB, ObservedIP: "1.1.1.1", ObservedAt: *now,
	}); !errors.Is(err, ErrEgressIPCollision) {
		t.Fatalf("invalid refresh released the lease: %v", err)
	}

	if err := registry.Deactivate(candidateProfileA); err != nil {
		t.Fatal(err)
	}

	observe(t, registry, candidateProfileB, "1.1.1.1", *now)
}

func TestActivateIsIdempotentButNeverRepins(t *testing.T) {
	registry, now := newTestCandidateRegistry(t)

	observe(t, registry, candidateProfileA, "1.1.1.1", *now)
	activate(t, registry, candidateProfileA)
	activate(t, registry, candidateProfileA)

	if err := registry.Deactivate(candidateProfileB); err != nil {
		t.Fatalf("deactivating an inactive profile: %v", err)
	}
}

func TestLeasesPersistAcrossRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state", "egress-leases.json")

	first, err := OpenEgressCandidateRegistry(30*time.Second, path)
	if err != nil {
		t.Fatal(err)
	}

	now := time.Date(2026, 11, 23, 0, 0, 0, 0, time.UTC)
	first.now = func() time.Time { return now }

	observe(t, first, candidateProfileA, "1.1.1.1", now)
	activate(t, first, candidateProfileA)

	if runtime.GOOS != "windows" {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}

		if info.Mode().Perm() != 0o600 {
			t.Fatalf("lease file mode %v", info.Mode().Perm())
		}
	}

	second, err := OpenEgressCandidateRegistry(30*time.Second, path)
	if err != nil {
		t.Fatal(err)
	}
	second.now = func() time.Time { return now }

	if snap := second.Snapshot(candidateProfileA); snap.Status != "active" || snap.PinnedIP != "1.1.1.1" {
		t.Fatalf("lease not restored: %+v", snap)
	}

	if _, err := second.Evaluate(EgressObservation{
		ProfileID: candidateProfileB, ObservedIP: "1.1.1.1", ObservedAt: now,
	}); !errors.Is(err, ErrEgressIPCollision) {
		t.Fatalf("restored lease did not reserve its IP: %v", err)
	}

	if err := second.Deactivate(candidateProfileA); err != nil {
		t.Fatal(err)
	}

	third, err := OpenEgressCandidateRegistry(30*time.Second, path)
	if err != nil {
		t.Fatal(err)
	}

	if snap := third.Snapshot(candidateProfileA); snap.Status != "absent" {
		t.Fatalf("deactivation not persisted: %+v", snap)
	}
}

func TestLeaseFileValidation(t *testing.T) {
	const good = `{"version": 1, "leases": [{"profile_id": "profile_0123456789abcdef", "ip": "1.1.1.1", ` +
		`"pinned_at": "2026-11-23T00:00:00Z"}]}`

	path := filepath.Join(t.TempDir(), "leases.json")
	if err := os.WriteFile(path, []byte(good), 0o600); err != nil {
		t.Fatal(err)
	}

	if _, err := OpenEgressCandidateRegistry(30*time.Second, path); err != nil {
		t.Fatalf("valid lease file rejected: %v", err)
	}

	bad := map[string]string{
		"version":         strings.Replace(good, `"version": 1`, `"version": 2`, 1),
		"private IP":      strings.Replace(good, `1.1.1.1`, `10.0.0.1`, 1),
		"profile":         strings.Replace(good, `profile_0123456789abcdef`, `profile_x`, 1),
		"missing time":    strings.Replace(good, `"pinned_at": "2026-11-23T00:00:00Z"`, `"pinned_at": "0001-01-01T00:00:00Z"`, 1),
		"unknown field":   strings.Replace(good, `"version": 1`, `"version": 1, "extra": true`, 1),
		"trailing data":   good + "{}",
		"duplicate IP":    strings.Replace(good, `}]}`, `}, {"profile_id": "profile_fedcba9876543210", "ip": "1.1.1.1", "pinned_at": "2026-11-23T00:00:00Z"}]}`, 1),
		"duplicate owner": strings.Replace(good, `}]}`, `}, {"profile_id": "profile_0123456789abcdef", "ip": "8.8.8.8", "pinned_at": "2026-11-23T00:00:00Z"}]}`, 1),
	}

	for name, contents := range bad {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "leases.json")
			if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
				t.Fatal(err)
			}

			if _, err := OpenEgressCandidateRegistry(30*time.Second, path); err == nil {
				t.Fatal("invalid lease file accepted")
			}
		})
	}

	if runtime.GOOS != "windows" {
		loose := filepath.Join(t.TempDir(), "leases.json")
		if err := os.WriteFile(loose, []byte(good), 0o644); err != nil {
			t.Fatal(err)
		}

		// WriteFile honours the umask; make the mode explicit.
		if err := os.Chmod(loose, 0o644); err != nil {
			t.Fatal(err)
		}

		if _, err := OpenEgressCandidateRegistry(30*time.Second, loose); err == nil {
			t.Fatal("world-readable lease file accepted")
		}
	}

	if _, err := OpenEgressCandidateRegistry(30*time.Second, ""); err == nil {
		t.Fatal("empty lease path accepted")
	}
}

func TestFailedLeasePersistRollsBack(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "state")

	registry, err := OpenEgressCandidateRegistry(30*time.Second, filepath.Join(dir, "leases.json"))
	if err != nil {
		t.Fatal(err)
	}

	// Break saving after a successful open: the lease directory becomes a regular file.
	if err := os.WriteFile(dir, nil, 0o600); err != nil {
		t.Fatal(err)
	}

	now := time.Date(2026, 11, 23, 0, 0, 0, 0, time.UTC)
	registry.now = func() time.Time { return now }

	observe(t, registry, candidateProfileA, "1.1.1.1", now)

	if _, err := registry.Activate(candidateProfileA); err == nil {
		t.Fatal("activation succeeded although the lease could not be persisted")
	}

	if snap := registry.Snapshot(candidateProfileA); snap.Status != "candidate" {
		t.Fatalf("failed activation left a lease behind: %+v", snap)
	}
}
