package control

import (
	"errors"
	"net/netip"
	"sync"
	"testing"
	"time"
)

// assertReservationIndexes checks the four indexes agree, not just the outcome of a call.
func assertReservationIndexes(t *testing.T, r *egressReservationRegistry, expected int) {
	t.Helper()

	r.mu.Lock()
	defer r.mu.Unlock()

	if len(r.byOwner) != expected || len(r.byIP) != expected || len(r.byProfile) != expected || len(r.byID) != expected {
		t.Fatalf("inconsistent indexes: owner=%d IP=%d profile=%d ID=%d",
			len(r.byOwner), len(r.byIP), len(r.byProfile), len(r.byID))
	}

	for owner, reservation := range r.byOwner {
		if reservation.Owner != owner ||
			r.byIP[reservation.IPv4] != owner ||
			r.byProfile[owner.ProfileID] != owner ||
			r.byID[reservation.ID] != owner {
			t.Fatal("reservation indexes disagree")
		}
	}
}

func testRegistryAt(now time.Time) *egressReservationRegistry {
	r := newEgressReservationRegistry()
	r.now = func() time.Time { return now }

	return r
}

func TestReservationCollisionAcrossRuntimes(t *testing.T) {
	base := reservationTestBase
	registry := testRegistryAt(base.Add(11 * time.Second))

	a := testReservationAdmission(t, 1, 1, 1, "8.8.4.4", base)
	b := testReservationAdmission(t, 2, 2, 2, "8.8.4.4", base)

	first, err := registry.reserve(a)
	if err != nil {
		t.Fatal(err)
	}

	if first.ID == "" || first.Owner.RuntimeID != a.runtime.ID || first.Owner.ProfileID != a.profile.ID ||
		first.IPv4 != a.probe.IPv4 || !first.FreshAt(base.Add(11*time.Second)) {
		t.Fatal("invalid first reservation")
	}

	second, err := registry.reserve(b)
	if !errors.Is(err, ErrReservationIPCollision) || second != (EgressReservation{}) {
		t.Fatalf("duplicate address reserved: %+v %v", second, err)
	}

	if current, exists := registry.lookupByIP(first.IPv4); !exists || current != first {
		t.Fatal("the collision replaced the existing owner")
	}

	assertReservationIndexes(t, registry, 1)
}

func TestReservationDistinctIPs(t *testing.T) {
	base := reservationTestBase
	registry := testRegistryAt(base.Add(11 * time.Second))

	first, err := registry.reserve(testReservationAdmission(t, 1, 1, 1, "8.8.4.4", base))
	if err != nil {
		t.Fatal(err)
	}

	second, err := registry.reserve(testReservationAdmission(t, 2, 2, 2, "8.8.8.8", base))
	if err != nil {
		t.Fatal(err)
	}

	if first.ID == second.ID || first.Owner == second.Owner || first.IPv4 == second.IPv4 {
		t.Fatal("independent reservation identity reused")
	}

	for _, reservation := range []EgressReservation{first, second} {
		byIP, ipExists := registry.lookupByIP(reservation.IPv4)
		byOwner, ownerExists := registry.lookupByOwner(reservation.Owner)
		byID, idExists := registry.lookupByID(reservation.ID)

		if !ipExists || !ownerExists || !idExists || byIP != reservation || byOwner != reservation || byID != reservation {
			t.Fatal("reservation lookup mismatch")
		}
	}

	if _, exists := registry.lookupByID("reservation_" + "0123456789abcdef0123456789abcdef"); exists {
		t.Fatal("unknown reservation ID found")
	}

	assertReservationIndexes(t, registry, 2)
}

func TestReservationCannotOverwriteOwner(t *testing.T) {
	base := reservationTestBase
	registry := testRegistryAt(base.Add(11 * time.Second))

	a := testReservationAdmission(t, 1, 1, 1, "8.8.4.4", base)

	first, err := registry.reserve(a)
	if err != nil {
		t.Fatal(err)
	}

	for name, tt := range map[string]struct {
		admission candidateAdmission
		want      error
	}{
		"same receipt again":                {a, ErrReservationOwnerHeld},
		"same owner, other address":         {testReservationAdmission(t, 1, 1, 1, "8.8.8.8", base), ErrReservationOwnerHeld},
		"reconnect with another generation": {testReservationAdmission(t, 1, 1, 2, "8.8.8.8", base), ErrReservationProfileHeld},
		"profile moved to another runtime":  {testReservationAdmission(t, 1, 2, 3, "8.8.8.8", base), ErrReservationProfileHeld},
	} {
		if _, err := registry.reserve(tt.admission); !errors.Is(err, tt.want) {
			t.Errorf("%s: %v, want %v", name, err, tt.want)
		}
	}

	if current, exists := registry.lookupByID(first.ID); !exists || current != first {
		t.Fatal("the original reservation changed")
	}

	assertReservationIndexes(t, registry, 1)
}

func TestReservationConcurrentCollision(t *testing.T) {
	const contenders = 16

	base := reservationTestBase
	registry := testRegistryAt(base.Add(11 * time.Second))

	// Every signed attempt is prepared before the race starts.
	admissions := make([]candidateAdmission, 0, contenders)
	for i := 1; i <= contenders; i++ {
		admissions = append(admissions, testReservationAdmission(t, i, i, i, "8.8.4.4", base))
	}

	type result struct {
		reservation EgressReservation
		err         error
	}

	start := make(chan struct{})
	results := make(chan result, contenders)

	var wg sync.WaitGroup

	for _, admission := range admissions {
		wg.Add(1)

		go func() {
			defer wg.Done()
			<-start

			reservation, err := registry.reserve(admission)
			results <- result{reservation, err}
		}()
	}

	close(start)
	wg.Wait()
	close(results)

	granted, collisions := 0, 0

	var winner EgressReservation

	for r := range results {
		if r.err == nil {
			granted++
			winner = r.reservation

			continue
		}

		if !errors.Is(r.err, ErrReservationIPCollision) {
			t.Fatalf("unexpected refusal: %v", r.err)
		}

		if r.reservation != (EgressReservation{}) {
			t.Fatal("a refused reservation returned ownership")
		}

		collisions++
	}

	if granted != 1 || collisions != contenders-1 {
		t.Fatalf("atomic uniqueness violated: granted=%d collisions=%d", granted, collisions)
	}

	if current, exists := registry.lookupByIP(netip.MustParseAddr("8.8.4.4")); !exists || current != winner {
		t.Fatal("the registry does not hold the winner")
	}

	assertReservationIndexes(t, registry, 1)
}

func TestReservationExpiryDoesNotReleaseIP(t *testing.T) {
	base := reservationTestBase
	now := base.Add(11 * time.Second)

	registry := newEgressReservationRegistry()
	registry.now = func() time.Time { return now }

	first, err := registry.reserve(testReservationAdmission(t, 1, 1, 1, "8.8.4.4", base))
	if err != nil {
		t.Fatal(err)
	}

	if !first.FreshAt(now) {
		t.Fatal("initial reservation not fresh")
	}

	now = base.Add(2 * time.Minute)

	if first.FreshAt(now) {
		t.Fatal("expired reservation still eligible")
	}

	// Another profile sees the same address, with fresh evidence of its own.
	freshBase := now.Add(-11 * time.Second)

	if _, err := registry.reserve(testReservationAdmission(t, 2, 2, 2, "8.8.4.4", freshBase)); !errors.Is(err, ErrReservationIPCollision) {
		t.Fatalf("expired reservation released its address: %v", err)
	}

	if held, exists := registry.lookupByIP(first.IPv4); !exists || held != first {
		t.Fatal("expired reservation forgotten")
	}

	if _, err := registry.reserve(testReservationAdmission(t, 3, 3, 3, "8.8.8.8", freshBase)); err != nil {
		t.Fatal(err)
	}

	if items := registry.snapshot(); len(items) != 2 {
		t.Fatalf("snapshot dropped the expired hold: %d", len(items))
	}

	assertReservationIndexes(t, registry, 2)
}

func TestReservationExpiresBeforeCommit(t *testing.T) {
	base := reservationTestBase
	a := testReservationAdmission(t, 1, 1, 1, "8.8.4.4", base)

	registry := newEgressReservationRegistry()
	calls := 0
	registry.now = func() time.Time {
		calls++
		if calls == 1 {
			return base.Add(11 * time.Second)
		}

		// The eligibility deadline is reached at the commit point.
		return base.Add(55 * time.Second)
	}

	reservation, err := registry.reserve(a)
	if !errors.Is(err, ErrReservationCandidateExpired) || reservation != (EgressReservation{}) {
		t.Fatalf("expired candidate committed: %+v %v", reservation, err)
	}

	assertReservationIndexes(t, registry, 0)
}

func TestReservationCapacityDoesNotEvict(t *testing.T) {
	base := reservationTestBase
	registry := testRegistryAt(base.Add(11 * time.Second))
	registry.limit = 1

	first, err := registry.reserve(testReservationAdmission(t, 1, 1, 1, "8.8.4.4", base))
	if err != nil {
		t.Fatal(err)
	}

	if _, err := registry.reserve(testReservationAdmission(t, 2, 2, 2, "8.8.8.8", base)); !errors.Is(err, ErrReservationLimit) {
		t.Fatalf("registry limit not enforced: %v", err)
	}

	snapshot := registry.snapshot()
	if len(snapshot) != 1 || snapshot[0] != first {
		t.Fatal("the capacity refusal evicted a hold")
	}

	// Changing the returned copy does not change the registry.
	snapshot[0].IPv4 = netip.MustParseAddr("8.8.8.8")
	snapshot[0].Owner.ProfileID = "profile_ffffffffffffffff"

	if current, exists := registry.lookupByID(first.ID); !exists || current != first {
		t.Fatal("the snapshot changed registry ownership")
	}

	assertReservationIndexes(t, registry, 1)
}

func TestReservationInvalidAdmissionNoMutation(t *testing.T) {
	base := reservationTestBase
	registry := testRegistryAt(base.Add(11 * time.Second))

	a := testReservationAdmission(t, 1, 1, 1, "8.8.4.4", base)
	a.receipt.IPv4 = netip.MustParseAddr("8.8.8.8")

	reservation, err := registry.reserve(a)
	if !errors.Is(err, ErrReservationCandidateInvalid) || reservation != (EgressReservation{}) {
		t.Fatalf("invalid receipt created a reservation: %+v %v", reservation, err)
	}

	assertReservationIndexes(t, registry, 0)
}

func TestReservationRegistryFailsClosed(t *testing.T) {
	base := reservationTestBase
	a := testReservationAdmission(t, 1, 1, 1, "8.8.4.4", base)

	var nilRegistry *egressReservationRegistry
	if _, err := nilRegistry.reserve(a); !errors.Is(err, ErrReservationUnavailable) {
		t.Fatalf("nil registry: %v", err)
	}

	// Indexes that disagree refuse every request.
	broken := testRegistryAt(base.Add(11 * time.Second))
	broken.byIP[netip.MustParseAddr("8.8.8.8")] = LeaseOwner{}

	if _, err := broken.reserve(a); !errors.Is(err, ErrReservationUnavailable) {
		t.Fatalf("inconsistent indexes: %v", err)
	}

	// A wall clock diverging from the monotonic one cannot be built through the time API; these
	// cover order and unset times.
	start := time.Now()

	if !stableReservationClock(start, start.Add(time.Millisecond)) {
		t.Fatal("forward progress refused")
	}

	if stableReservationClock(start, start.Add(-time.Millisecond)) || stableReservationClock(time.Time{}, start) {
		t.Fatal("backwards or unset time accepted")
	}
}
