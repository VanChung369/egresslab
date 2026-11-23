package agent

import (
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"
)

const (
	candidateProfileA = "profile_0123456789abcdef"
	candidateProfileB = "profile_fedcba9876543210"
)

func newTestCandidateRegistry(t *testing.T) (*EgressCandidateRegistry, *time.Time) {
	t.Helper()

	registry, err := NewEgressCandidateRegistry(30 * time.Second)
	if err != nil {
		t.Fatal(err)
	}

	now := time.Date(2026, 11, 23, 0, 0, 0, 0, time.UTC)
	registry.now = func() time.Time { return now }

	return registry, &now
}

func observe(t *testing.T, registry *EgressCandidateRegistry, profile, ip string, at time.Time) EgressCandidateStatus {
	t.Helper()

	result, err := registry.Evaluate(EgressObservation{ProfileID: profile, ObservedIP: ip, ObservedAt: at})
	if err != nil {
		t.Fatalf("observe %s for %s: %v", ip, profile, err)
	}

	return result
}

func TestCandidateRegistryTTL(t *testing.T) {
	for _, ttl := range []time.Duration{0, -time.Second, time.Minute + time.Nanosecond} {
		if _, err := NewEgressCandidateRegistry(ttl); err == nil {
			t.Errorf("TTL %v accepted", ttl)
		}
	}

	if _, err := NewEgressCandidateRegistry(time.Minute); err != nil {
		t.Fatal(err)
	}
}

func TestCandidateAcceptsPublicIPv4ButNeverReady(t *testing.T) {
	registry, now := newTestCandidateRegistry(t)

	result := observe(t, registry, candidateProfileA, "1.1.1.1", *now)

	if result.Status != "candidate" || result.NetworkReady || result.CandidateIP != "1.1.1.1" {
		t.Fatalf("unexpected result: %+v", result)
	}

	if result.ExpiresAt == nil || !result.ExpiresAt.Equal(now.Add(30*time.Second)) {
		t.Fatalf("unexpected expiry: %v", result.ExpiresAt)
	}
}

func TestCandidateRejectsNonPublicIP(t *testing.T) {
	addresses := []string{
		"",
		"127.0.0.1",
		"10.0.0.1",
		"172.16.0.1",
		"192.168.1.1",
		"100.64.0.2",
		"169.254.0.1",
		"0.1.2.3",
		"192.0.0.8",
		"192.0.2.10",
		"192.88.99.1",
		"198.18.0.1",
		"198.51.100.3",
		"203.0.113.4",
		"224.0.0.1",
		"240.0.0.1",
		"255.255.255.255",
		"::1",
		"2001:db8::1",
		"2606:4700:4700::1111",
		"::ffff:1.1.1.1",
		"1.1.1.1\n",
		" 1.1.1.1",
		"1.1.1.1/32",
		"001.001.001.001",
		"example.com",
	}

	for _, address := range addresses {
		t.Run(address, func(t *testing.T) {
			registry, now := newTestCandidateRegistry(t)

			result, err := registry.Evaluate(EgressObservation{
				ProfileID:  candidateProfileA,
				ObservedIP: address,
				ObservedAt: *now,
			})

			if !errors.Is(err, ErrInvalidObservation) || result.NetworkReady || result.Status != "rejected" {
				t.Fatalf("IP %q: result=%+v error=%v", address, result, err)
			}

			if result.ExpiresAt != nil || result.CandidateIP != "" {
				t.Fatalf("rejected result carries candidate data: %+v", result)
			}
		})
	}
}

func TestCandidateRejectsCollision(t *testing.T) {
	registry, now := newTestCandidateRegistry(t)

	observe(t, registry, candidateProfileA, "1.1.1.1", *now)

	result, err := registry.Evaluate(EgressObservation{
		ProfileID:  candidateProfileB,
		ObservedIP: "1.1.1.1",
		ObservedAt: *now,
	})

	if !errors.Is(err, ErrEgressIPCollision) {
		t.Fatalf("expected collision, got %v", err)
	}

	if result.Status != "collision" || result.NetworkReady || result.CandidateIP != "" {
		t.Fatalf("unexpected result: %+v", result)
	}

	if registry.Snapshot(candidateProfileA).Status != "candidate" {
		t.Fatal("first candidate was lost")
	}

	if registry.Snapshot(candidateProfileB).Status != "absent" {
		t.Fatal("colliding candidate was registered")
	}
}

func TestCandidateExpiryAndReplacement(t *testing.T) {
	registry, now := newTestCandidateRegistry(t)

	observe(t, registry, candidateProfileA, "1.1.1.1", *now)

	*now = now.Add(30 * time.Second)

	if registry.Snapshot(candidateProfileA).Status != "absent" {
		t.Fatal("expired candidate was retained")
	}

	observe(t, registry, candidateProfileB, "1.1.1.1", *now)
	observe(t, registry, candidateProfileB, "8.8.8.8", *now)

	if registry.Snapshot(candidateProfileB).CandidateIP != "8.8.8.8" {
		t.Fatal("candidate replacement failed")
	}

	observe(t, registry, candidateProfileA, "1.1.1.1", *now)
}

func TestCandidateExpiryCountsFromObservationTime(t *testing.T) {
	registry, now := newTestCandidateRegistry(t)

	result := observe(t, registry, candidateProfileA, "1.1.1.1", now.Add(-20*time.Second))

	if !result.ExpiresAt.Equal(now.Add(10 * time.Second)) {
		t.Fatalf("lifetime was extended: %v", result.ExpiresAt)
	}

	*now = now.Add(9 * time.Second)

	if registry.Snapshot(candidateProfileA).Status != "candidate" {
		t.Fatal("candidate expired early")
	}

	*now = now.Add(time.Second)

	if registry.Snapshot(candidateProfileA).Status != "absent" {
		t.Fatal("candidate outlived its observation")
	}
}

func TestCandidateRefreshWithSameIP(t *testing.T) {
	registry, now := newTestCandidateRegistry(t)

	observe(t, registry, candidateProfileA, "1.1.1.1", *now)

	*now = now.Add(20 * time.Second)
	result := observe(t, registry, candidateProfileA, "1.1.1.1", *now)

	if !result.ExpiresAt.Equal(now.Add(30 * time.Second)) {
		t.Fatalf("refresh did not renew expiry: %v", result.ExpiresAt)
	}
}

func TestCandidateInvalidRefreshRevokesPrevious(t *testing.T) {
	registry, now := newTestCandidateRegistry(t)

	observe(t, registry, candidateProfileA, "1.1.1.1", *now)

	if _, err := registry.Evaluate(EgressObservation{
		ProfileID:  candidateProfileA,
		ObservedIP: "10.0.0.2",
		ObservedAt: *now,
	}); err == nil {
		t.Fatal("invalid observation was accepted")
	}

	if registry.Snapshot(candidateProfileA).Status != "absent" {
		t.Fatal("previous candidate survived invalid refresh")
	}

	observe(t, registry, candidateProfileB, "1.1.1.1", *now)
}

func TestCandidateCollisionRevokesPrevious(t *testing.T) {
	registry, now := newTestCandidateRegistry(t)

	observe(t, registry, candidateProfileA, "1.1.1.1", *now)
	observe(t, registry, candidateProfileB, "8.8.8.8", *now)

	if _, err := registry.Evaluate(EgressObservation{
		ProfileID:  candidateProfileB,
		ObservedIP: "1.1.1.1",
		ObservedAt: *now,
	}); !errors.Is(err, ErrEgressIPCollision) {
		t.Fatalf("expected collision, got %v", err)
	}

	if registry.Snapshot(candidateProfileB).Status != "absent" {
		t.Fatal("previous candidate survived a colliding refresh")
	}
}

func TestCandidateRejectsStaleFutureAndBadProfile(t *testing.T) {
	registry, now := newTestCandidateRegistry(t)

	observations := []EgressObservation{
		{ProfileID: candidateProfileA, ObservedIP: "1.1.1.1", ObservedAt: now.Add(-31 * time.Second)},
		{ProfileID: candidateProfileA, ObservedIP: "1.1.1.1", ObservedAt: now.Add(-30 * time.Second)},
		{ProfileID: candidateProfileA, ObservedIP: "1.1.1.1", ObservedAt: now.Add(time.Second)},
		{ProfileID: candidateProfileA, ObservedIP: "1.1.1.1"},
		{ProfileID: "invalid-profile", ObservedIP: "1.1.1.1", ObservedAt: *now},
		{ProfileID: "profile_0123456789ABCDEF", ObservedIP: "1.1.1.1", ObservedAt: *now},
	}

	for _, observation := range observations {
		result, err := registry.Evaluate(observation)

		if !errors.Is(err, ErrInvalidObservation) || result.NetworkReady || result.Status != "rejected" {
			t.Errorf("observation %+v: result=%+v error=%v", observation, result, err)
		}
	}
}

func TestCandidateRelease(t *testing.T) {
	registry, now := newTestCandidateRegistry(t)

	observe(t, registry, candidateProfileA, "1.1.1.1", *now)
	registry.Release(candidateProfileA)

	if registry.Snapshot(candidateProfileA).Status != "absent" {
		t.Fatal("candidate not released")
	}

	observe(t, registry, candidateProfileB, "1.1.1.1", *now)
}

func TestCandidateStatusJSONNeverClaimsReady(t *testing.T) {
	registry, now := newTestCandidateRegistry(t)

	observe(t, registry, candidateProfileA, "1.1.1.1", *now)

	for _, status := range []EgressCandidateStatus{
		registry.Snapshot(candidateProfileA),
		registry.Snapshot(candidateProfileB),
	} {
		data, err := json.Marshal(status)
		if err != nil {
			t.Fatal(err)
		}

		if !strings.Contains(string(data), `"network_ready":false`) {
			t.Fatalf("unexpected JSON: %s", data)
		}

		if status.Status == "absent" && strings.Contains(string(data), "expires_at") {
			t.Fatalf("absent status carries expiry: %s", data)
		}
	}
}

func TestCandidateConcurrentCollision(t *testing.T) {
	registry, now := newTestCandidateRegistry(t)

	type outcome struct {
		status string
		err    error
	}

	results := make(chan outcome, 2)

	var wg sync.WaitGroup

	for _, profile := range []string{candidateProfileA, candidateProfileB} {
		wg.Add(1)

		go func(id string) {
			defer wg.Done()

			result, err := registry.Evaluate(EgressObservation{ProfileID: id, ObservedIP: "1.1.1.1", ObservedAt: *now})
			results <- outcome{status: result.Status, err: err}
		}(profile)
	}

	wg.Wait()
	close(results)

	candidates, collisions := 0, 0

	for result := range results {
		if result.status == "candidate" && result.err == nil {
			candidates++
		}

		if result.status == "collision" && errors.Is(result.err, ErrEgressIPCollision) {
			collisions++
		}
	}

	if candidates != 1 || collisions != 1 {
		t.Fatalf("candidates=%d collisions=%d", candidates, collisions)
	}
}
