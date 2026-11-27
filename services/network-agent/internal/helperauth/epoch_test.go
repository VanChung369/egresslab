package helperauth

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
)

func TestHelperEpochInvalidatesOldCapabilities(t *testing.T) {
	now := time.Unix(1795500000, 0)

	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	firstID, err := NewHelperID()
	if err != nil {
		t.Fatal(err)
	}

	secondID, err := NewHelperID()
	if err != nil {
		t.Fatal(err)
	}

	if firstID == secondID || !ValidHelperID(firstID) || !ValidHelperID(secondID) {
		t.Fatalf("invalid or repeated helper epoch: %s %s", firstID, secondID)
	}

	first, err := NewVerifier(public, firstID)
	if err != nil {
		t.Fatal(err)
	}

	second, err := NewVerifier(public, secondID)
	if err != nil {
		t.Fatal(err)
	}

	first.now = func() time.Time { return now }
	second.now = func() time.Time { return now }

	mint := func(id string) SignedCapability {
		t.Helper()

		claims, err := NewClaims(connectIntent(), id, now)
		if err != nil {
			t.Fatal(err)
		}

		token, err := Mint(private, claims)
		if err != nil {
			t.Fatal(err)
		}

		return token
	}

	consumed := mint(firstID)
	unused := mint(firstID)

	if err := first.VerifyAndConsume(consumed, connectIntent()); err != nil {
		t.Fatal(err)
	}

	// Neither consumed nor unused capabilities from an earlier helper may be reused.
	for _, token := range []SignedCapability{consumed, unused} {
		if err := second.VerifyAndConsume(token, connectIntent()); !errors.Is(err, ErrInvalidCapability) {
			t.Fatalf("old epoch accepted: %v", err)
		}
	}

	if err := second.VerifyAndConsume(mint(secondID), connectIntent()); err != nil {
		t.Fatal(err)
	}

	id1, fingerprint1 := first.Identity()
	id2, fingerprint2 := second.Identity()

	// The fingerprint is the SHA-256 of the raw 32-byte public key; the controller pins it.
	digest := sha256.Sum256(public)
	want := hex.EncodeToString(digest[:])

	if id1 != firstID || id2 != secondID || fingerprint1 != want || fingerprint2 != want {
		t.Fatalf("identity: %s %s %s %s, want fingerprint %s", id1, fingerprint1, id2, fingerprint2, want)
	}

	var nilVerifier *Verifier
	if id, fingerprint := nilVerifier.Identity(); id != "" || fingerprint != "" {
		t.Fatalf("nil verifier identity: %q %q", id, fingerprint)
	}
}

// A rollback refuses every capability until the clock is back at the latest second seen, and never
// lets a consumed nonce be accepted again.
func TestClockRollbackCannotRestoreConsumedNonce(t *testing.T) {
	now := time.Unix(1795500000, 0)
	token, verifier, private := testToken(t, connectIntent(), now)

	if err := verifier.VerifyAndConsume(token, connectIntent()); err != nil {
		t.Fatal(err)
	}

	later := now.Add(MaxTTL + time.Second)

	mint := func(at time.Time) SignedCapability {
		t.Helper()

		claims, err := NewClaims(connectIntent(), testHelper, at)
		if err != nil {
			t.Fatal(err)
		}

		fresh, err := Mint(private, claims)
		if err != nil {
			t.Fatal(err)
		}

		return fresh
	}

	verifier.now = func() time.Time { return later }

	if err := verifier.VerifyAndConsume(mint(later), connectIntent()); err != nil {
		t.Fatal(err)
	}

	if _, exists := verifier.used[token.Claims.Nonce]; exists {
		t.Fatal("expired nonce was not pruned")
	}

	if !verifier.ClockSafe() {
		t.Fatal("a forward clock reported unsafe")
	}

	// By the wall clock, the original capability now looks valid again.
	verifier.now = func() time.Time { return now.Add(5 * time.Second) }

	if err := verifier.VerifyAndConsume(token, connectIntent()); !errors.Is(err, ErrAuthorizationClockUnsafe) {
		t.Fatalf("clock rollback accepted: %v", err)
	}

	if verifier.ClockSafe() {
		t.Fatal("a rolled-back clock reported safe")
	}

	// A capability minted at the rolled-back time is refused too, and the latest time is not lowered.
	behind := now.Add(5 * time.Second)

	if err := verifier.VerifyAndConsume(mint(behind), connectIntent()); !errors.Is(err, ErrAuthorizationClockUnsafe) {
		t.Fatalf("a capability behind the latest time accepted: %v", err)
	}

	verifier.now = func() time.Time { return later.Add(-time.Second) }

	if err := verifier.Check(mint(later.Add(-time.Second)), connectIntent()); !errors.Is(err, ErrAuthorizationClockUnsafe) {
		t.Fatalf("authorization resumed before the clock caught up: %v", err)
	}

	// Once the clock is back at the latest second, authorization resumes; the consumed capability
	// has expired by then, so it can never be accepted again.
	verifier.now = func() time.Time { return later }

	if !verifier.ClockSafe() {
		t.Fatal("a clock that caught up reported unsafe")
	}

	if err := verifier.VerifyAndConsume(token, connectIntent()); err == nil || errors.Is(err, ErrAuthorizationClockUnsafe) {
		t.Fatalf("the consumed capability after the catch-up: %v", err)
	}

	if err := verifier.VerifyAndConsume(mint(later), connectIntent()); err != nil {
		t.Fatalf("authorization did not resume: %v", err)
	}
}

// A rollback logs one line when authorization pauses and one when it resumes.
func TestClockRollbackLogged(t *testing.T) {
	now := time.Unix(1795500000, 0)
	token, verifier, _ := testToken(t, connectIntent(), now)

	var lines []string
	verifier.logf = func(format string, args ...any) { lines = append(lines, fmt.Sprintf(format, args...)) }

	if err := verifier.Check(token, connectIntent()); err != nil {
		t.Fatal(err)
	}

	verifier.now = func() time.Time { return now.Add(-2 * time.Second) }
	_ = verifier.ClockSafe()
	_ = verifier.ClockSafe()

	verifier.now = func() time.Time { return now }
	_ = verifier.ClockSafe()
	_ = verifier.ClockSafe()

	if len(lines) != 2 || !strings.Contains(lines[0], "paused") || !strings.Contains(lines[0], "2s behind") ||
		!strings.Contains(lines[1], "resumed") {
		t.Fatalf("log lines: %q", lines)
	}
}

func TestClockAtOrBeforeEpochIsUnsafe(t *testing.T) {
	now := time.Unix(1795500000, 0)
	token, verifier, _ := testToken(t, connectIntent(), now)

	verifier.now = func() time.Time { return time.Unix(0, 0) }

	if err := verifier.VerifyAndConsume(token, connectIntent()); !errors.Is(err, ErrAuthorizationClockUnsafe) {
		t.Fatalf("zero clock: %v", err)
	}
}

// A consumed capability still live when the clock catches up stays consumed; work queued since it
// was consumed sees it expire, and sees nothing while the clock is behind.
func TestClockRollbackLiveNonceAndExpiry(t *testing.T) {
	now := time.Unix(1795500000, 0)
	token, verifier, _ := testToken(t, connectIntent(), now)

	if err := verifier.VerifyAndConsume(token, connectIntent()); err != nil {
		t.Fatal(err)
	}

	verifier.now = func() time.Time { return now.Add(10 * time.Second) }

	if !verifier.Unexpired(token) {
		t.Fatal("a live capability reported expired")
	}

	verifier.now = func() time.Time { return now.Add(5 * time.Second) }

	if verifier.Unexpired(token) {
		t.Fatal("a capability judged by a clock behind the latest time")
	}

	verifier.now = func() time.Time { return now.Add(10 * time.Second) }

	if err := verifier.VerifyAndConsume(token, connectIntent()); !errors.Is(err, ErrCapabilityReplay) {
		t.Fatalf("a live nonce after the catch-up: %v", err)
	}

	verifier.now = func() time.Time { return time.Unix(token.Claims.NotAfter, 0) }

	if verifier.Unexpired(token) {
		t.Fatal("an expired capability reported unexpired")
	}

	if (*Verifier)(nil).Unexpired(token) {
		t.Fatal("nil verifier")
	}
}
