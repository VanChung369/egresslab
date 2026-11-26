package helperauth

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
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

	// Moving the clock forward does not clear the fault. A new helper epoch is required.
	verifier.now = func() time.Time { return later }

	if err := verifier.VerifyAndConsume(mint(later), connectIntent()); !errors.Is(err, ErrAuthorizationClockUnsafe) {
		t.Fatalf("clock fault was cleared: %v", err)
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
