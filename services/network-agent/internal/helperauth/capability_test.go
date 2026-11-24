package helperauth

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

const (
	testHelper  = "helper_0123456789abcdef0123456789abcdef"
	testLab     = "egresslab-lab-0123456789abcdef"
	testProfile = "profile_0123456789abcdef"
	testStage   = "wgstage_0123456789abcdef0123456789abcdef"
)

func connectIntent() Intent {
	return Intent{Operation: OpConnectTunnel, ProfileID: testProfile, Namespace: testLab, StageID: testStage}
}

func probeIntent() Intent {
	return Intent{Operation: OpPermitProbe, ProfileID: testProfile, Namespace: testLab, ProbeIPv4: "1.1.1.1"}
}

func testToken(t *testing.T, intent Intent, now time.Time) (SignedCapability, *Verifier, ed25519.PrivateKey) {
	t.Helper()

	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	claims, err := NewClaims(intent, testHelper, now)
	if err != nil {
		t.Fatal(err)
	}

	token, err := Mint(private, claims)
	if err != nil {
		t.Fatal(err)
	}

	verifier, err := NewVerifier(public, testHelper)
	if err != nil {
		t.Fatal(err)
	}

	verifier.now = func() time.Time { return now }

	return token, verifier, private
}

func requireInvalid(t *testing.T, err error, what string) {
	t.Helper()

	if !errors.Is(err, ErrInvalidCapability) {
		t.Fatalf("%s: got %v, want ErrInvalidCapability", what, err)
	}
}

func TestCapabilitySingleUseAndBinding(t *testing.T) {
	now := time.Unix(1795500000, 0)

	for _, intent := range []Intent{connectIntent(), probeIntent()} {
		token, v, _ := testToken(t, intent, now)

		// Each expected intent below is well formed, so only the binding can reject it.
		wrong := intent
		wrong.Namespace = "egresslab-lab-ffffffffffffffff"
		requireInvalid(t, v.VerifyAndConsume(token, wrong), "other namespace")

		wrong = intent
		wrong.ProfileID = "profile_ffffffffffffffff"
		requireInvalid(t, v.VerifyAndConsume(token, wrong), "other profile")

		wrong = intent
		if wrong.Operation == OpConnectTunnel {
			wrong.StageID = "wgstage_ffffffffffffffffffffffffffffffff"
		} else {
			wrong.ProbeIPv4 = "8.8.8.8"
		}
		requireInvalid(t, v.VerifyAndConsume(token, wrong), "other target")

		wrong = probeIntent()
		if intent.Operation == OpPermitProbe {
			wrong = connectIntent()
		}
		requireInvalid(t, v.VerifyAndConsume(token, wrong), "other operation")

		// The rejected attempts above did not consume the nonce.
		if err := v.VerifyAndConsume(token, intent); err != nil {
			t.Fatal(err)
		}

		if err := v.VerifyAndConsume(token, intent); !errors.Is(err, ErrCapabilityReplay) {
			t.Fatalf("replay: got %v", err)
		}
	}
}

func TestCapabilitySignatureTimeAndIdentity(t *testing.T) {
	now := time.Unix(1795500000, 0)
	token, v, private := testToken(t, connectIntent(), now)

	tampered := token
	tampered.Claims.Intent.ProfileID = "profile_ffffffffffffffff"
	requireInvalid(t, v.VerifyAndConsume(tampered, tampered.Claims.Intent), "tampered claims")

	tampered = token
	tampered.Claims.NotAfter--
	requireInvalid(t, v.VerifyAndConsume(tampered, connectIntent()), "tampered expiry")

	tampered = token
	tampered.Signature = "%%%"
	requireInvalid(t, v.VerifyAndConsume(tampered, connectIntent()), "undecodable signature")

	tampered = token
	tampered.Signature = token.Signature + "="
	requireInvalid(t, v.VerifyAndConsume(tampered, connectIntent()), "padded signature")

	_, otherKey, _ := ed25519.GenerateKey(rand.Reader)
	foreign, err := Mint(otherKey, token.Claims)
	if err != nil {
		t.Fatal(err)
	}
	requireInvalid(t, v.VerifyAndConsume(foreign, connectIntent()), "signed by another key")

	otherHelper := token.Claims
	otherHelper.HelperID = "helper_ffffffffffffffffffffffffffffffff"
	signed, err := Mint(private, otherHelper)
	if err != nil {
		t.Fatal(err)
	}
	requireInvalid(t, v.VerifyAndConsume(signed, connectIntent()), "other helper")

	v.now = func() time.Time { return now.Add(-time.Second) }
	requireInvalid(t, v.VerifyAndConsume(token, connectIntent()), "not yet valid")

	// Time only moves forward here: a step back would trip the rollback guard (epoch_test.go).
	v.now = func() time.Time { return now.Add(MaxTTL - time.Second) }
	if err := v.VerifyAndConsume(token, connectIntent()); err != nil {
		t.Fatalf("last valid second: %v", err)
	}

	// The expiry check runs before the replay check, so this is an expiry refusal.
	v.now = func() time.Time { return now.Add(MaxTTL) }
	err = v.VerifyAndConsume(token, connectIntent())
	requireInvalid(t, err, "expired")
	if errors.Is(err, ErrAuthorizationClockUnsafe) {
		t.Fatalf("expired: got %v, want a plain expiry refusal", err)
	}

	tooLong := token.Claims
	tooLong.NotAfter = tooLong.IssuedAt + 31
	if signed, err := Mint(private, tooLong); err == nil || signed.Signature != "" {
		t.Fatal("oversized TTL signed")
	}

	if _, err := Mint(private[:10], token.Claims); err == nil {
		t.Fatal("short private key accepted")
	}

	if _, err := NewVerifier(ed25519.PublicKey(make([]byte, 31)), testHelper); err == nil {
		t.Fatal("short public key accepted")
	}

	var nilVerifier *Verifier
	requireInvalid(t, nilVerifier.VerifyAndConsume(token, connectIntent()), "nil verifier")
}

func TestInvalidIntents(t *testing.T) {
	now := time.Unix(1795500000, 0)

	bad := []Intent{
		{Operation: "CreateLab", ProfileID: testProfile, Namespace: testLab},
		{Operation: OpConnectTunnel, ProfileID: testProfile, Namespace: testLab},
		{Operation: OpConnectTunnel, ProfileID: testProfile, Namespace: testLab, StageID: testStage, ProbeIPv4: "1.1.1.1"},
		{Operation: OpConnectTunnel, ProfileID: "profile_0123", Namespace: testLab, StageID: testStage},
		{Operation: OpConnectTunnel, ProfileID: testProfile, Namespace: "egresslab-lab_0123456789abcdef", StageID: testStage},
		{Operation: OpConnectTunnel, ProfileID: testProfile, Namespace: testLab, StageID: "wgstage_0123456789ABCDEF0123456789abcdef"},
		{Operation: OpPermitProbe, ProfileID: testProfile, Namespace: testLab, ProbeIPv4: "127.0.0.1"},
		{Operation: OpPermitProbe, ProfileID: testProfile, Namespace: testLab, ProbeIPv4: "2001:db8::1"},
		{Operation: OpPermitProbe, ProfileID: testProfile, Namespace: testLab, ProbeIPv4: "01.1.1.1"},
		{Operation: OpPermitProbe, ProfileID: testProfile, Namespace: testLab, ProbeIPv4: "::ffff:1.1.1.1"},
		{Operation: OpPermitProbe, ProfileID: testProfile, Namespace: testLab, ProbeIPv4: "1.1.1.1", StageID: testStage},
	}

	for _, in := range bad {
		if _, err := NewClaims(in, testHelper, now); !errors.Is(err, ErrInvalidCapability) {
			t.Fatalf("invalid intent accepted: %+v", in)
		}
	}

	if _, err := NewClaims(connectIntent(), "helper_1234", now); err == nil {
		t.Fatal("invalid helper ID accepted")
	}
}

// TestSigningMessageGolden pins the exact signed bytes. Another implementation (for example the
// controller, which is a separate Go module) must produce the same message and signature.
func TestSigningMessageGolden(t *testing.T) {
	seed := bytes.Repeat([]byte{0x42}, ed25519.SeedSize)
	private := ed25519.NewKeyFromSeed(seed)

	claims := Claims{
		Version:  Version,
		Intent:   connectIntent(),
		HelperID: testHelper,
		Nonce:    "00112233445566778899aabbccddeeff",
		IssuedAt: 1795500000,
		NotAfter: 1795500030,
	}

	wantMessage := "egresslab/helper-capability/v1\x00" +
		`{"version":1,"intent":{"operation":"ConnectTunnel","profile_id":"profile_0123456789abcdef",` +
		`"namespace":"egresslab-lab-0123456789abcdef","stage_id":"wgstage_0123456789abcdef0123456789abcdef"},` +
		`"helper_id":"helper_0123456789abcdef0123456789abcdef","nonce":"00112233445566778899aabbccddeeff",` +
		`"issued_at":1795500000,"not_after":1795500030}`

	msg, err := signingMessage(claims)
	if err != nil {
		t.Fatal(err)
	}

	if string(msg) != wantMessage {
		t.Fatalf("signing message changed:\n got %q\nwant %q", msg, wantMessage)
	}

	token, err := Mint(private, claims)
	if err != nil {
		t.Fatal(err)
	}

	// Cross-checked with OpenSSL 3 (openssl pkeyutl -sign -rawin) using the same seed.
	const wantSignature = "_46Bh7TESfJcvG71RrKSxFLq31MPs2VrLI8U3Jt7tgb_PRdTvnDdITVMvKJ5DHvFkaRQzDWwHUvxxRgpHlXCCw"
	if token.Signature != wantSignature {
		t.Fatalf("signature changed: %s", token.Signature)
	}
}

func TestVerifierConcurrentReplay(t *testing.T) {
	now := time.Unix(1795500000, 0)
	token, v, _ := testToken(t, connectIntent(), now)

	var accepted, replays atomic.Int32
	var wg sync.WaitGroup

	for i := 0; i < 100; i++ {
		wg.Add(1)

		go func() {
			defer wg.Done()

			switch err := v.VerifyAndConsume(token, connectIntent()); {
			case err == nil:
				accepted.Add(1)
			case errors.Is(err, ErrCapabilityReplay):
				replays.Add(1)
			}
		}()
	}

	wg.Wait()

	if accepted.Load() != 1 || replays.Load() != 99 {
		t.Fatalf("%d accepted, %d replays; want 1 and 99", accepted.Load(), replays.Load())
	}
}

func TestVerifierCapacityAndExpiryPruning(t *testing.T) {
	now := time.Unix(1795500000, 0)
	token, v, private := testToken(t, connectIntent(), now)

	mint := func(c Claims) SignedCapability {
		t.Helper()

		issued, err := Mint(private, c)
		if err != nil {
			t.Fatal(err)
		}

		return issued
	}

	for i := 0; i < maxLiveNonces; i++ {
		claims := token.Claims
		claims.Nonce = nonceHex(i)

		if err := v.VerifyAndConsume(mint(claims), connectIntent()); err != nil {
			t.Fatal(err)
		}
	}

	claims := token.Claims
	claims.Nonce = nonceHex(maxLiveNonces)
	overflow := mint(claims)
	requireInvalid(t, v.VerifyAndConsume(overflow, connectIntent()), "replay cache limit")

	// Once every cached capability has expired, the cache is pruned and accepts new ones.
	later := now.Add(MaxTTL + time.Second)
	v.now = func() time.Time { return later }
	requireInvalid(t, v.VerifyAndConsume(overflow, connectIntent()), "expired")

	fresh, err := NewClaims(connectIntent(), testHelper, later)
	if err != nil {
		t.Fatal(err)
	}

	if err := v.VerifyAndConsume(mint(fresh), connectIntent()); err != nil {
		t.Fatalf("after expiry: %v", err)
	}

	if len(v.used) != 1 {
		t.Fatalf("%d nonces cached after pruning; want 1", len(v.used))
	}
}

func nonceHex(i int) string {
	const digits = "0123456789abcdef"

	b := bytes.Repeat([]byte{'0'}, 32)
	for p := 31; p >= 0 && i > 0; p-- {
		b[p] = digits[i&15]
		i >>= 4
	}

	return string(b)
}
