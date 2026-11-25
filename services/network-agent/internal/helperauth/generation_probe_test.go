package helperauth

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"testing"
	"time"
)

const (
	testGenerationA = "tunnelgen_0123456789abcdef0123456789abcdef"
	testGenerationB = "tunnelgen_ffffffffffffffffffffffffffffffff"
)

func TestGenerationProbeCapability(t *testing.T) {
	now := time.Unix(1795500000, 0)

	intent, err := NewGenerationProbeIntent(testProfile, testLab, "9.9.9.9", testGenerationA)
	if err != nil {
		t.Fatal(err)
	}

	token, verifier, _ := testToken(t, intent, now)

	foreign := intent
	foreign.TunnelGeneration = testGenerationB
	requireInvalid(t, verifier.VerifyAndConsume(token, foreign), "foreign tunnel generation")

	tampered := token
	tampered.Claims.Intent.TunnelGeneration = testGenerationB
	requireInvalid(t, verifier.VerifyAndConsume(tampered, foreign), "tampered tunnel generation")

	legacy, err := NewMultiProbeIntent(testProfile, testLab, "9.9.9.9")
	if err != nil {
		t.Fatal(err)
	}

	requireInvalid(t, verifier.VerifyAndConsume(token, legacy), "V2 capability used for V1")

	// None of the refusals consumed the nonce.
	if err := verifier.VerifyAndConsume(token, intent); err != nil {
		t.Fatal(err)
	}

	if err := verifier.VerifyAndConsume(token, intent); !errors.Is(err, ErrCapabilityReplay) {
		t.Fatalf("replay accepted: %v", err)
	}
}

func TestGenerationProbeIntentPolicy(t *testing.T) {
	for _, generation := range []string{
		"",
		"tunnelgen_invalid",
		"tunnelgen_0123456789abcdef",
		"tunnelgen_0123456789ABCDEF0123456789ABCDEF",
		testGenerationA + " ",
		"helper_0123456789abcdef0123456789abcdef",
	} {
		if _, err := NewGenerationProbeIntent(testProfile, testLab, "9.9.9.9", generation); !errors.Is(err,
			ErrInvalidCapability) {
			t.Fatalf("invalid generation %q accepted", generation)
		}
	}

	for _, pin := range []string{"1.1.1.1", "10.0.0.1", ""} {
		if _, err := NewGenerationProbeIntent(testProfile, testLab, pin, testGenerationA); !errors.Is(err,
			ErrInvalidCapability) {
			t.Fatalf("invalid pin %q accepted", pin)
		}
	}

	legacy, err := NewMultiProbeIntent(testProfile, testLab, "9.9.9.9")
	if err != nil {
		t.Fatal(err)
	}

	// Only V2 may carry a generation.
	createLab := Intent{Operation: OpCreateLab, ProfileID: testProfile}

	for _, intent := range []Intent{legacy, probeIntent(), connectIntent(), createLab} {
		intent.TunnelGeneration = testGenerationA

		if err := validateIntent(intent); !errors.Is(err, ErrInvalidCapability) {
			t.Fatalf("generation accepted by %s", intent.Operation)
		}
	}

	staged, err := NewGenerationProbeIntent(testProfile, testLab, "9.9.9.9", testGenerationA)
	if err != nil {
		t.Fatal(err)
	}

	staged.StageID = testStage
	if err := validateIntent(staged); !errors.Is(err, ErrInvalidCapability) {
		t.Fatal("V2 intent with a stage accepted")
	}
}

// The new field is the last one and appears only in V2, so every earlier vector is unchanged; this
// pins its name and position. Cross-checked with OpenSSL 3 (pkeyutl -sign -rawin), same seed.
func TestPermitMultiProbeV2SigningMessageGolden(t *testing.T) {
	private := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x42}, ed25519.SeedSize))

	intent, err := NewGenerationProbeIntent(testProfile, testLab, "9.9.9.9", testGenerationA)
	if err != nil {
		t.Fatal(err)
	}

	claims := Claims{
		Version:  Version,
		Intent:   intent,
		HelperID: testHelper,
		Nonce:    "00112233445566778899aabbccddeeff",
		IssuedAt: 1795500000,
		NotAfter: 1795500030,
	}

	wantMessage := "egresslab/helper-capability/v1\x00" +
		`{"version":1,"intent":{"operation":"PermitMultiProbeV2","profile_id":"profile_0123456789abcdef",` +
		`"namespace":"egresslab-lab-0123456789abcdef","probe_ipv4":"9.9.9.9",` +
		`"tunnel_generation":"tunnelgen_0123456789abcdef0123456789abcdef"},` +
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

	const wantSignature = "sRRT76f9zHhm22LwX3wRFj1qqP2ug7YzPXCTXaBL3B50bwejThRjeVWLt6Kk33HRkLC3ugajV3ksNo2MUxONCw"
	if token.Signature != wantSignature {
		t.Fatalf("signature changed: %s", token.Signature)
	}
}
