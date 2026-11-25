package helperauth

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"strings"
	"testing"
	"time"
)

const testCandidateEvidenceNonce = "00112233445566778899aabbccddeeff"

func TestCandidateCapabilityBinding(t *testing.T) {
	now := time.Unix(1795500000, 0)

	intent, err := NewReserveEgressCandidateIntent(testProfile, testLab, "9.9.9.9", testGenerationA, testCandidateEvidenceNonce)
	if err != nil {
		t.Fatal(err)
	}

	token, verifier, _ := testToken(t, intent, now)

	for name, mutate := range map[string]func(*Intent){
		"another evidence":   func(i *Intent) { i.EvidenceNonce = strings.Repeat("f", 32) },
		"another generation": func(i *Intent) { i.TunnelGeneration = testGenerationB },
		"another source pin": func(i *Intent) { i.ProbeIPv4 = "8.8.8.8" },
		"another profile":    func(i *Intent) { i.ProfileID = "profile_ffffffffffffffff" },
	} {
		t.Run(name, func(t *testing.T) {
			foreign := intent
			mutate(&foreign)

			requireInvalid(t, verifier.VerifyAndConsume(token, foreign), name)

			tampered := token
			tampered.Claims.Intent = foreign
			requireInvalid(t, verifier.VerifyAndConsume(tampered, foreign), "tampered signature")
		})
	}

	// The refusals above did not consume the token.
	if err := verifier.VerifyAndConsume(token, intent); err != nil {
		t.Fatal(err)
	}

	if err := verifier.VerifyAndConsume(token, intent); !errors.Is(err, ErrCapabilityReplay) {
		t.Fatalf("candidate capability replay accepted: %v", err)
	}
}

func TestCandidateIntentPolicy(t *testing.T) {
	intent, err := NewReserveEgressCandidateIntent(testProfile, testLab, "9.9.9.9", testGenerationA, testCandidateEvidenceNonce)
	if err != nil {
		t.Fatal(err)
	}

	for name, mutate := range map[string]func(*Intent){
		"missing evidence":   func(i *Intent) { i.EvidenceNonce = "" },
		"bad nonce":          func(i *Intent) { i.EvidenceNonce = "invalid" },
		"uppercase nonce":    func(i *Intent) { i.EvidenceNonce = strings.ToUpper(testCandidateEvidenceNonce) },
		"missing generation": func(i *Intent) { i.TunnelGeneration = "" },
		"bad generation":     func(i *Intent) { i.TunnelGeneration = "invalid" },
		"invalid pin":        func(i *Intent) { i.ProbeIPv4 = "10.0.0.1" },
		"cloudflare pin":     func(i *Intent) { i.ProbeIPv4 = MultiProbeCloudflareIPv4 },
		"unexpected stage":   func(i *Intent) { i.StageID = testStage },
		"no namespace":       func(i *Intent) { i.Namespace = "" },
	} {
		t.Run(name, func(t *testing.T) {
			bad := intent
			mutate(&bad)

			if err := validateIntent(bad); !errors.Is(err, ErrInvalidCapability) {
				t.Fatal("invalid intent accepted")
			}
		})
	}

	// No earlier operation may carry the new evidence reference.
	v2, err := NewGenerationProbeIntent(testProfile, testLab, "9.9.9.9", testGenerationA)
	if err != nil {
		t.Fatal(err)
	}

	v1, err := NewMultiProbeIntent(testProfile, testLab, "9.9.9.9")
	if err != nil {
		t.Fatal(err)
	}

	for _, old := range []Intent{v2, v1, connectIntent(), probeIntent(), {Operation: OpCreateLab, ProfileID: testProfile}} {
		old.EvidenceNonce = testCandidateEvidenceNonce

		if err := validateIntent(old); !errors.Is(err, ErrInvalidCapability) {
			t.Fatalf("%s accepted an evidence nonce", old.Operation)
		}
	}
}

// Cross-checked with OpenSSL 3 (openssl pkeyutl -sign -rawin) using the same seed.
func TestReserveEgressCandidateSigningMessageGolden(t *testing.T) {
	private := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x42}, ed25519.SeedSize))

	intent, err := NewReserveEgressCandidateIntent(testProfile, testLab, "9.9.9.9", testGenerationA,
		"ffeeddccbbaa99887766554433221100")
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
		`{"version":1,"intent":{"operation":"ReserveEgressCandidateV1","profile_id":"profile_0123456789abcdef",` +
		`"namespace":"egresslab-lab-0123456789abcdef","probe_ipv4":"9.9.9.9",` +
		`"tunnel_generation":"tunnelgen_0123456789abcdef0123456789abcdef",` +
		`"evidence_nonce":"ffeeddccbbaa99887766554433221100"},` +
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

	const wantSignature = "WrDOmIHMAE-VvemqyqyxXj4iSwf_nJeFu9I0gTqRdcopF2fCfQxnYbidX_0WCkX8dEDzvUwBMclAf8R_Bq0jCg"
	if token.Signature != wantSignature {
		t.Fatalf("signature changed: %s", token.Signature)
	}
}
