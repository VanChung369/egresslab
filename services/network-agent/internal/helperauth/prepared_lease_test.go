package helperauth

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"testing"
	"time"
)

func testPrepareLeaseIntent(t *testing.T) Intent {
	t.Helper()

	intent, err := NewPrepareEgressLeaseIntent(testProfile, testLab, "9.9.9.9", testGenerationA,
		"ffeeddccbbaa99887766554433221100", "aabbccddeeff00112233445566778899",
		"runtime_0123456789abcdef0123456789abcdef", "authority_0123456789abcdef0123456789abcdef",
		"reservation_0123456789abcdef0123456789abcdef", "8.8.4.4")
	if err != nil {
		t.Fatal(err)
	}

	return intent
}

func TestPrepareLeaseCapabilityBinding(t *testing.T) {
	intent := testPrepareLeaseIntent(t)
	token, verifier, _ := testToken(t, intent, time.Unix(1795500000, 0))

	for name, mutate := range map[string]func(*Intent){
		"foreign authority":   func(i *Intent) { i.AuthorityID = "authority_ffffffffffffffffffffffffffffffff" },
		"foreign reservation": func(i *Intent) { i.ReservationID = "reservation_ffffffffffffffffffffffffffffffff" },
		"foreign runtime":     func(i *Intent) { i.RuntimeID = "runtime_ffffffffffffffffffffffffffffffff" },
		"foreign generation":  func(i *Intent) { i.TunnelGeneration = testGenerationB },
		"foreign evidence":    func(i *Intent) { i.EvidenceNonce = "ffffffffffffffffffffffffffffffff" },
		"foreign candidate":   func(i *Intent) { i.ReservationNonce = "ffffffffffffffffffffffffffffffff" },
		"different egress":    func(i *Intent) { i.EgressIPv4 = "8.8.8.8" },
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

	if err := verifier.VerifyAndConsume(token, intent); err != nil {
		t.Fatal(err)
	}

	if err := verifier.VerifyAndConsume(token, intent); !errors.Is(err, ErrCapabilityReplay) {
		t.Fatalf("preparation replay accepted: %v", err)
	}
}

func TestPrepareLeaseIntentPolicy(t *testing.T) {
	intent := testPrepareLeaseIntent(t)

	for name, mutate := range map[string]func(*Intent){
		"missing authority":       func(i *Intent) { i.AuthorityID = "" },
		"missing reservation":     func(i *Intent) { i.ReservationID = "" },
		"missing runtime":         func(i *Intent) { i.RuntimeID = "" },
		"missing candidate nonce": func(i *Intent) { i.ReservationNonce = "" },
		"missing evidence":        func(i *Intent) { i.EvidenceNonce = "" },
		"duplicate nonce":         func(i *Intent) { i.ReservationNonce = i.EvidenceNonce },
		"missing generation":      func(i *Intent) { i.TunnelGeneration = "" },
		"missing pin":             func(i *Intent) { i.ProbeIPv4 = "" },
		"private address":         func(i *Intent) { i.EgressIPv4 = "10.0.0.1" },
		"mapped IPv6":             func(i *Intent) { i.EgressIPv4 = "::ffff:8.8.4.4" },
		"unexpected stage":        func(i *Intent) { i.StageID = testStage },
		"malformed authority":     func(i *Intent) { i.AuthorityID = "authority_1" },
	} {
		t.Run(name, func(t *testing.T) {
			bad := intent
			mutate(&bad)

			if err := validateIntent(bad); !errors.Is(err, ErrInvalidCapability) {
				t.Fatal("invalid lease intent accepted")
			}
		})
	}

	candidate, err := NewReserveEgressCandidateIntent(testProfile, testLab, "9.9.9.9", testGenerationA,
		testCandidateEvidenceNonce)
	if err != nil {
		t.Fatal(err)
	}

	v2, err := NewGenerationProbeIntent(testProfile, testLab, "9.9.9.9", testGenerationA)
	if err != nil {
		t.Fatal(err)
	}

	v1, err := NewMultiProbeIntent(testProfile, testLab, "9.9.9.9")
	if err != nil {
		t.Fatal(err)
	}

	// Each lease field on its own extends no earlier operation's policy.
	for _, field := range []func(*Intent){
		func(i *Intent) { i.ReservationNonce = intent.ReservationNonce },
		func(i *Intent) { i.RuntimeID = intent.RuntimeID },
		func(i *Intent) { i.AuthorityID = intent.AuthorityID },
		func(i *Intent) { i.ReservationID = intent.ReservationID },
		func(i *Intent) { i.EgressIPv4 = intent.EgressIPv4 },
	} {
		for _, old := range []Intent{candidate, v2, v1, connectIntent(), probeIntent(), {Operation: OpCreateLab, ProfileID: testProfile}} {
			field(&old)

			if err := validateIntent(old); !errors.Is(err, ErrInvalidCapability) {
				t.Fatalf("%s accepted lease fields: %+v", old.Operation, old)
			}
		}
	}
}

// The signed bytes until the seventh golden vector arrives with the controller signer (Step 31D.3b).
func TestPrepareLeaseIntentEncoding(t *testing.T) {
	raw, err := json.Marshal(testPrepareLeaseIntent(t))
	if err != nil {
		t.Fatal(err)
	}

	const want = `{"operation":"PrepareEgressLeaseV1","profile_id":"profile_0123456789abcdef",` +
		`"namespace":"egresslab-lab-0123456789abcdef","probe_ipv4":"9.9.9.9",` +
		`"tunnel_generation":"tunnelgen_0123456789abcdef0123456789abcdef",` +
		`"evidence_nonce":"ffeeddccbbaa99887766554433221100","reservation_nonce":"aabbccddeeff00112233445566778899",` +
		`"runtime_id":"runtime_0123456789abcdef0123456789abcdef",` +
		`"authority_id":"authority_0123456789abcdef0123456789abcdef",` +
		`"reservation_id":"reservation_0123456789abcdef0123456789abcdef","egress_ipv4":"8.8.4.4"}`

	if string(raw) != want {
		t.Fatalf("lease intent encoding changed:\n%s", raw)
	}
}

// The seventh golden vector; the controller pins the same signature (test seed 0x42, never a real key).
func TestPrepareEgressLeaseSigningMessageGolden(t *testing.T) {
	private := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x42}, ed25519.SeedSize))

	token, err := Mint(private, Claims{
		Version:  Version,
		Intent:   testPrepareLeaseIntent(t),
		HelperID: testHelper,
		Nonce:    "00112233445566778899aabbccddeeff",
		IssuedAt: 1795500000,
		NotAfter: 1795500030,
	})
	if err != nil {
		t.Fatal(err)
	}

	const want = "0NoCsoeg6bZBAxHU5qrpNDO0xjOAOS5U98RnZVZUY-POYFxr48rVgpy17K6B2-scLAUC39hSIcsIh4KkTwyPBg"

	if token.Signature != want {
		t.Fatalf("lease signature mismatch: %s", token.Signature)
	}
}
