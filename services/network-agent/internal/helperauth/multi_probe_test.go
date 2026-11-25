package helperauth

import (
	"errors"
	"testing"
	"time"
)

func TestMultiProbeIntentPolicy(t *testing.T) {
	now := time.Unix(1795500000, 0)

	valid, err := NewMultiProbeIntent(testProfile, testLab, "9.9.9.9")
	if err != nil {
		t.Fatal(err)
	}

	if valid != (Intent{Operation: OpPermitMultiProbe, ProfileID: testProfile, Namespace: testLab, ProbeIPv4: "9.9.9.9"}) {
		t.Fatalf("unexpected intent: %+v", valid)
	}

	if _, err := NewClaims(valid, testHelper, now); err != nil {
		t.Fatal(err)
	}

	for _, pin := range []string{
		"",
		"1.1.1.1",
		"0.1.2.3",
		"10.0.0.1",
		"127.0.0.1",
		"100.64.0.1",
		"169.254.169.254",
		"172.16.0.1",
		"192.168.1.1",
		"192.0.0.1",
		"192.0.2.42",
		"192.88.99.1",
		"198.18.0.1",
		"198.51.100.1",
		"203.0.113.1",
		"224.0.0.1",
		"240.0.0.1",
		"255.255.255.255",
		"2001:db8::1",
		"::ffff:9.9.9.9",
		"9.9.9.9:443",
		"9.9.9.9 ",
		"009.9.9.9",
		"4.ident.me",
	} {
		if _, err := NewMultiProbeIntent(testProfile, testLab, pin); !errors.Is(err, ErrInvalidCapability) {
			t.Fatalf("pin %q accepted: %v", pin, err)
		}
	}

	for name, edit := range map[string]func(*Intent){
		"stage ID":          func(in *Intent) { in.StageID = testStage },
		"missing namespace": func(in *Intent) { in.Namespace = "" },
		"invalid profile":   func(in *Intent) { in.ProfileID = "profile_x" },
	} {
		bad := valid
		edit(&bad)

		if _, err := NewClaims(bad, testHelper, now); !errors.Is(err, ErrInvalidCapability) {
			t.Errorf("%s accepted", name)
		}
	}

	if _, err := NewMultiProbeIntent(testProfile, "", "9.9.9.9"); !errors.Is(err, ErrInvalidCapability) {
		t.Fatal("intent without a namespace built")
	}
}

func TestMultiProbeCapabilityBinding(t *testing.T) {
	now := time.Unix(1795500000, 0)

	intent, err := NewMultiProbeIntent(testProfile, testLab, "9.9.9.9")
	if err != nil {
		t.Fatal(err)
	}

	token, verifier, private := testToken(t, intent, now)

	for name, edit := range map[string]func(*Intent){
		"different pin":       func(in *Intent) { in.ProbeIPv4 = "8.8.8.8" },
		"different namespace": func(in *Intent) { in.Namespace = "egresslab-lab-ffffffffffffffff" },
		"different profile":   func(in *Intent) { in.ProfileID = "profile_ffffffffffffffff" },
		"legacy operation":    func(in *Intent) { *in = probeIntent() },
	} {
		other := intent
		edit(&other)
		requireInvalid(t, verifier.VerifyAndConsume(token, other), name)
	}

	legacyClaims, err := NewClaims(probeIntent(), testHelper, now)
	if err != nil {
		t.Fatal(err)
	}

	legacyToken, err := Mint(private, legacyClaims)
	if err != nil {
		t.Fatal(err)
	}

	requireInvalid(t, verifier.VerifyAndConsume(legacyToken, intent), "legacy capability for a multi-source probe")

	// The pin is signed: changing it breaks the signature.
	tampered := token
	tampered.Claims.Intent.ProbeIPv4 = "8.8.8.8"
	requireInvalid(t, verifier.VerifyAndConsume(tampered, tampered.Claims.Intent), "tampered pin")

	// None of the refusals consumed the nonce.
	if err := verifier.VerifyAndConsume(token, intent); err != nil {
		t.Fatal(err)
	}

	if err := verifier.VerifyAndConsume(token, intent); !errors.Is(err, ErrCapabilityReplay) {
		t.Fatalf("replay accepted: %v", err)
	}
}
