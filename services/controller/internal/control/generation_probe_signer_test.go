package control

import (
	"net/netip"
	"slices"
	"strings"
	"testing"
	"time"
)

const (
	testLabGenerationA = "tunnelgen_0123456789abcdef0123456789abcdef"
	testLabGenerationB = "tunnelgen_ffffffffffffffffffffffffffffffff"
)

func TestMintPermitMultiProbeV2(t *testing.T) {
	signer, profile, info, binding, lab, policy := multiProbeFixture()
	now := time.Unix(1795500000, 0).UTC()
	policy.Policy = LabMultiProbeV2Op

	target := LabMultiProbeTarget{
		ProfileID:           profile.ID,
		Namespace:           binding.Namespace,
		TunnelGeneration:    testLabGenerationA,
		LabMultiProbePolicy: policy,
	}

	token, err := MintPermitMultiProbeV2(signer, profile, binding, info, lab, target, now)
	if err != nil {
		t.Fatal(err)
	}

	if token.Claims.Intent != (LabIntent{Operation: LabMultiProbeV2Op, ProfileID: profile.ID, Namespace: binding.Namespace,
		ProbeIPv4: policy.IdentIPv4, TunnelGeneration: testLabGenerationA}) ||
		token.Claims.HelperID != info.HelperID || token.Claims.NotAfter-token.Claims.IssuedAt != 30 ||
		!labProbeNoncePattern.MatchString(token.Claims.Nonce) {
		t.Fatalf("invalid generation-bound capability: %+v", token.Claims)
	}

	before := signer.signs

	for name, mutate := range map[string]func(*LabMultiProbeTarget){
		"missing generation":   func(target *LabMultiProbeTarget) { target.TunnelGeneration = "" },
		"malformed generation": func(target *LabMultiProbeTarget) { target.TunnelGeneration = "tunnelgen_invalid" },
		"legacy policy":        func(target *LabMultiProbeTarget) { target.Policy = LabMultiProbeOp },
		"unsupported policy":   func(target *LabMultiProbeTarget) { target.Policy = "PermitMultiProbeV3" },
		"foreign profile":      func(target *LabMultiProbeTarget) { target.ProfileID = "profile_ffffffffffffffff" },
		"foreign namespace":    func(target *LabMultiProbeTarget) { target.Namespace = "egresslab-lab-ffffffffffffffff" },
		"foreign runtime": func(target *LabMultiProbeTarget) {
			target.RuntimeID = "runtime_ffffffffffffffffffffffffffffffff"
		},
		"foreign epoch": func(target *LabMultiProbeTarget) { target.HelperID = "helper_ffffffffffffffffffffffffffffffff" },
		"foreign key":   func(target *LabMultiProbeTarget) { target.PublicKeySHA256 = strings.Repeat("f", 64) },
		"invalid pin":   func(target *LabMultiProbeTarget) { target.IdentIPv4 = "10.0.0.1" },
	} {
		bad := target
		mutate(&bad)

		if _, err := MintPermitMultiProbeV2(signer, profile, binding, info, lab, bad, now); err == nil {
			t.Errorf("%s was signed", name)
		}
	}

	sealed := lab
	sealed.State = LabSealed

	if _, err := MintPermitMultiProbeV2(signer, profile, binding, info, sealed, target, now); err == nil {
		t.Error("sealed lab was signed")
	}

	if _, err := MintPermitMultiProbe(signer, profile, binding, info, lab, policy, now); err == nil {
		t.Error("V1 signed from a V2 policy")
	}

	if signer.signs != before {
		t.Fatal("a refused target reached the signer")
	}

	target.TunnelGeneration = testLabGenerationB

	next, err := MintPermitMultiProbeV2(signer, profile, binding, info, lab, target, now)
	if err != nil || next.Claims.Intent.TunnelGeneration != testLabGenerationB || next.Claims.Nonce == token.Claims.Nonce {
		t.Fatalf("invalid next capability: %+v %v", next.Claims, err)
	}
}

func generationProbeEvidence() (LabMultiProbeInfo, LabCapability) {
	info, intent := testMultiProbeInfo()
	intent.Operation = LabMultiProbeV2Op
	intent.TunnelGeneration = testLabGenerationA

	claims := goldenClaims(intent)
	claims.IssuedAt = info.StartedAt.Unix() - 1
	claims.NotAfter = claims.IssuedAt + 30

	info.TunnelGeneration = testLabGenerationA
	info.AttemptNonce = claims.Nonce

	return info, LabCapability{Claims: claims}
}

func TestGenerationProbeEvidence(t *testing.T) {
	info, capability := generationProbeEvidence()
	intent := capability.Claims.Intent
	sent, received := info.StartedAt, info.FinishedAt.Add(time.Second)

	if !info.ValidForCapability(capability, sent, received) {
		t.Fatal("valid V2 evidence refused")
	}

	for name, mutate := range map[string]func(*LabMultiProbeInfo){
		"missing generation": func(p *LabMultiProbeInfo) { p.TunnelGeneration = "" },
		"wrong generation":   func(p *LabMultiProbeInfo) { p.TunnelGeneration = testLabGenerationB },
		"missing nonce":      func(p *LabMultiProbeInfo) { p.AttemptNonce = "" },
		"wrong nonce":        func(p *LabMultiProbeInfo) { p.AttemptNonce = strings.Repeat("f", 32) },
		"malformed nonce":    func(p *LabMultiProbeInfo) { p.AttemptNonce = "nonce_invalid" },
		"legacy response":    func(p *LabMultiProbeInfo) { p.TunnelGeneration, p.AttemptNonce = "", "" },
		"another valid pin":  func(p *LabMultiProbeInfo) { p.Sources[1].DestinationIPv4 = netip.MustParseAddr("8.8.8.8") },
	} {
		bad := info
		bad.Sources = slices.Clone(info.Sources)
		mutate(&bad)

		if bad.ValidForCapability(capability, sent, received) {
			t.Errorf("%s accepted", name)
		}
	}

	for name, edit := range map[string]func(*LabClaims){
		"previous attempt": func(c *LabClaims) { c.Nonce = strings.Repeat("a", 32) },
		"V1 operation": func(c *LabClaims) {
			c.Intent.Operation, c.Intent.TunnelGeneration = LabMultiProbeOp, ""
		},
		"other generation":  func(c *LabClaims) { c.Intent.TunnelGeneration = testLabGenerationB },
		"unknown version":   func(c *LabClaims) { c.Version = 2 },
		"malformed helper":  func(c *LabClaims) { c.HelperID = "helper_x" },
		"lifetime over 30s": func(c *LabClaims) { c.NotAfter = c.IssuedAt + 31 },
	} {
		other := capability
		edit(&other.Claims)

		if info.ValidForCapability(other, sent, received) {
			t.Errorf("%s accepted", name)
		}
	}

	observedDeadline := info.ObservedAt.Add(60 * time.Second)

	if !info.ValidForCapability(capability, sent, observedDeadline.Add(-time.Nanosecond)) ||
		info.ValidForCapability(capability, sent, observedDeadline) {
		t.Fatal("V2 evidence not bounded by 60 s from its oldest observation")
	}

	short := capability
	short.Claims.NotAfter = info.StartedAt.Unix()

	if !info.ValidForCapability(short, info.StartedAt.Add(-time.Second), received) ||
		info.ValidForCapability(short, info.StartedAt, received) {
		t.Fatal("capability expiry not enforced at submission")
	}

	for name, times := range map[string][2]time.Time{
		"started before the request": {info.StartedAt.Add(6 * time.Second), received},
		"finished after receipt":     {sent, info.FinishedAt.Add(-6 * time.Second)},
		"received before sent":       {received, sent},
	} {
		if info.ValidForCapability(capability, times[0], times[1]) {
			t.Errorf("%s accepted", name)
		}
	}

	issued := time.Unix(capability.Claims.IssuedAt, 0)

	if info.ValidFor(intent, issued, sent, received) {
		t.Fatal("V2 evidence accepted by the legacy validator")
	}

	legacy, legacyIntent := testMultiProbeInfo()
	legacy.TunnelGeneration, legacy.AttemptNonce = info.TunnelGeneration, info.AttemptNonce

	if legacy.MatchesIntent(legacyIntent) {
		t.Fatal("V2 evidence matched a V1 intent")
	}

	for name, edit := range map[string]func(*LabMultiProbeInfo){
		"generation without nonce": func(p *LabMultiProbeInfo) { p.AttemptNonce = "" },
		"nonce without generation": func(p *LabMultiProbeInfo) { p.TunnelGeneration = "" },
		"malformed generation":     func(p *LabMultiProbeInfo) { p.TunnelGeneration = "tunnelgen_invalid" },
	} {
		bad := info
		edit(&bad)

		if bad.Valid() {
			t.Errorf("%s valid", name)
		}
	}
}
