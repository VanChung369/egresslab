package control

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"testing"
	"time"
)

// testReservationAdmission builds one complete admission: real Ed25519 capabilities from the
// controller's test key, synthetic addresses and observations, no network.
func testReservationAdmission(t *testing.T, profileNumber, runtimeNumber, generationNumber int, rawIP string,
	base time.Time) candidateAdmission {
	t.Helper()

	signer, profile, helper, binding, lab, policy := multiProbeFixture()

	profile.ID = fmt.Sprintf("profile_%016x", profileNumber)
	helper.RuntimeID = fmt.Sprintf("runtime_%032x", runtimeNumber)
	helper.HelperID = fmt.Sprintf("helper_%032x", runtimeNumber)

	binding.ProfileID = profile.ID
	binding.RuntimeID = helper.RuntimeID
	binding.HelperEpoch = helper.HelperID
	binding.Namespace = fmt.Sprintf("egresslab-lab-%016x", profileNumber)
	binding.UpdatedAt = base.Add(-time.Minute)

	lab.ProfileID = profile.ID
	lab.Namespace = binding.Namespace
	lab.State = LabTunnelConfigured

	policy.Policy = LabMultiProbeV2Op
	policy.RuntimeID = helper.RuntimeID
	policy.HelperID = helper.HelperID

	target := LabMultiProbeTarget{
		ProfileID:           profile.ID,
		Namespace:           binding.Namespace,
		TunnelGeneration:    fmt.Sprintf("tunnelgen_%032x", generationNumber),
		LabMultiProbePolicy: policy,
	}

	rt := TrustedRuntime{
		ID:              helper.RuntimeID,
		Provider:        "wsl",
		Target:          fmt.Sprintf("Ubuntu-%d", runtimeNumber),
		PublicKeySHA256: helper.PublicKeySHA256,
		TrustedAt:       base.Add(-time.Minute),
	}

	probeCapability, err := MintPermitMultiProbeV2(signer, profile, binding, helper, lab, target, base)
	if err != nil {
		t.Fatal(err)
	}

	ip := netip.MustParseAddr(rawIP)

	probe := LabMultiProbeInfo{
		ProfileID:        profile.ID,
		Namespace:        binding.Namespace,
		IPv4:             ip,
		StartedAt:        base.Add(time.Second),
		FinishedAt:       base.Add(7 * time.Second),
		ObservedAt:       base.Add(2 * time.Second),
		HandshakeAt:      base.Add(time.Second),
		TunnelGeneration: target.TunnelGeneration,
		AttemptNonce:     probeCapability.Claims.Nonce,
		Sources: []LabMultiProbeSourceInfo{
			{Source: LabProbeSource, DestinationIPv4: netip.MustParseAddr(LabProbeIPv4), IPv4: ip,
				ObservedAt: base.Add(2 * time.Second)},
			{Source: LabMultiProbeIdentSource, DestinationIPv4: netip.MustParseAddr(target.IdentIPv4), IPv4: ip,
				ObservedAt: base.Add(5 * time.Second)},
		},
	}

	reserveIntent, err := NewLabReserveEgressCandidateIntent(profile.ID, binding.Namespace, target.IdentIPv4,
		target.TunnelGeneration, probe.AttemptNonce)
	if err != nil {
		t.Fatal(err)
	}

	// Tests only: the production reservation signer comes with Step 31D.
	reserveCapability, err := mintLabCapability(signer, reserveIntent, helper, base.Add(9*time.Second))
	if err != nil {
		t.Fatal(err)
	}

	public, err := signer.PublicKey()
	if err != nil {
		t.Fatal(err)
	}

	return candidateAdmission{
		profile:   profile,
		binding:   binding,
		runtime:   rt,
		helper:    helper,
		lab:       lab,
		publicKey: public,
		target:    target,

		probe:           probe,
		probeCapability: probeCapability,
		probeSentAt:     base,
		probeReceivedAt: base.Add(8 * time.Second),

		receipt: LabCandidateInfo{
			LabMultiProbeTarget: target,
			EvidenceNonce:       probe.AttemptNonce,
			ReservationNonce:    reserveCapability.Claims.Nonce,
			IPv4:                ip,
			ObservedAt:          probe.ObservedAt,
			ExpiresAt:           base.Add(time.Minute),
		},
		reserveCapability: reserveCapability,
		reserveSentAt:     base.Add(9 * time.Second),
		reserveReceivedAt: base.Add(10 * time.Second),
	}
}

var reservationTestBase = time.Unix(1795500000, 0).UTC()

func TestCandidateAdmissionValid(t *testing.T) {
	base := reservationTestBase
	a := testReservationAdmission(t, 1, 1, 1, "8.8.4.4", base)

	candidate, err := validateCandidateAdmission(a, base.Add(11*time.Second))
	if err != nil {
		t.Fatal(err)
	}

	if !candidate.owner.Valid() ||
		candidate.owner.ProfileID != a.profile.ID ||
		candidate.owner.RuntimeID != a.runtime.ID ||
		candidate.owner.HelperEpoch != a.helper.HelperID ||
		candidate.owner.Namespace != a.binding.Namespace ||
		candidate.owner.TunnelGeneration != a.target.TunnelGeneration ||
		candidate.receipt.IPv4 != a.probe.IPv4 {
		t.Fatal("incorrect admitted candidate")
	}

	// The helper's deadline is base+60 s; the 5 s margin makes it base+55 s.
	if want := base.Add(55 * time.Second); !candidate.eligibleUntil.Equal(want) {
		t.Fatalf("eligibility deadline %s, want %s", candidate.eligibleUntil, want)
	}
}

func TestCandidateAdmissionRejectsInvalid(t *testing.T) {
	base := reservationTestBase

	for name, mutate := range map[string]func(*candidateAdmission){
		"non-strict profile":               func(a *candidateAdmission) { a.profile.UniqueIPRequired = false },
		"kill-switch disabled":             func(a *candidateAdmission) { a.profile.KillSwitchRequired = false },
		"sealed lab":                       func(a *candidateAdmission) { a.lab.State = LabSealed },
		"foreign runtime":                  func(a *candidateAdmission) { a.runtime.ID = "runtime_ffffffffffffffffffffffffffffffff" },
		"runtime key not pinned":           func(a *candidateAdmission) { a.runtime.PublicKeySHA256 = strings.Repeat("0", 64) },
		"runtime trusted after the probe":  func(a *candidateAdmission) { a.runtime.TrustedAt = a.probeSentAt.Add(time.Second) },
		"untrusted runtime target":         func(a *candidateAdmission) { a.runtime.Provider = "remote" },
		"stale helper epoch":               func(a *candidateAdmission) { a.binding.HelperEpoch = "helper_ffffffffffffffffffffffffffffffff" },
		"wrong generation":                 func(a *candidateAdmission) { a.receipt.TunnelGeneration = "tunnelgen_ffffffffffffffffffffffffffffffff" },
		"wrong receipt IP":                 func(a *candidateAdmission) { a.receipt.IPv4 = netip.MustParseAddr("8.8.8.8") },
		"private receipt IP":               func(a *candidateAdmission) { a.receipt.IPv4 = netip.MustParseAddr("10.0.0.1") },
		"mapped IPv6":                      func(a *candidateAdmission) { a.receipt.IPv4 = netip.MustParseAddr("::ffff:8.8.4.4") },
		"wrong observed timestamp":         func(a *candidateAdmission) { a.receipt.ObservedAt = a.receipt.ObservedAt.Add(time.Second) },
		"wrong evidence nonce":             func(a *candidateAdmission) { a.receipt.EvidenceNonce = strings.Repeat("f", 32) },
		"wrong reservation nonce":          func(a *candidateAdmission) { a.receipt.ReservationNonce = strings.Repeat("f", 32) },
		"wrong source pin":                 func(a *candidateAdmission) { a.receipt.IdentIPv4 = "8.8.8.8" },
		"legacy source policy":             func(a *candidateAdmission) { a.receipt.Policy = LabMultiProbeOp },
		"extended evidence TTL":            func(a *candidateAdmission) { a.receipt.ExpiresAt = a.receipt.ObservedAt.Add(61 * time.Second) },
		"probe evidence for another IP":    func(a *candidateAdmission) { a.probe.IPv4 = netip.MustParseAddr("8.8.8.8") },
		"forged probe signature":           func(a *candidateAdmission) { a.probeCapability.Signature = "invalid" },
		"forged reservation signature":     func(a *candidateAdmission) { a.reserveCapability.Signature = "invalid" },
		"unexpected public key":            func(a *candidateAdmission) { a.publicKey = make([]byte, 32) },
		"reservation before probe receipt": func(a *candidateAdmission) { a.reserveSentAt = a.probeReceivedAt.Add(-time.Second) },
		"backdated reservation receipt":    func(a *candidateAdmission) { a.reserveReceivedAt = a.reserveSentAt.Add(-time.Second) },
		"backdated probe receipt":          func(a *candidateAdmission) { a.probeReceivedAt = a.probeSentAt.Add(-time.Second) },
	} {
		t.Run(name, func(t *testing.T) {
			a := testReservationAdmission(t, 1, 1, 1, "8.8.4.4", base)
			mutate(&a)

			if _, err := validateCandidateAdmission(a, base.Add(11*time.Second)); !errors.Is(err, ErrReservationCandidateInvalid) {
				t.Fatalf("invalid candidate accepted: %v", err)
			}
		})
	}

	// A signature valid in itself but by another key.
	t.Run("capability signed by another key", func(t *testing.T) {
		a := testReservationAdmission(t, 1, 1, 1, "8.8.4.4", base)
		other := testReservationAdmission(t, 1, 1, 1, "8.8.4.4", base)
		other.publicKey[0] ^= 0xff

		if verifyIssuedLabCapability(other.publicKey, a.reserveCapability) {
			t.Fatal("signature accepted for another key")
		}
	})
}

func TestCandidateAdmissionDeadline(t *testing.T) {
	base := reservationTestBase
	a := testReservationAdmission(t, 1, 1, 1, "8.8.4.4", base)

	if _, err := validateCandidateAdmission(a, base.Add(55*time.Second-time.Nanosecond)); err != nil {
		t.Fatalf("fresh candidate rejected: %v", err)
	}

	for _, now := range []time.Time{
		base.Add(55 * time.Second),
		base.Add(56 * time.Second),
		base.Add(time.Minute),
		base.Add(2 * time.Minute),
	} {
		if _, err := validateCandidateAdmission(a, now); !errors.Is(err, ErrReservationCandidateExpired) {
			t.Fatalf("expired candidate accepted at %s: %v", now, err)
		}
	}

	// The controller clock must not run behind the recorded receipt time.
	if _, err := validateCandidateAdmission(a, a.reserveReceivedAt.Add(-time.Second)); !errors.Is(err, ErrReservationCandidateInvalid) {
		t.Fatalf("backdated admission accepted: %v", err)
	}
}

// The host-side bound (60 s after the probe was sent) wins when the helper's deadline, minus the
// margin, would be later. The capabilities sign no observation time, so only those move.
func TestCandidateAdmissionHostDeadlineCap(t *testing.T) {
	base := reservationTestBase
	a := testReservationAdmission(t, 1, 1, 1, "8.8.4.4", base)

	observed := base.Add(6 * time.Second)
	a.probe.ObservedAt = observed
	a.probe.Sources[0].ObservedAt = observed
	a.probe.Sources[1].ObservedAt = observed.Add(500 * time.Millisecond)
	a.receipt.ObservedAt = observed
	a.receipt.ExpiresAt = observed.Add(labGenerationProbeFreshness) // base+66 s

	candidate, err := validateCandidateAdmission(a, base.Add(11*time.Second))
	if err != nil {
		t.Fatal(err)
	}

	if want := base.Add(labGenerationProbeFreshness); !candidate.eligibleUntil.Equal(want) {
		t.Fatalf("eligibility deadline %s, want the host bound %s", candidate.eligibleUntil, want)
	}
}

// Every part is valid and correctly signed, but the probe is another attempt than the one the
// receipt consumed: only the evidence binding can refuse it.
func TestCandidateAdmissionRejectsAnotherAttempt(t *testing.T) {
	base := reservationTestBase
	a := testReservationAdmission(t, 1, 1, 1, "8.8.4.4", base)
	other := testReservationAdmission(t, 1, 1, 1, "8.8.4.4", base)

	a.probe, a.probeCapability = other.probe, other.probeCapability

	if _, err := validateCandidateAdmission(a, base.Add(11*time.Second)); !errors.Is(err, ErrReservationCandidateInvalid) {
		t.Fatalf("receipt bound to another probe attempt accepted: %v", err)
	}
}

func TestMintReserveEgressCandidate(t *testing.T) {
	base := reservationTestBase
	valid := testReservationAdmission(t, 1, 1, 1, "8.8.4.4", base)

	mint := func(a candidateAdmission, signer LabSigner, now time.Time) (LabCapability, error) {
		return mintReserveEgressCandidate(signer, a.profile, a.binding, a.helper, a.lab, a.target, a.probe,
			a.probeCapability, a.probeSentAt, a.probeReceivedAt, now)
	}

	signer := newSeedSigner()
	now := valid.reserveSentAt

	capability, err := mint(valid, signer, now)
	if err != nil {
		t.Fatal(err)
	}

	expected, err := NewLabReserveEgressCandidateIntent(valid.profile.ID, valid.binding.Namespace, valid.target.IdentIPv4,
		valid.target.TunnelGeneration, valid.probe.AttemptNonce)
	if err != nil || capability.Claims.Intent != expected || capability.Claims.HelperID != valid.helper.HelperID ||
		capability.Claims.IssuedAt != now.Unix() || capability.Claims.Nonce == valid.probe.AttemptNonce ||
		!verifyIssuedLabCapability(valid.publicKey, capability) || signer.signs != 1 {
		t.Fatalf("unexpected candidate capability: %+v %v", capability, err)
	}

	for name, tt := range map[string]struct {
		mutate func(*candidateAdmission, *time.Time)
		want   error
	}{
		"tampered probe signature": {func(a *candidateAdmission, _ *time.Time) {
			sig := []byte(a.probeCapability.Signature)
			sig[0] ^= 1
			a.probeCapability.Signature = string(sig)
		}, ErrReservationCandidateInvalid},
		"other generation": {func(a *candidateAdmission, _ *time.Time) {
			a.target.TunnelGeneration = "tunnelgen_ffffffffffffffffffffffffffffffff"
		}, ErrReservationCandidateInvalid},
		"foreign target helper": {func(a *candidateAdmission, _ *time.Time) {
			a.target.HelperID = "helper_ffffffffffffffffffffffffffffffff"
		}, ErrReservationCandidateInvalid},
		"other attempt": {func(a *candidateAdmission, _ *time.Time) {
			a.probe.AttemptNonce = "ffffffffffffffffffffffffffffffff"
		}, ErrReservationCandidateInvalid},
		"clock before the probe": {func(a *candidateAdmission, now *time.Time) {
			*now = a.probeSentAt.Add(-time.Second)
		}, ErrReservationCandidateInvalid},
		"60 s after sending": {func(a *candidateAdmission, now *time.Time) {
			*now = a.probeSentAt.Add(labGenerationProbeFreshness)
		}, ErrReservationCandidateExpired},
		"55 s after the observation": {func(a *candidateAdmission, now *time.Time) {
			*now = a.probe.ObservedAt.Add(labGenerationProbeFreshness - labProbeClockSkew)
		}, ErrReservationCandidateExpired},
		"stale binding": {func(a *candidateAdmission, _ *time.Time) {
			a.binding.HelperEpoch = "helper_ffffffffffffffffffffffffffffffff"
		}, nil},
	} {
		t.Run(name, func(t *testing.T) {
			a, at := valid, now
			tt.mutate(&a, &at)

			s := newSeedSigner()
			_, err := mint(a, s, at)

			if err == nil || (tt.want != nil && !errors.Is(err, tt.want)) || s.signs != 0 {
				t.Fatalf("got %v after %d signatures", err, s.signs)
			}
		})
	}

	other := &seedSigner{private: ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x24}, ed25519.SeedSize))}
	if _, err := mint(valid, other, now); !errors.Is(err, ErrReservationCandidateInvalid) || other.signs != 0 {
		t.Fatalf("another controller key signed: %v", err)
	}
}
