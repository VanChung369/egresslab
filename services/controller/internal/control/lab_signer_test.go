package control

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"testing"
	"time"
)

type seedSigner struct {
	private ed25519.PrivateKey
	signs   int
}

func newSeedSigner() *seedSigner {
	return &seedSigner{private: ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x42}, ed25519.SeedSize))}
}

func (s *seedSigner) PublicKey() (ed25519.PublicKey, error) {
	return s.private.Public().(ed25519.PublicKey), nil
}

func (s *seedSigner) Sign(message []byte) ([]byte, error) {
	s.signs++
	return ed25519.Sign(s.private, message), nil
}

func goldenClaims(intent LabIntent) LabClaims {
	return LabClaims{
		Version:  1,
		Intent:   intent,
		HelperID: "helper_0123456789abcdef0123456789abcdef",
		Nonce:    "00112233445566778899aabbccddeeff",
		IssuedAt: 1795500000,
		NotAfter: 1795500030,
	}
}

// Same vectors as the network agent's TestSigningMessageGolden, TestCreateLabSigningMessageGolden,
// TestPermitProbeSigningMessageGolden, TestPermitMultiProbeSigningMessageGolden and
// TestPermitMultiProbeV2SigningMessageGolden, so the controller's JSON matches the helper's byte
// for byte.
func TestLabSignerGolden(t *testing.T) {
	tests := map[string]struct {
		intent LabIntent
		want   string
	}{
		"ConnectTunnel": {
			LabIntent{Operation: "ConnectTunnel", ProfileID: "profile_0123456789abcdef",
				Namespace: "egresslab-lab-0123456789abcdef", StageID: "wgstage_0123456789abcdef0123456789abcdef"},
			"_46Bh7TESfJcvG71RrKSxFLq31MPs2VrLI8U3Jt7tgb_PRdTvnDdITVMvKJ5DHvFkaRQzDWwHUvxxRgpHlXCCw",
		},
		"CreateLab": {
			LabIntent{Operation: "CreateLab", ProfileID: "profile_0123456789abcdef"},
			"jYuiWZqwyviLOxTYGLcz_UXkxmrO-Gk_Q2kEc0-hKtSTm4r59a1u-a0QFI44sYJPe6XL8EuKbS0_5kjA_o-NDw",
		},
		"PermitProbe": {
			LabIntent{Operation: "PermitProbe", ProfileID: "profile_0123456789abcdef",
				Namespace: "egresslab-lab-0123456789abcdef", ProbeIPv4: LabProbeIPv4},
			"Jd8xQ1dVXMy2Ahpa80HfrJbmLs54zKuV4NCcUBBVCR2Xz-XFHdWc_0AAv1BVYhi7G3taO1pQBWozslB-9StIBQ",
		},
		"PermitMultiProbeV1": {
			LabIntent{Operation: LabMultiProbeOp, ProfileID: "profile_0123456789abcdef",
				Namespace: "egresslab-lab-0123456789abcdef", ProbeIPv4: "9.9.9.9"},
			"XepTcoWImAW-vewRsc-T_gOfB3NWD1Rr6-xch0blj9kS2ECoA_DBoybFDCUmSDJPuu_j5Tw8IPSmysPeosU5BA",
		},
		"PermitMultiProbeV2": {
			LabIntent{Operation: LabMultiProbeV2Op, ProfileID: "profile_0123456789abcdef",
				Namespace: "egresslab-lab-0123456789abcdef", ProbeIPv4: "9.9.9.9",
				TunnelGeneration: "tunnelgen_0123456789abcdef0123456789abcdef"},
			"sRRT76f9zHhm22LwX3wRFj1qqP2ug7YzPXCTXaBL3B50bwejThRjeVWLt6Kk33HRkLC3ugajV3ksNo2MUxONCw",
		},
		// From TestReserveEgressCandidateSigningMessageGolden in the network agent (cross-checked with
		// OpenSSL 3).
		"ReserveEgressCandidateV1": {
			LabIntent{Operation: LabReserveEgressCandidateOp, ProfileID: "profile_0123456789abcdef",
				Namespace: "egresslab-lab-0123456789abcdef", ProbeIPv4: "9.9.9.9",
				TunnelGeneration: "tunnelgen_0123456789abcdef0123456789abcdef",
				EvidenceNonce:    "ffeeddccbbaa99887766554433221100"},
			"WrDOmIHMAE-VvemqyqyxXj4iSwf_nJeFu9I0gTqRdcopF2fCfQxnYbidX_0WCkX8dEDzvUwBMclAf8R_Bq0jCg",
		},
		// From TestPrepareEgressLeaseSigningMessageGolden in the network agent.
		"PrepareEgressLeaseV1": {
			LabIntent{Operation: LabPrepareEgressLeaseOp, ProfileID: "profile_0123456789abcdef",
				Namespace: "egresslab-lab-0123456789abcdef", ProbeIPv4: "9.9.9.9",
				TunnelGeneration: "tunnelgen_0123456789abcdef0123456789abcdef",
				EvidenceNonce:    "ffeeddccbbaa99887766554433221100",
				ReservationNonce: "aabbccddeeff00112233445566778899",
				RuntimeID:        "runtime_0123456789abcdef0123456789abcdef",
				AuthorityID:      "authority_0123456789abcdef0123456789abcdef",
				ReservationID:    "reservation_0123456789abcdef0123456789abcdef",
				EgressIPv4:       "8.8.4.4"},
			"0NoCsoeg6bZBAxHU5qrpNDO0xjOAOS5U98RnZVZUY-POYFxr48rVgpy17K6B2-scLAUC39hSIcsIh4KkTwyPBg",
		},
		// From TestRevokeEgressLeaseSigningMessageGolden in the network agent.
		"RevokeEgressLeaseV1": {
			LabIntent{Operation: LabRevokeEgressLeaseOp, ProfileID: "profile_0123456789abcdef",
				Namespace: "egresslab-lab-0123456789abcdef", ProbeIPv4: "9.9.9.9",
				TunnelGeneration: "tunnelgen_0123456789abcdef0123456789abcdef",
				EvidenceNonce:    "ffeeddccbbaa99887766554433221100",
				ReservationNonce: "aabbccddeeff00112233445566778899",
				RuntimeID:        "runtime_0123456789abcdef0123456789abcdef",
				AuthorityID:      "authority_0123456789abcdef0123456789abcdef",
				ReservationID:    "reservation_0123456789abcdef0123456789abcdef",
				EgressIPv4:       "8.8.4.4"},
			"eEGqTiEcjfhnoBNTQ_3cck8frTGITa2HuAxmDEhwxRe_SONZZN7T7Ito6UW1wTX8ze39YEwcEXuudlYI8DHlCQ",
		},
	}

	for name, tt := range tests {
		token, err := signLabClaims(newSeedSigner(), goldenClaims(tt.intent))
		if err != nil {
			t.Fatal(err)
		}

		if token.Signature != tt.want {
			t.Errorf("%s signature mismatch: %s", name, token.Signature)
		}
	}
}

func labTestFixture() (*seedSigner, RoutingProfile, LabHelperInfo) {
	signer := newSeedSigner()
	public, _ := signer.PublicKey()
	digest := sha256.Sum256(public)

	return signer,
		RoutingProfile{ID: "profile_0123456789abcdef", Status: "unconfigured", UniqueIPRequired: true, KillSwitchRequired: true},
		LabHelperInfo{
			AuthorizationConfigured: true,
			HelperID:                "helper_0123456789abcdef0123456789abcdef",
			PublicKeySHA256:         hex.EncodeToString(digest[:]),
		}
}

func TestMintCreateLab(t *testing.T) {
	signer, profile, info := labTestFixture()
	now := time.Unix(1795500000, 0)

	first, err := MintCreateLab(signer, profile, info, now)
	if err != nil {
		t.Fatal(err)
	}

	second, err := MintCreateLab(signer, profile, info, now)
	if err != nil {
		t.Fatal(err)
	}

	if first.Claims.Nonce == second.Claims.Nonce {
		t.Fatal("nonce reused")
	}

	if first.Claims.Intent != (LabIntent{Operation: "CreateLab", ProfileID: profile.ID}) ||
		first.Claims.HelperID != info.HelperID ||
		first.Claims.IssuedAt != now.Unix() ||
		first.Claims.NotAfter-first.Claims.IssuedAt != 30 {
		t.Fatalf("invalid signed claims: %+v", first.Claims)
	}

	raw, err := json.Marshal(first.Claims)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Contains(raw, []byte(`"namespace":""`)) {
		t.Fatalf("CreateLab must sign the empty namespace: %s", raw)
	}

	signature, err := base64.RawURLEncoding.DecodeString(first.Signature)
	if err != nil {
		t.Fatal(err)
	}

	public, _ := signer.PublicKey()
	if !ed25519.Verify(public, append([]byte(labCapabilityDomain), raw...), signature) {
		t.Fatal("invalid signature")
	}
}

func TestMintCreateLabRefusesWithoutSigning(t *testing.T) {
	_, profile, info := labTestFixture()
	now := time.Unix(1795500000, 0)

	wrongKey := info
	wrongKey.PublicKeySHA256 = hex.EncodeToString(make([]byte, sha256.Size))

	disabled := LabHelperInfo{}

	badID := info
	badID.HelperID = "helper_1234"

	cases := map[string]struct {
		profile RoutingProfile
		info    LabHelperInfo
		now     time.Time
	}{
		"untrusted helper key":  {profile, wrongKey, now},
		"unconfigured helper":   {profile, disabled, now},
		"malformed helper ID":   {profile, badID, now},
		"no unique IP policy":   {withProfile(profile, func(p *RoutingProfile) { p.UniqueIPRequired = false }), info, now},
		"no kill-switch policy": {withProfile(profile, func(p *RoutingProfile) { p.KillSwitchRequired = false }), info, now},
		"profile has a tunnel":  {withProfile(profile, func(p *RoutingProfile) { p.TunnelID = "tunnel_1" }), info, now},
		"profile status":        {withProfile(profile, func(p *RoutingProfile) { p.Status = "active" }), info, now},
		"malformed profile ID":  {withProfile(profile, func(p *RoutingProfile) { p.ID = "profile_x" }), info, now},
		"clock at epoch":        {profile, info, time.Unix(0, 0)},
	}

	for name, tt := range cases {
		signer := newSeedSigner()

		if _, err := MintCreateLab(signer, tt.profile, tt.info, tt.now); err == nil {
			t.Errorf("%s: capability minted", name)
		}

		if signer.signs != 0 {
			t.Errorf("%s: signer was called", name)
		}
	}
}

type failingSigner struct{ seedSigner }

func (failingSigner) Sign([]byte) ([]byte, error) { return []byte("short"), nil }

func TestMintCreateLabRejectsBadSignature(t *testing.T) {
	signer, profile, info := labTestFixture()

	if _, err := MintCreateLab(&failingSigner{*signer}, profile, info, time.Unix(1795500000, 0)); err == nil ||
		err.Error() != "signer returned an invalid signature" {
		t.Fatalf("short signature accepted: %v", err)
	}
}

func TestLabHelperInfoValid(t *testing.T) {
	_, _, info := labTestFixture()

	upper := info
	upper.PublicKeySHA256 = "AB" + info.PublicKeySHA256[2:]

	for name, tt := range map[string]struct {
		info LabHelperInfo
		want bool
	}{
		"configured":                 {info, true},
		"unconfigured":               {LabHelperInfo{}, true},
		"uppercase fingerprint":      {upper, false},
		"ID while unconfigured":      {LabHelperInfo{HelperID: info.HelperID}, false},
		"configured without a print": {LabHelperInfo{AuthorizationConfigured: true, HelperID: info.HelperID}, false},
	} {
		if got := tt.info.Valid(); got != tt.want {
			t.Errorf("%s: got %t", name, got)
		}
	}
}

func withProfile(p RoutingProfile, change func(*RoutingProfile)) RoutingProfile {
	change(&p)
	return p
}
