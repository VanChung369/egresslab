package control

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"testing"
	"time"
)

func TestMintConnectTunnel(t *testing.T) {
	signer, profile, info := labTestFixture()
	info.RuntimeID = "runtime_0123456789abcdef0123456789abcdef"
	now := time.Unix(1795500000, 0)

	binding := RuntimeBinding{
		ProfileID:   profile.ID,
		RuntimeID:   info.RuntimeID,
		Namespace:   "egresslab-lab-0123456789abcdef",
		HelperEpoch: info.HelperID,
		UpdatedAt:   now,
	}

	stage := LabStageInfo{ProfileID: profile.ID, StageID: "wgstage_0123456789abcdef0123456789abcdef", Compatible: true}

	token, err := MintConnectTunnel(signer, profile, binding, info, stage, now)
	if err != nil {
		t.Fatal(err)
	}

	expected := LabIntent{Operation: "ConnectTunnel", ProfileID: profile.ID, Namespace: binding.Namespace, StageID: stage.StageID}

	if token.Claims.Intent != expected || token.Claims.HelperID != info.HelperID ||
		token.Claims.NotAfter-token.Claims.IssuedAt != 30 {
		t.Fatalf("invalid claims: %+v", token.Claims)
	}

	raw, err := json.Marshal(token.Claims)
	if err != nil {
		t.Fatal(err)
	}

	signature, err := base64.RawURLEncoding.DecodeString(token.Signature)
	if err != nil {
		t.Fatal(err)
	}

	public, err := signer.PublicKey()
	if err != nil {
		t.Fatal(err)
	}

	if !ed25519.Verify(public, append([]byte(labCapabilityDomain), raw...), signature) {
		t.Fatal("invalid tunnel capability signature")
	}

	type request struct {
		p RoutingProfile
		b RuntimeBinding
		i LabHelperInfo
		s LabStageInfo
	}

	tests := map[string]func(*request){
		"foreign runtime":     func(r *request) { r.b.RuntimeID = "runtime_ffffffffffffffffffffffffffffffff" },
		"no runtime ID":       func(r *request) { r.b.RuntimeID, r.i.RuntimeID = "", "" },
		"old helper epoch":    func(r *request) { r.b.HelperEpoch = "helper_ffffffffffffffffffffffffffffffff" },
		"no namespace":        func(r *request) { r.b.Namespace = "" },
		"another profile":     func(r *request) { r.b.ProfileID = "profile_ffffffffffffffff" },
		"foreign stage":       func(r *request) { r.s.ProfileID = "profile_ffffffffffffffff" },
		"malformed stage":     func(r *request) { r.s.StageID = "wgstage_x" },
		"incompatible config": func(r *request) { r.s.Compatible = false },
		"no kill switch":      func(r *request) { r.p.KillSwitchRequired = false },
		"active profile":      func(r *request) { r.p.Status = "active" },
		"other helper key":    func(r *request) { r.i.PublicKeySHA256 = "00" + r.i.PublicKeySHA256[2:] },
		"no authorization":    func(r *request) { r.i.AuthorizationConfigured = false },
	}

	for name, change := range tests {
		t.Run(name, func(t *testing.T) {
			r := request{profile, binding, info, stage}
			change(&r)

			before := signer.signs

			if _, err := MintConnectTunnel(signer, r.p, r.b, r.i, r.s, now); err == nil {
				t.Fatal("unsafe capability minted")
			}

			if signer.signs != before {
				t.Fatal("signer called for a refused request")
			}
		})
	}
}
