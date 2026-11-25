package control

import (
	"net/netip"
	"testing"
	"time"
)

func TestMintPermitProbe(t *testing.T) {
	signer, profile, info := labTestFixture()
	now := time.Unix(1795500000, 0)
	info.RuntimeID = "runtime_0123456789abcdef0123456789abcdef"

	binding := RuntimeBinding{
		ProfileID:   profile.ID,
		RuntimeID:   info.RuntimeID,
		Namespace:   "egresslab-lab-0123456789abcdef",
		HelperEpoch: info.HelperID,
		UpdatedAt:   now,
	}

	lab := LabInfo{ProfileID: profile.ID, Namespace: binding.Namespace, State: LabTunnelConfigured}

	token, err := MintPermitProbe(signer, profile, binding, info, lab, now)
	if err != nil {
		t.Fatal(err)
	}

	expected := LabIntent{
		Operation: "PermitProbe",
		ProfileID: profile.ID,
		Namespace: binding.Namespace,
		ProbeIPv4: LabProbeIPv4,
	}

	if token.Claims.Intent != expected || token.Claims.HelperID != info.HelperID ||
		token.Claims.NotAfter-token.Claims.IssuedAt != 30 {
		t.Fatal("invalid probe claims")
	}

	before := signer.signs

	refusals := map[string]func() (LabCapability, error){
		"sealed lab": func() (LabCapability, error) {
			l := lab
			l.State = LabSealed
			return MintPermitProbe(signer, profile, binding, info, l, now)
		},
		"faulted lab": func() (LabCapability, error) {
			l := lab
			l.State = LabFaulted
			return MintPermitProbe(signer, profile, binding, info, l, now)
		},
		"another namespace": func() (LabCapability, error) {
			l := lab
			l.Namespace = "egresslab-lab-ffffffffffffffff"
			return MintPermitProbe(signer, profile, binding, info, l, now)
		},
		"stale helper epoch": func() (LabCapability, error) {
			b := binding
			b.HelperEpoch = "helper_ffffffffffffffffffffffffffffffff"
			return MintPermitProbe(signer, profile, b, info, lab, now)
		},
		"another runtime": func() (LabCapability, error) {
			b := binding
			b.RuntimeID = "runtime_ffffffffffffffffffffffffffffffff"
			return MintPermitProbe(signer, profile, b, info, lab, now)
		},
		"active profile": func() (LabCapability, error) {
			p := profile
			p.Status = "active"
			return MintPermitProbe(signer, p, binding, info, lab, now)
		},
		"no kill switch": func() (LabCapability, error) {
			p := profile
			p.KillSwitchRequired = false
			return MintPermitProbe(signer, p, binding, info, lab, now)
		},
	}

	for name, mint := range refusals {
		if _, err := mint(); err == nil {
			t.Errorf("%s accepted", name)
		}
	}

	if signer.signs != before {
		t.Fatal("refused requests reached the signer")
	}
}

func TestProbeObservationValidation(t *testing.T) {
	now := time.Unix(1795500000, 0)

	valid := LabProbeInfo{
		ProfileID:   "profile_0123456789abcdef",
		Namespace:   "egresslab-lab-0123456789abcdef",
		IPv4:        netip.MustParseAddr("8.8.4.4"),
		ObservedAt:  now,
		HandshakeAt: now.Add(-time.Second),
		Source:      LabProbeSource,
	}

	if !valid.ValidFor(valid.ProfileID, valid.Namespace, now.Add(-time.Second), now) {
		t.Fatal("valid observation rejected")
	}

	for _, ip := range []string{
		"10.0.0.1", "172.16.0.1", "192.168.1.1", "127.0.0.1", "100.64.0.1", "169.254.169.254",
		"198.51.100.1", "203.0.113.1", "224.0.0.1", "240.0.0.1", "0.0.0.1", "2001:db8::1",
	} {
		bad := valid
		bad.IPv4 = netip.MustParseAddr(ip)

		if bad.Valid() {
			t.Errorf("invalid IP accepted: %s", ip)
		}
	}

	for name, tt := range map[string]struct {
		edit                 func(*LabProbeInfo)
		issuedAt, receivedAt time.Time
	}{
		"stale observation":        {nil, now.Add(-100 * time.Second), now.Add(91 * time.Second)},
		"observed before issuing":  {nil, now.Add(10 * time.Second), now.Add(10 * time.Second)},
		"observed in the future":   {nil, now.Add(-20 * time.Second), now.Add(-10 * time.Second)},
		"foreign profile":          {func(p *LabProbeInfo) { p.ProfileID = "profile_ffffffffffffffff" }, now, now},
		"foreign namespace":        {func(p *LabProbeInfo) { p.Namespace = "egresslab-lab-ffffffffffffffff" }, now, now},
		"other source":             {func(p *LabProbeInfo) { p.Source = "other" }, now, now},
		"stale handshake":          {func(p *LabProbeInfo) { p.HandshakeAt = now.Add(-181 * time.Second) }, now, now},
		"handshake in the future":  {func(p *LabProbeInfo) { p.HandshakeAt = now.Add(10 * time.Second) }, now, now},
		"no handshake":             {func(p *LabProbeInfo) { p.HandshakeAt = time.Time{} }, now, now},
		"no observation timestamp": {func(p *LabProbeInfo) { p.ObservedAt = time.Time{} }, now, now},
	} {
		changed := valid
		if tt.edit != nil {
			tt.edit(&changed)
		}

		if changed.ValidFor(valid.ProfileID, valid.Namespace, tt.issuedAt, tt.receivedAt) {
			t.Errorf("%s accepted", name)
		}
	}
}
