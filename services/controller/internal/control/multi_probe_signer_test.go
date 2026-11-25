package control

import (
	"net/netip"
	"slices"
	"testing"
	"time"
)

func multiProbeFixture() (*seedSigner, RoutingProfile, LabHelperInfo, RuntimeBinding, LabInfo, LabMultiProbePolicy) {
	signer, profile, info := labTestFixture()
	info.RuntimeID = "runtime_0123456789abcdef0123456789abcdef"

	binding := RuntimeBinding{
		ProfileID:   profile.ID,
		RuntimeID:   info.RuntimeID,
		Namespace:   "egresslab-lab-0123456789abcdef",
		HelperEpoch: info.HelperID,
		UpdatedAt:   time.Unix(1795500000, 0).UTC(),
	}

	lab := LabInfo{ProfileID: profile.ID, Namespace: binding.Namespace, State: LabTunnelConfigured}

	policy := LabMultiProbePolicy{
		Policy:          LabMultiProbeOp,
		IdentIPv4:       "9.9.9.9",
		HelperID:        info.HelperID,
		RuntimeID:       info.RuntimeID,
		PublicKeySHA256: info.PublicKeySHA256,
	}

	return signer, profile, info, binding, lab, policy
}

func TestMintPermitMultiProbe(t *testing.T) {
	signer, profile, info, binding, lab, policy := multiProbeFixture()
	now := time.Unix(1795500000, 0).UTC()

	token, err := MintPermitMultiProbe(signer, profile, binding, info, lab, policy, now)
	if err != nil {
		t.Fatal(err)
	}

	if token.Claims.Intent != (LabIntent{Operation: LabMultiProbeOp, ProfileID: profile.ID, Namespace: binding.Namespace,
		ProbeIPv4: policy.IdentIPv4}) ||
		token.Claims.HelperID != info.HelperID || token.Claims.NotAfter-token.Claims.IssuedAt != 30 {
		t.Fatalf("invalid multi-source capability: %+v", token.Claims)
	}

	before := signer.signs

	for name, mutate := range map[string]func(*LabMultiProbePolicy){
		"legacy policy":       func(p *LabMultiProbePolicy) { p.Policy = "PermitProbe" },
		"unsupported version": func(p *LabMultiProbePolicy) { p.Policy = "PermitMultiProbeV2" },
		"private pin":         func(p *LabMultiProbePolicy) { p.IdentIPv4 = "10.0.0.1" },
		"Cloudflare as pin":   func(p *LabMultiProbePolicy) { p.IdentIPv4 = LabProbeIPv4 },
		"foreign runtime":     func(p *LabMultiProbePolicy) { p.RuntimeID = "runtime_ffffffffffffffffffffffffffffffff" },
		"foreign epoch":       func(p *LabMultiProbePolicy) { p.HelperID = "helper_ffffffffffffffffffffffffffffffff" },
		"foreign key": func(p *LabMultiProbePolicy) {
			p.PublicKeySHA256 = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
		},
	} {
		bad := policy
		mutate(&bad)

		if _, err := MintPermitMultiProbe(signer, profile, binding, info, lab, bad, now); err == nil {
			t.Errorf("%s was signed", name)
		}
	}

	nonStrict := profile
	nonStrict.UniqueIPRequired = false

	sealed := lab
	sealed.State = LabSealed

	staleBinding := binding
	staleBinding.HelperEpoch = "helper_ffffffffffffffffffffffffffffffff"

	unauthorized := info
	unauthorized.AuthorizationConfigured = false

	for name, call := range map[string]func() error{
		"non-strict profile": func() error {
			_, err := MintPermitMultiProbe(signer, nonStrict, binding, info, lab, policy, now)
			return err
		},
		"sealed lab": func() error {
			_, err := MintPermitMultiProbe(signer, profile, binding, info, sealed, policy, now)
			return err
		},
		"stale binding": func() error {
			_, err := MintPermitMultiProbe(signer, profile, staleBinding, info, lab, policy, now)
			return err
		},
		"authorization not configured": func() error {
			_, err := MintPermitMultiProbe(signer, profile, binding, unauthorized, lab, policy, now)
			return err
		},
	} {
		if call() == nil {
			t.Errorf("%s was signed", name)
		}
	}

	if signer.signs != before {
		t.Fatal("a refused request reached the signer")
	}
}

func TestLabMultiProbePin(t *testing.T) {
	if !ValidLabMultiProbePin("9.9.9.9") {
		t.Fatal("valid pin refused")
	}

	for _, value := range []string{
		"", "1.1.1.1", "0.0.0.1", "10.0.0.1", "100.64.0.1", "127.0.0.1", "169.254.169.254", "172.16.0.1",
		"192.0.0.1", "192.0.2.42", "192.88.99.1", "192.168.1.1", "198.18.0.1", "198.51.100.1", "203.0.113.1",
		"224.0.0.1", "240.0.0.1", "255.255.255.255", "2001:db8::1", "::ffff:9.9.9.9", "9.9.9.9:443", "9.9.9.9 ",
		"009.9.9.9", "4.ident.me",
	} {
		if ValidLabMultiProbePin(value) {
			t.Errorf("invalid pin %q accepted", value)
		}
	}
}

func testMultiProbeInfo() (LabMultiProbeInfo, LabIntent) {
	start := time.Unix(1795500000, 0).UTC()
	ip := netip.MustParseAddr("8.8.4.4")

	intent := LabIntent{
		Operation: LabMultiProbeOp,
		ProfileID: "profile_0123456789abcdef",
		Namespace: "egresslab-lab-0123456789abcdef",
		ProbeIPv4: "9.9.9.9",
	}

	return LabMultiProbeInfo{
		ProfileID:   intent.ProfileID,
		Namespace:   intent.Namespace,
		IPv4:        ip,
		StartedAt:   start,
		FinishedAt:  start.Add(12 * time.Second),
		ObservedAt:  start.Add(3 * time.Second),
		HandshakeAt: start.Add(time.Second),
		Sources: []LabMultiProbeSourceInfo{
			{Source: LabProbeSource, DestinationIPv4: netip.MustParseAddr(LabProbeIPv4), IPv4: ip,
				ObservedAt: start.Add(3 * time.Second)},
			{Source: LabMultiProbeIdentSource, DestinationIPv4: netip.MustParseAddr(intent.ProbeIPv4), IPv4: ip,
				ObservedAt: start.Add(9 * time.Second)},
		},
	}, intent
}

func TestLabMultiProbeEvidence(t *testing.T) {
	info, intent := testMultiProbeInfo()
	issued, sent, received := info.StartedAt.Add(-time.Second), info.StartedAt, info.FinishedAt.Add(time.Second)

	if !info.ValidFor(intent, issued, sent, received) {
		t.Fatal("valid evidence refused")
	}

	setIP := func(raw string) func(*LabMultiProbeInfo) {
		return func(p *LabMultiProbeInfo) {
			ip := netip.MustParseAddr(raw)
			p.IPv4, p.Sources[0].IPv4, p.Sources[1].IPv4 = ip, ip, ip
		}
	}

	for name, mutate := range map[string]func(*LabMultiProbeInfo){
		"missing source":   func(p *LabMultiProbeInfo) { p.Sources = p.Sources[:1] },
		"extra source":     func(p *LabMultiProbeInfo) { p.Sources = append(p.Sources, p.Sources[1]) },
		"wrong source":     func(p *LabMultiProbeInfo) { p.Sources[1].Source = "unknown" },
		"duplicate source": func(p *LabMultiProbeInfo) { p.Sources[1].Source = p.Sources[0].Source },
		"reversed sources": func(p *LabMultiProbeInfo) { p.Sources[0], p.Sources[1] = p.Sources[1], p.Sources[0] },
		"wrong Cloudflare destination": func(p *LabMultiProbeInfo) {
			p.Sources[0].DestinationIPv4 = netip.MustParseAddr("8.8.8.8")
		},
		"another valid pin": func(p *LabMultiProbeInfo) {
			p.Sources[1].DestinationIPv4 = netip.MustParseAddr("8.8.8.8")
		},
		"private pin": func(p *LabMultiProbeInfo) {
			p.Sources[1].DestinationIPv4 = netip.MustParseAddr("10.0.0.1")
		},
		"IP mismatch":            func(p *LabMultiProbeInfo) { p.Sources[1].IPv4 = netip.MustParseAddr("8.8.8.8") },
		"aggregate IP":           func(p *LabMultiProbeInfo) { p.IPv4 = netip.MustParseAddr("8.8.8.8") },
		"private IP":             setIP("10.0.0.1"),
		"shared IP":              setIP("100.64.0.1"),
		"IPv6":                   setIP("2001:4860::1"),
		"foreign profile":        func(p *LabMultiProbeInfo) { p.ProfileID = "profile_ffffffffffffffff" },
		"foreign namespace":      func(p *LabMultiProbeInfo) { p.Namespace = "egresslab-lab-ffffffffffffffff" },
		"wrong oldest timestamp": func(p *LabMultiProbeInfo) { p.ObservedAt = p.Sources[1].ObservedAt },
		// The aggregate still names the first source, so only the order checks can refuse these two.
		"source before the attempt": func(p *LabMultiProbeInfo) {
			p.Sources[0].ObservedAt = p.StartedAt.Add(-time.Second)
			p.ObservedAt = p.Sources[0].ObservedAt
		},
		"reordered timestamps": func(p *LabMultiProbeInfo) {
			p.Sources[0].ObservedAt, p.Sources[1].ObservedAt = p.Sources[1].ObservedAt, p.Sources[0].ObservedAt
			p.ObservedAt = p.Sources[0].ObservedAt
		},
		"source after the attempt": func(p *LabMultiProbeInfo) { p.Sources[1].ObservedAt = p.FinishedAt.Add(time.Second) },
		"reversed interval":        func(p *LabMultiProbeInfo) { p.FinishedAt = p.StartedAt.Add(-time.Second) },
		"excessive interval":       func(p *LabMultiProbeInfo) { p.FinishedAt = p.StartedAt.Add(81 * time.Second) },
		"no start":                 func(p *LabMultiProbeInfo) { p.StartedAt = time.Time{} },
		"no handshake":             func(p *LabMultiProbeInfo) { p.HandshakeAt = time.Time{} },
		"stale handshake":          func(p *LabMultiProbeInfo) { p.HandshakeAt = p.FinishedAt.Add(-181 * time.Second) },
		"future handshake":         func(p *LabMultiProbeInfo) { p.HandshakeAt = p.FinishedAt.Add(time.Second) },
	} {
		bad := info
		bad.Sources = slices.Clone(info.Sources)
		mutate(&bad)

		// Each of these is wrong in itself, whatever the request timing.
		if bad.MatchesIntent(intent) || bad.ValidFor(intent, issued, sent, received) {
			t.Errorf("%s accepted", name)
		}
	}

	// Valid alone, before any intent: the pin must still be a distinct public address.
	for _, pin := range []string{"10.0.0.1", LabProbeIPv4, "100.64.0.1"} {
		bad := info
		bad.Sources = slices.Clone(info.Sources)
		bad.Sources[1].DestinationIPv4 = netip.MustParseAddr(pin)

		if bad.Valid() {
			t.Errorf("evidence with pin %s valid", pin)
		}
	}

	// The evidence must be for the signed intent, whatever pin it names itself.
	for name, edit := range map[string]func(*LabIntent){
		"another signed pin":  func(i *LabIntent) { i.ProbeIPv4 = "8.8.8.8" },
		"another profile":     func(i *LabIntent) { i.ProfileID = "profile_ffffffffffffffff" },
		"another namespace":   func(i *LabIntent) { i.Namespace = "egresslab-lab-ffffffffffffffff" },
		"legacy operation":    func(i *LabIntent) { i.Operation = "PermitProbe" },
		"stage in the intent": func(i *LabIntent) { i.StageID = "wgstage_0123456789abcdef0123456789abcdef" },
	} {
		other := intent
		edit(&other)

		if info.ValidFor(other, issued, sent, received) {
			t.Errorf("evidence accepted for %s", name)
		}
	}
}

// The helper judges the handshake in whole seconds at FinishedAt; the controller must agree.
func TestLabMultiProbeHandshakeBoundary(t *testing.T) {
	info, intent := testMultiProbeInfo()
	info.FinishedAt = info.FinishedAt.Add(900 * time.Millisecond)

	for age, ok := range map[int64]bool{0: true, 180: true, 181: false} {
		info.HandshakeAt = time.Unix(info.FinishedAt.Unix()-age, 0).UTC()

		if info.MatchesIntent(intent) != ok {
			t.Errorf("handshake %d whole seconds before a fractional finish: want %t", age, ok)
		}
	}
}

func TestLabMultiProbeFreshness(t *testing.T) {
	info, intent := testMultiProbeInfo()
	issued := info.StartedAt.Add(-time.Second)

	for _, tt := range []struct {
		name                   string
		issued, sent, received time.Time
		ok                     bool
	}{
		{"current", issued, info.StartedAt, info.FinishedAt.Add(time.Second), true},
		{"within clock skew", info.StartedAt.Add(5 * time.Second), info.StartedAt.Add(5 * time.Second),
			info.FinishedAt.Add(-5 * time.Second), true},
		{"stale evidence", issued, info.StartedAt, info.ObservedAt.Add(91 * time.Second), false},
		{"started before the request", issued, info.StartedAt.Add(6 * time.Second), info.FinishedAt, false},
		{"started before issuance", info.StartedAt.Add(6 * time.Second), info.StartedAt.Add(6 * time.Second),
			info.FinishedAt.Add(time.Second), false},
		{"finished after receipt", issued, info.StartedAt, info.FinishedAt.Add(-6 * time.Second), false},
		{"clock moved backwards", issued, info.FinishedAt, info.StartedAt, false},
		{"sent before issuance", info.StartedAt, info.StartedAt.Add(-time.Second), info.FinishedAt, false},
		{"no issuance time", time.Time{}, info.StartedAt, info.FinishedAt, false},
	} {
		if info.ValidFor(intent, tt.issued, tt.sent, tt.received) != tt.ok {
			t.Errorf("%s: want %t", tt.name, tt.ok)
		}
	}

	// 170 s old at the finish, within the helper's rule, but 190 s old when the answer arrives 20 s
	// later: only the controller's own handshake bound refuses it.
	aged := info
	aged.HandshakeAt = info.FinishedAt.Add(-170 * time.Second)

	if !aged.ValidFor(intent, issued, info.StartedAt, info.FinishedAt.Add(14*time.Second)) {
		t.Fatal("handshake within both bounds refused")
	}

	if aged.ValidFor(intent, issued, info.StartedAt, info.FinishedAt.Add(20*time.Second)) {
		t.Fatal("handshake too old at receipt accepted")
	}
}
