package helperipc

import (
	"context"
	"errors"
	"net/netip"
	"slices"
	"testing"
	"time"

	"github.com/VanChung369/egresslab/services/network-agent/internal/helperauth"
)

type fakeMultiProbeTunnelBackend struct {
	*fakeTunnelBackend

	pin      netip.Addr
	pinErr   error
	probeErr error
	calls    int
	mutate   func(*MultiProbeObservation)
}

func (f *fakeMultiProbeTunnelBackend) MultiProbePolicyPin() (netip.Addr, error) {
	return f.pin, f.pinErr
}

// ProbeConfiguredMulti returns synthetic evidence shaped like the agent's: real clock readings for
// the start and the finish, the sources in order between them, and a handshake in whole seconds.
func (f *fakeMultiProbeTunnelBackend) ProbeConfiguredMulti(context.Context, string) (MultiProbeObservation, error) {
	f.calls++

	if f.probeErr != nil {
		return MultiProbeObservation{}, f.probeErr
	}

	start := time.Now().UTC()
	for time.Since(start) < 3*time.Microsecond {
	}

	ip := netip.MustParseAddr("8.8.4.4")

	result := MultiProbeObservation{
		IPv4:        ip,
		StartedAt:   start,
		FinishedAt:  time.Now().UTC(),
		ObservedAt:  start.Add(time.Microsecond),
		HandshakeAt: start.Add(-time.Second).Truncate(time.Second),
		Sources: []MultiProbeSourceObservation{
			{
				Source:          helperauth.MultiProbeCloudflareSource,
				DestinationIPv4: netip.MustParseAddr(helperauth.MultiProbeCloudflareIPv4),
				IPv4:            ip,
				ObservedAt:      start.Add(time.Microsecond),
			},
			{
				Source:          helperauth.MultiProbeIdentSource,
				DestinationIPv4: f.pin,
				IPv4:            ip,
				ObservedAt:      start.Add(2 * time.Microsecond),
			},
		},
	}

	if f.mutate != nil {
		f.mutate(&result)
	}

	return result, nil
}

func newMultiProbeFixture(t *testing.T) (*tunnelFixture, *fakeMultiProbeTunnelBackend) {
	t.Helper()

	f := newTunnelFixture(t)
	backend := &fakeMultiProbeTunnelBackend{fakeTunnelBackend: f.tunnels, pin: netip.MustParseAddr("9.9.9.9")}

	f.labs.tunnels = backend
	f.labs.multiProbes = backend

	if _, err := f.execute(f.connectRequest()); err != nil {
		t.Fatal(err)
	}

	return f, backend
}

func multiProbeIntent(lab LabInfo, pin string) helperauth.Intent {
	return helperauth.Intent{
		Operation: helperauth.OpPermitMultiProbe,
		ProfileID: lab.ProfileID,
		Namespace: lab.Namespace,
		ProbeIPv4: pin,
	}
}

func shiftObservation(d time.Duration) func(*MultiProbeObservation) {
	return func(p *MultiProbeObservation) {
		p.StartedAt, p.FinishedAt = p.StartedAt.Add(d), p.FinishedAt.Add(d)
		p.ObservedAt, p.HandshakeAt = p.ObservedAt.Add(d), p.HandshakeAt.Add(d)

		for i := range p.Sources {
			p.Sources[i].ObservedAt = p.Sources[i].ObservedAt.Add(d)
		}
	}
}

func TestSignedMultiProbeLifecycle(t *testing.T) {
	ctx := context.Background()
	f, backend := newMultiProbeFixture(t)

	intent := multiProbeIntent(f.lab, backend.pin.String())
	req := f.mint(intent)

	unsigned := req
	unsigned.Capability = nil

	if _, err := f.labs.executeMultiProbe(ctx, unsigned, f.verifier); labCode(err) != CodeAuthorizationDenied {
		t.Fatalf("unsigned probe accepted: %v", err)
	}

	// A valid signature for another pin does not override the helper's own policy.
	foreign := intent
	foreign.ProbeIPv4 = "8.8.8.8"
	wrong := f.mint(foreign)

	if _, err := f.labs.executeMultiProbe(ctx, wrong, f.verifier); labCode(err) != CodeInvalidRequest {
		t.Fatalf("foreign policy accepted: %v", err)
	}

	tampered := req
	tampered.Capability = wrong.Capability

	if _, err := f.labs.executeMultiProbe(ctx, tampered, f.verifier); labCode(err) != CodeAuthorizationDenied {
		t.Fatalf("capability for another pin accepted: %v", err)
	}

	legacy := f.mint(probeIntent(f.lab))
	tampered.Capability = legacy.Capability

	if _, err := f.labs.executeMultiProbe(ctx, tampered, f.verifier); labCode(err) != CodeAuthorizationDenied {
		t.Fatalf("legacy capability authorized a multi-source probe: %v", err)
	}

	if _, err := f.labs.executeProbe(ctx, legacy, f.verifier); labCode(err) != CodeRuntimeUnavailable {
		t.Fatalf("legacy probe ran on a multi-source lifecycle: %v", err)
	}

	if backend.calls != 0 || backend.cleanups != 0 || f.labs.labs.peek(f.lab.ProfileID).State != LabTunnelConfigured {
		t.Fatal("a refused operation reached the backend or changed the lab")
	}

	result, err := f.labs.executeMultiProbe(ctx, req, f.verifier)
	if err != nil || result.IPv4.String() != "8.8.4.4" || len(result.Sources) != 2 ||
		result.ProfileID != f.lab.ProfileID || result.Namespace != f.lab.Namespace {
		t.Fatalf("unexpected result: %+v %v", result, err)
	}

	if backend.calls != 1 || f.labs.tunnelProfile != f.lab.ProfileID ||
		f.labs.labs.peek(f.lab.ProfileID).State != LabTunnelConfigured {
		t.Fatal("configured tunnel state lost")
	}

	if _, err := f.labs.executeMultiProbe(ctx, req, f.verifier); labCode(err) != CodeAuthorizationDenied {
		t.Fatalf("replay accepted: %v", err)
	}

	if backend.calls != 1 {
		t.Fatal("a replay reached the backend")
	}
}

// Refusals before the nonce is consumed leave the capability usable and the lab untouched.
func TestMultiProbeRefusals(t *testing.T) {
	ctx := context.Background()

	t.Run("multi-source probe disabled", func(t *testing.T) {
		f := newTunnelFixture(t)
		if _, err := f.execute(f.connectRequest()); err != nil {
			t.Fatal(err)
		}

		_, err := f.labs.executeMultiProbe(ctx, f.mint(multiProbeIntent(f.lab, "9.9.9.9")), f.verifier)
		if labCode(err) != CodeRuntimeUnavailable {
			t.Fatalf("disabled multi-source probe: %v", err)
		}
	})

	f, backend := newMultiProbeFixture(t)
	intent := multiProbeIntent(f.lab, backend.pin.String())
	req := f.mint(intent)

	other := intent
	other.ProfileID = "profile_ffffffffffffffff"

	foreign := intent
	foreign.Namespace = "egresslab-lab-ffffffffffffffff"

	staged := intent
	staged.StageID = tunnelTestStage

	for name, tt := range map[string]struct {
		req  Request
		code string
	}{
		"lab not found":      {f.mint(other), CodeLabNotFound},
		"namespace mismatch": {f.mint(foreign), CodeOwnershipMismatch},
		"intent with stage":  {Request{Version: Version, Operation: staged.Operation, Intent: &staged}, CodeInvalidRequest},
	} {
		if _, err := f.labs.executeMultiProbe(ctx, tt.req, f.verifier); labCode(err) != tt.code {
			t.Errorf("%s: %v", name, err)
		}
	}

	f.labs.mu.Lock()
	_, err := f.labs.executeMultiProbe(ctx, req, f.verifier)
	f.labs.mu.Unlock()

	if labCode(err) != CodeLabBusy {
		t.Fatalf("concurrent operation: %v", err)
	}

	backend.pinErr = errors.New("local policy unavailable")

	if _, err := f.labs.executeMultiProbe(ctx, req, f.verifier); labCode(err) != CodeRuntimeUnavailable {
		t.Fatalf("missing local policy: %v", err)
	}

	backend.pinErr = nil
	backend.pin = netip.MustParseAddr("10.0.0.1")

	if _, err := f.labs.executeMultiProbe(ctx, req, f.verifier); labCode(err) != CodeRuntimeUnavailable {
		t.Fatalf("invalid local policy: %v", err)
	}

	backend.pin = netip.MustParseAddr("9.9.9.9")

	sealed := f.labs.labs.peek(f.lab.ProfileID)
	sealed.State = LabSealed
	f.labs.labs.set(f.lab.ProfileID, sealed)

	if _, err := f.labs.executeMultiProbe(ctx, req, f.verifier); labCode(err) != CodeLabFaulted {
		t.Fatalf("probe without a tunnel: %v", err)
	}

	sealed.State = LabTunnelConfigured
	f.labs.labs.set(f.lab.ProfileID, sealed)

	if backend.calls != 0 || backend.cleanups != 0 {
		t.Fatal("a refused operation reached the backend")
	}

	if _, err := f.labs.executeMultiProbe(ctx, req, f.verifier); err != nil || backend.calls != 1 {
		t.Fatalf("capability consumed by a refusal: %v", err)
	}
}

func TestMultiProbeFailureFaultsLab(t *testing.T) {
	for _, mode := range []string{
		"source failure",
		"IP mismatch",
		"missing source",
		"invalid destination",
		"invalid aggregate timestamp",
		"stale handshake",
		"evidence from the future",
		"evidence before acceptance",
		"context expired",
		"cleanup failure",
	} {
		t.Run(mode, func(t *testing.T) {
			f, backend := newMultiProbeFixture(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			req := f.mint(multiProbeIntent(f.lab, backend.pin.String()))

			switch mode {
			case "source failure":
				backend.probeErr = errors.New("HTTPS source unavailable")
			case "IP mismatch":
				backend.mutate = func(p *MultiProbeObservation) { p.Sources[1].IPv4 = netip.MustParseAddr("8.8.8.8") }
			case "missing source":
				backend.mutate = func(p *MultiProbeObservation) { p.Sources = p.Sources[:1] }
			case "invalid destination":
				backend.mutate = func(p *MultiProbeObservation) {
					p.Sources[1].DestinationIPv4 = netip.MustParseAddr("8.8.8.8")
				}
			case "invalid aggregate timestamp":
				backend.mutate = func(p *MultiProbeObservation) { p.ObservedAt = p.Sources[1].ObservedAt }
			case "stale handshake":
				backend.mutate = func(p *MultiProbeObservation) { p.HandshakeAt = p.FinishedAt.Add(-182 * time.Second) }
			case "evidence from the future":
				// Consistent in itself and after issuance, but it finishes after the helper's now.
				backend.mutate = shiftObservation(5 * time.Second)
			case "evidence before acceptance":
				// Issued 10 s ago, and evidence from 8 s ago: after issuance, but before the helper
				// accepted the capability.
				req = f.mintAt(multiProbeIntent(f.lab, backend.pin.String()), time.Now().Add(-10*time.Second))
				backend.mutate = shiftObservation(-8 * time.Second)
			case "context expired":
				backend.mutate = func(*MultiProbeObservation) { cancel() }
			case "cleanup failure":
				backend.probeErr = errors.New("probe failed")
				backend.cleanupErr = errors.New("cleanup failed")
			}

			result, err := f.labs.executeMultiProbe(ctx, req, f.verifier)
			if err == nil || result.IPv4.IsValid() || result.Sources != nil || !result.ObservedAt.IsZero() {
				t.Fatalf("failed probe returned evidence: %+v %v", result, err)
			}

			if f.labs.labs.peek(f.lab.ProfileID).State != LabFaulted || backend.calls != 1 || backend.cleanups != 1 {
				t.Fatal("failed probe did not fault the lab and roll back")
			}

			if mode == "cleanup failure" {
				if labCode(err) != CodeStateUncertain || f.labs.tunnelProfile != f.lab.ProfileID {
					t.Fatal("uncertain ownership was lost")
				}

				return
			}

			if labCode(err) != CodeLabFaulted || f.labs.tunnelProfile != "" {
				t.Fatalf("clean rollback not recorded: %v", err)
			}

			// Only DeleteLab clears a faulted lab.
			next := f.mint(multiProbeIntent(f.lab, backend.pin.String()))
			if _, err := f.labs.executeMultiProbe(context.Background(), next, f.verifier); labCode(err) != CodeLabFaulted {
				t.Fatalf("probe of a faulted lab: %v", err)
			}
		})
	}
}

// A multi-source lifecycle refuses the single-source probe even when a legacy backend is present.
func TestMultiProbeNoSingleSourceFallback(t *testing.T) {
	f, multi := newMultiProbeFixture(t)
	legacy := &fakeProbeTunnelBackend{fakeTunnelBackend: f.tunnels}
	f.labs.probes = legacy

	_, err := f.labs.executeProbe(context.Background(), f.mint(probeIntent(f.lab)), f.verifier)
	if labCode(err) != CodeRuntimeUnavailable || legacy.probeCalls != 0 || multi.calls != 0 {
		t.Fatalf("single-source fallback: %v", err)
	}
}

func TestMultiProbeLifecycleConstruction(t *testing.T) {
	f, backend := newMultiProbeFixture(t)
	lifecycle := NewMultiProbeLifecycle(f.backend, backend)

	if lifecycle.tunnels != backend || lifecycle.multiProbes != backend || lifecycle.probes != nil {
		t.Fatal("invalid multi-source lifecycle configuration")
	}
}

func TestMultiProbeResponseValidation(t *testing.T) {
	f, backend := newMultiProbeFixture(t)
	req := f.mint(multiProbeIntent(f.lab, backend.pin.String()))

	observation, err := backend.ProbeConfiguredMulti(context.Background(), f.lab.Namespace)
	if err != nil {
		t.Fatal(err)
	}

	info := MultiProbeInfo{ProfileID: f.lab.ProfileID, Namespace: f.lab.Namespace, MultiProbeObservation: observation}
	resp := Response{Version: Version, Operation: req.Operation, OK: true, MultiProbe: &info}

	if !validMultiProbeResponse(req, resp) {
		t.Fatal("valid response rejected")
	}

	setIP := func(raw string) func(*MultiProbeInfo) {
		return func(p *MultiProbeInfo) {
			ip := netip.MustParseAddr(raw)
			p.IPv4, p.Sources[0].IPv4, p.Sources[1].IPv4 = ip, ip, ip
		}
	}

	for name, mutate := range map[string]func(*MultiProbeInfo){
		"foreign profile":     func(p *MultiProbeInfo) { p.ProfileID = "profile_ffffffffffffffff" },
		"foreign namespace":   func(p *MultiProbeInfo) { p.Namespace = "egresslab-lab-ffffffffffffffff" },
		"missing source":      func(p *MultiProbeInfo) { p.Sources = p.Sources[:1] },
		"extra source":        func(p *MultiProbeInfo) { p.Sources = append(p.Sources, p.Sources[1]) },
		"unknown source":      func(p *MultiProbeInfo) { p.Sources[1].Source = "unknown" },
		"duplicate source":    func(p *MultiProbeInfo) { p.Sources[1].Source = p.Sources[0].Source },
		"reordered sources":   func(p *MultiProbeInfo) { p.Sources[0], p.Sources[1] = p.Sources[1], p.Sources[0] },
		"wrong destination":   func(p *MultiProbeInfo) { p.Sources[1].DestinationIPv4 = netip.MustParseAddr("8.8.8.8") },
		"swapped destination": func(p *MultiProbeInfo) { p.Sources[0].DestinationIPv4 = p.Sources[1].DestinationIPv4 },
		"IP disagreement":     func(p *MultiProbeInfo) { p.Sources[1].IPv4 = netip.MustParseAddr("8.8.8.8") },
		"aggregate IP":        func(p *MultiProbeInfo) { p.IPv4 = netip.MustParseAddr("8.8.8.8") },
		"private IP":          setIP("10.0.0.1"),
		"shared IP":           setIP("100.64.0.1"),
		"documentation IP":    setIP("192.0.2.1"),
		"IPv6":                setIP("2001:4860::1"),
		// The aggregate still names the first source, so only the order checks can refuse these two.
		"before the attempt": func(p *MultiProbeInfo) {
			p.Sources[0].ObservedAt = p.StartedAt.Add(-time.Second)
			p.ObservedAt = p.Sources[0].ObservedAt
		},
		"after the attempt": func(p *MultiProbeInfo) { p.Sources[1].ObservedAt = p.FinishedAt.Add(time.Second) },
		"reordered timestamps": func(p *MultiProbeInfo) {
			p.Sources[0].ObservedAt, p.Sources[1].ObservedAt = p.Sources[1].ObservedAt, p.Sources[0].ObservedAt
			p.ObservedAt = p.Sources[0].ObservedAt
		},
		"reversed interval":   func(p *MultiProbeInfo) { p.FinishedAt = p.StartedAt.Add(-time.Second) },
		"excessive interval":  func(p *MultiProbeInfo) { p.FinishedAt = p.StartedAt.Add(81 * time.Second) },
		"aggregate timestamp": func(p *MultiProbeInfo) { p.ObservedAt = p.Sources[1].ObservedAt },
		"no start":            func(p *MultiProbeInfo) { p.StartedAt = time.Time{} },
		"no handshake":        func(p *MultiProbeInfo) { p.HandshakeAt = time.Time{} },
		"stale handshake":     func(p *MultiProbeInfo) { p.HandshakeAt = p.FinishedAt.Add(-182 * time.Second) },
		"future handshake":    func(p *MultiProbeInfo) { p.HandshakeAt = p.FinishedAt.Add(time.Second) },
	} {
		t.Run(name, func(t *testing.T) {
			bad := info
			bad.Sources = slices.Clone(info.Sources)
			mutate(&bad)

			changed := resp
			changed.MultiProbe = &bad

			if validMultiProbeResponse(req, changed) {
				t.Fatal("invalid evidence accepted")
			}
		})
	}

	for name, changed := range map[string]Response{
		"failure with evidence":    {Version: Version, Operation: req.Operation, MultiProbe: &info},
		"success without evidence": {Version: Version, Operation: req.Operation, OK: true},
		"network ready":            {Version: Version, Operation: req.Operation, OK: true, NetworkReady: true, MultiProbe: &info},
		"single-source metadata": {Version: Version, Operation: req.Operation, OK: true, MultiProbe: &info,
			Probe: &ProbeInfo{}},
	} {
		if validMultiProbeResponse(req, changed) {
			t.Errorf("%s accepted", name)
		}
	}

	if validMultiProbeResponse(Request{Operation: OpPing}, resp) {
		t.Fatal("unsolicited evidence accepted")
	}

	unsigned := req
	unsigned.Capability = nil

	if validMultiProbeResponse(unsigned, resp) {
		t.Fatal("evidence without a capability accepted")
	}

	late := *req.Capability
	late.Claims.IssuedAt = info.FinishedAt.Unix() + 1
	lateRequest := req
	lateRequest.Capability = &late

	if validMultiProbeResponse(lateRequest, resp) {
		t.Fatal("evidence from before the capability was issued accepted")
	}
}

// The agent judges the handshake in whole seconds at FinishedAt; the helper must agree at the edge.
func TestMultiProbeHandshakeBoundary(t *testing.T) {
	intent := multiProbeIntent(LabInfo{ProfileID: lifecycleProfile, Namespace: "egresslab-lab-0123456789abcdef"},
		"9.9.9.9")
	finish := time.Unix(1795500100, 900_000_000).UTC()
	ip := netip.MustParseAddr("8.8.4.4")

	info := MultiProbeInfo{
		ProfileID: intent.ProfileID,
		Namespace: intent.Namespace,
		MultiProbeObservation: MultiProbeObservation{
			IPv4:       ip,
			StartedAt:  finish.Add(-2 * time.Second),
			FinishedAt: finish,
			ObservedAt: finish.Add(-time.Second),
			Sources: []MultiProbeSourceObservation{
				{helperauth.MultiProbeCloudflareSource, netip.MustParseAddr("1.1.1.1"), ip, finish.Add(-time.Second)},
				{helperauth.MultiProbeIdentSource, netip.MustParseAddr("9.9.9.9"), ip, finish.Add(-time.Second / 2)},
			},
		},
	}

	for age, ok := range map[int64]bool{0: true, 180: true, 181: false} {
		info.HandshakeAt = time.Unix(finish.Unix()-age, 0).UTC()

		if validMultiProbeInfo(&info, &intent) != ok {
			t.Errorf("handshake %d whole seconds before a fractional finish: want %t", age, ok)
		}
	}
}

func TestMultiProbeWithin(t *testing.T) {
	from := time.Unix(1795500000, 0).UTC()
	to := from.Add(10 * time.Second)

	for name, tt := range map[string]struct {
		start, finish time.Time
		ok            bool
	}{
		"inside":                {from, to, true},
		"start within 1 s":      {from.Add(-time.Second), to, true},
		"start over 1 s before": {from.Add(-time.Second - time.Millisecond), to, false},
		"finish after receipt":  {from, to.Add(time.Millisecond), false},
	} {
		info := &MultiProbeInfo{MultiProbeObservation: MultiProbeObservation{StartedAt: tt.start, FinishedAt: tt.finish}}
		if multiProbeWithin(info, from, to) != tt.ok {
			t.Errorf("%s: want %t", name, tt.ok)
		}
	}

	if multiProbeWithin(nil, from, to) {
		t.Fatal("missing evidence accepted")
	}
}
