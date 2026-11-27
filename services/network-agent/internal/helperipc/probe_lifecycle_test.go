package helperipc

import (
	"context"
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/VanChung369/egresslab/services/network-agent/internal/helperauth"
)

type fakeProbeTunnelBackend struct {
	*fakeTunnelBackend

	probeCalls int
	probeErr   error
	invalidIP  bool
}

func (f *fakeProbeTunnelBackend) ProbeConfigured(context.Context, string) (ProbeObservation, error) {
	f.probeCalls++

	now := time.Now().UTC()
	ip := netip.MustParseAddr("8.8.4.4")

	if f.invalidIP {
		ip = netip.MustParseAddr("10.0.0.1")
	}

	return ProbeObservation{IPv4: ip, ObservedAt: now, HandshakeAt: now.Add(-time.Second), Source: ProbeSource},
		f.probeErr
}

// newProbeFixture is a lifecycle with the probe enabled and a configured tunnel in f.lab.
func newProbeFixture(t *testing.T) (*tunnelFixture, *fakeProbeTunnelBackend) {
	t.Helper()

	f := newTunnelFixture(t)
	backend := &fakeProbeTunnelBackend{fakeTunnelBackend: f.tunnels}

	f.labs.tunnels = backend
	f.labs.probes = backend

	if _, err := f.execute(f.connectRequest()); err != nil {
		t.Fatal(err)
	}

	return f, backend
}

func probeIntent(lab LabInfo) helperauth.Intent {
	return helperauth.Intent{
		Operation: helperauth.OpPermitProbe,
		ProfileID: lab.ProfileID,
		Namespace: lab.Namespace,
		ProbeIPv4: ProbeDestinationIPv4,
	}
}

func TestSignedProbeLifecycle(t *testing.T) {
	f, backend := newProbeFixture(t)
	ctx := context.Background()

	req := f.mint(probeIntent(f.lab))

	unsigned := req
	unsigned.Capability = nil

	if _, err := f.labs.executeProbe(ctx, unsigned, f.verifier); !errors.Is(err, errLabAuthorization) {
		t.Fatalf("unsigned probe accepted: %v", err)
	}

	// helperauth accepts any unicast IPv4 here; the helper only its fixed destination.
	wrongDestination := probeIntent(f.lab)
	wrongDestination.ProbeIPv4 = "8.8.8.8"
	wrong := f.mint(wrongDestination)

	if _, err := f.labs.executeProbe(ctx, wrong, f.verifier); !errors.Is(err, errLabInvalid) {
		t.Fatalf("arbitrary probe destination accepted: %v", err)
	}

	tampered := req
	tampered.Capability = wrong.Capability

	if _, err := f.labs.executeProbe(ctx, tampered, f.verifier); !errors.Is(err, errLabAuthorization) {
		t.Fatalf("wrong capability accepted: %v", err)
	}

	if backend.probeCalls != 0 {
		t.Fatal("unauthorized probe reached the backend")
	}

	result, err := f.labs.executeProbe(ctx, req, f.verifier)
	if err != nil || result.IPv4.String() != "8.8.4.4" || result.ProfileID != f.lab.ProfileID ||
		result.Namespace != f.lab.Namespace || result.Source != ProbeSource {
		t.Fatalf("unexpected result: %+v %v", result, err)
	}

	if f.labs.labs.peek(f.lab.ProfileID).State != LabTunnelConfigured || f.labs.tunnelProfile != f.lab.ProfileID {
		t.Fatal("configured tunnel state lost")
	}

	if _, err := f.labs.executeProbe(ctx, req, f.verifier); !errors.Is(err, errLabAuthorization) {
		t.Fatalf("probe replay accepted: %v", err)
	}

	if backend.probeCalls != 1 {
		t.Fatal("unexpected probe count")
	}
}

// Refusals before the nonce is consumed leave the capability usable and the lab untouched.
func TestProbeRefusalsKeepTheCapability(t *testing.T) {
	ctx := context.Background()

	t.Run("probe disabled", func(t *testing.T) {
		f := newTunnelFixture(t)
		if _, err := f.execute(f.connectRequest()); err != nil {
			t.Fatal(err)
		}

		_, err := f.labs.executeProbe(ctx, f.mint(probeIntent(f.lab)), f.verifier)
		if labCode(err) != CodeRuntimeUnavailable {
			t.Fatalf("disabled probe: %v", err)
		}
	})

	f, backend := newProbeFixture(t)
	req := f.mint(probeIntent(f.lab))

	other := probeIntent(f.lab)
	other.ProfileID = "profile_ffffffffffffffff"

	foreign := probeIntent(f.lab)
	foreign.Namespace = "egresslab-lab-ffffffffffffffff"

	for name, tt := range map[string]struct {
		req  Request
		code string
	}{
		"lab not found":      {f.mint(other), CodeLabNotFound},
		"namespace mismatch": {f.mint(foreign), CodeOwnershipMismatch},
	} {
		if _, err := f.labs.executeProbe(ctx, tt.req, f.verifier); labCode(err) != tt.code {
			t.Errorf("%s: %v", name, err)
		}
	}

	f.labs.mu.Lock()
	_, err := f.labs.executeProbe(ctx, req, f.verifier)
	f.labs.mu.Unlock()

	if labCode(err) != CodeLabBusy {
		t.Fatalf("probe during another operation: %v", err)
	}

	sealed := f.labs.labs.peek(f.lab.ProfileID)
	sealed.State = LabSealed
	f.labs.labs.set(f.lab.ProfileID, sealed)

	if _, err := f.labs.executeProbe(ctx, req, f.verifier); labCode(err) != CodeLabFaulted {
		t.Fatalf("probe without a tunnel: %v", err)
	}

	sealed.State = LabTunnelConfigured
	f.labs.labs.set(f.lab.ProfileID, sealed)

	if backend.probeCalls != 0 {
		t.Fatal("a refused probe reached the backend")
	}

	if _, err := f.labs.executeProbe(ctx, req, f.verifier); err != nil || backend.probeCalls != 1 {
		t.Fatalf("capability consumed by a refusal: %v", err)
	}
}

func TestProbeFailureFaultsLab(t *testing.T) {
	for _, mode := range []string{"probe failure", "invalid observation", "cleanup failure"} {
		t.Run(mode, func(t *testing.T) {
			f, backend := newProbeFixture(t)
			ctx := context.Background()

			switch mode {
			case "invalid observation":
				backend.invalidIP = true
			case "cleanup failure":
				backend.probeErr = errors.New("probe failed")
				backend.cleanupErr = errors.New("cleanup failed")
			default:
				backend.probeErr = errors.New("probe failed")
			}

			result, err := f.labs.executeProbe(ctx, f.mint(probeIntent(f.lab)), f.verifier)
			if err == nil || result.IPv4.IsValid() {
				t.Fatal("failed probe returned an address")
			}

			if f.labs.labs.peek(f.lab.ProfileID).State != LabFaulted {
				t.Fatal("lab not faulted")
			}

			if mode == "cleanup failure" {
				if labCode(err) != CodeStateUncertain || f.labs.tunnelProfile != f.lab.ProfileID {
					t.Fatal("uncertain ownership was lost")
				}

				return
			}

			if labCode(err) != CodeLabFaulted || f.labs.tunnelProfile != "" || backend.cleanups == 0 {
				t.Fatalf("clean rollback not recorded: %v", err)
			}

			// Only DeleteLab clears a faulted lab; another probe is refused.
			if _, err := f.labs.executeProbe(ctx, f.mint(probeIntent(f.lab)), f.verifier); labCode(err) != CodeLabFaulted {
				t.Fatalf("probe of a faulted lab: %v", err)
			}
		})
	}
}

func TestProbeContextExpiry(t *testing.T) {
	f, backend := newProbeFixture(t)

	ctx, cancel := context.WithCancel(context.Background())

	// The context ends while the backend runs: the result is discarded.
	probe := &cancellingProbe{fakeProbeTunnelBackend: backend, cancel: cancel}
	f.labs.probes = probe

	if _, err := f.labs.executeProbe(ctx, f.mint(probeIntent(f.lab)), f.verifier); labCode(err) != CodeLabFaulted {
		t.Fatalf("expired probe: %v", err)
	}
}

type cancellingProbe struct {
	*fakeProbeTunnelBackend
	cancel context.CancelFunc
}

func (c *cancellingProbe) ProbeConfigured(ctx context.Context, namespace string) (ProbeObservation, error) {
	c.cancel()
	return c.fakeProbeTunnelBackend.ProbeConfigured(ctx, namespace)
}

func TestProbeResponseValidation(t *testing.T) {
	intent := probeIntent(LabInfo{ProfileID: lifecycleProfile, Namespace: "egresslab-lab-0123456789abcdef"})
	now := time.Now().UTC()

	info := ProbeInfo{
		ProfileID: intent.ProfileID,
		Namespace: intent.Namespace,
		ProbeObservation: ProbeObservation{
			IPv4:        netip.MustParseAddr("8.8.4.4"),
			ObservedAt:  now,
			HandshakeAt: now.Add(-time.Second),
			Source:      ProbeSource,
		},
	}

	req := Request{Version: Version, Operation: helperauth.OpPermitProbe, Intent: &intent}
	resp := Response{Version: Version, Operation: req.Operation, OK: true, Probe: &info}

	if !validProbeResponse(req, resp) {
		t.Fatal("valid observation rejected")
	}

	for name, edit := range map[string]func(*ProbeInfo){
		"foreign profile":   func(p *ProbeInfo) { p.ProfileID = "profile_ffffffffffffffff" },
		"foreign namespace": func(p *ProbeInfo) { p.Namespace = "egresslab-lab-ffffffffffffffff" },
		"private address":   func(p *ProbeInfo) { p.IPv4 = netip.MustParseAddr("10.0.0.1") },
		"IPv6 address":      func(p *ProbeInfo) { p.IPv4 = netip.MustParseAddr("2001:4860::1") },
		"other source":      func(p *ProbeInfo) { p.Source = "other" },
		"stale handshake":   func(p *ProbeInfo) { p.HandshakeAt = p.ObservedAt.Add(-181 * time.Second) },
		"no handshake":      func(p *ProbeInfo) { p.HandshakeAt = time.Time{} },
		"no observed time":  func(p *ProbeInfo) { p.ObservedAt = time.Time{} },
	} {
		changed := info
		edit(&changed)
		resp.Probe = &changed

		if validProbeResponse(req, resp) {
			t.Errorf("%s accepted", name)
		}
	}

	resp.Probe = &info

	if validProbeResponse(Request{Operation: OpPing}, resp) {
		t.Fatal("unsolicited probe metadata accepted")
	}

	resp.OK = false

	if validProbeResponse(req, resp) {
		t.Fatal("failure response carried an observation")
	}

	resp.OK = true
	resp.Probe = nil

	if validProbeResponse(req, resp) {
		t.Fatal("missing observation accepted")
	}
}

func TestUncertainOutranksOtherCodes(t *testing.T) {
	for _, err := range []error{
		errors.Join(errLabUncertain, errLabAuthorization),
		errors.Join(errLabUncertain, errLabFaulted, ErrLabFirewallDrift),
		errors.Join(errLabBusy, errLabUncertain),
	} {
		if labCode(err) != CodeStateUncertain {
			t.Errorf("%v: %s", err, labCode(err))
		}
	}
}
