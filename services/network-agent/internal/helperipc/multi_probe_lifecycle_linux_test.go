//go:build linux

package helperipc

import (
	"context"
	"testing"
	"time"
)

// Real socket, framing, dispatcher and Ed25519 verifier; only the kernel backend is fake.
func TestSignedMultiProbeIPC(t *testing.T) {
	ctx := context.Background()
	f, backend := newMultiProbeFixture(t)
	socket := serveLifecycleTest(t, f.verifier, f.labs)

	req := f.mint(multiProbeIntent(f.lab, backend.pin.String()))

	response, err := ProbeEgressMulti(ctx, socket, f.lab.ProfileID, f.lab.Namespace, *req.Capability)
	if err != nil || response.MultiProbe == nil || response.Probe != nil || response.Lab != nil || response.NetworkReady ||
		response.Operation != req.Operation {
		t.Fatalf("unexpected response: %+v %v", response, err)
	}

	info := response.MultiProbe
	if info.IPv4.String() != "8.8.4.4" || info.ProfileID != f.lab.ProfileID || info.Namespace != f.lab.Namespace ||
		len(info.Sources) != 2 {
		t.Fatalf("invalid multi-source metadata: %+v", info)
	}

	if _, err := ProbeEgressMulti(ctx, socket, f.lab.ProfileID, f.lab.Namespace, *req.Capability); ErrorCode(err) !=
		CodeAuthorizationDenied {
		t.Fatalf("replay accepted: %v", err)
	}

	legacy := f.mint(probeIntent(f.lab))

	if _, err := ProbeEgress(ctx, socket, f.lab.ProfileID, f.lab.Namespace, *legacy.Capability); ErrorCode(err) !=
		CodeOperationDisabled {
		t.Fatalf("legacy probe on a multi-source helper: %v", err)
	}

	listed, err := Call(ctx, socket, OpListLabs)
	if err != nil || len(listed.Labs) != 1 || listed.Labs[0].State != LabTunnelConfigured {
		t.Fatalf("configured lab state lost: %+v %v", listed, err)
	}

	if _, err := DeleteSealedLab(ctx, socket, f.lab.ProfileID, f.lab.Namespace); err != nil {
		t.Fatal(err)
	}
}

func TestMultiProbeDisabledOverIPC(t *testing.T) {
	ctx := context.Background()
	f := newTunnelFixture(t)

	if _, err := f.execute(f.connectRequest()); err != nil {
		t.Fatal(err)
	}

	socket := serveLifecycleTest(t, f.verifier, f.labs)
	req := f.mint(multiProbeIntent(f.lab, "9.9.9.9"))

	if _, err := ProbeEgressMulti(ctx, socket, f.lab.ProfileID, f.lab.Namespace, *req.Capability); ErrorCode(err) !=
		CodeOperationDisabled {
		t.Fatalf("multi-source probe enabled without a backend: %v", err)
	}
}

// With both backends present, the dispatcher still refuses the single-source probe.
func TestMultiProbeFallbackDisabledOverIPC(t *testing.T) {
	ctx := context.Background()
	f, multi := newMultiProbeFixture(t)
	legacy := &fakeProbeTunnelBackend{fakeTunnelBackend: f.tunnels}
	f.labs.probes = legacy

	socket := serveLifecycleTest(t, f.verifier, f.labs)
	req := f.mint(probeIntent(f.lab))

	if _, err := ProbeEgress(ctx, socket, f.lab.ProfileID, f.lab.Namespace, *req.Capability); ErrorCode(err) !=
		CodeOperationDisabled || legacy.probeCalls != 0 || multi.calls != 0 {
		t.Fatalf("single-source fallback over IPC: %v", err)
	}
}

// The client binds the evidence to its own request: a helper answering with evidence that is
// otherwise valid, but older than the request or finishing after the answer, is refused.
func TestProbeEgressMultiBindsEvidenceToRequest(t *testing.T) {
	requireUnprivileged(t)

	ctx := context.Background()
	f, backend := newMultiProbeFixture(t)
	intent := multiProbeIntent(f.lab, backend.pin.String())

	for name, tt := range map[string]struct {
		issued time.Time
		shift  time.Duration
		ok     bool
	}{
		"current evidence":      {time.Now(), 0, true},
		"evidence from 8 s ago": {time.Now().Add(-10 * time.Second), -8 * time.Second, false},
		"evidence 5 s ahead":    {time.Now(), 5 * time.Second, false},
	} {
		t.Run(name, func(t *testing.T) {
			req := f.mintAt(intent, tt.issued)
			backend.mutate = shiftObservation(tt.shift)

			// The evidence is made once the request has arrived, as a helper would.
			socket := fakeHelper(t, func(Request) Response {
				observation, err := backend.ProbeConfiguredMulti(ctx, f.lab.Namespace)
				if err != nil {
					t.Error(err)
				}

				info := MultiProbeInfo{ProfileID: f.lab.ProfileID, Namespace: f.lab.Namespace,
					MultiProbeObservation: observation}
				resp := Response{Version: Version, Operation: req.Operation, OK: true, MultiProbe: &info}

				// Valid against the capability alone, so only the request window can refuse it.
				if !validMultiProbeResponse(req, resp) {
					t.Error("fixture evidence does not match its capability")
				}

				return resp
			})

			resp, err := ProbeEgressMulti(ctx, socket, f.lab.ProfileID, f.lab.Namespace, *req.Capability)
			if (err == nil) != tt.ok || (err == nil && resp.MultiProbe == nil) || (err != nil && resp.MultiProbe != nil) {
				t.Fatalf("want accepted %t: %+v %v", tt.ok, resp, err)
			}
		})
	}
}

// A helper from before Step 29C.4a refuses the operation without echoing its name.
func TestOlderHelperRefusesMultiProbe(t *testing.T) {
	requireUnprivileged(t)

	ctx := context.Background()
	f, backend := newMultiProbeFixture(t)
	req := f.mint(multiProbeIntent(f.lab, backend.pin.String()))

	refusal := Response{Version: Version, Code: CodeOperationDisabled, Error: "operation not enabled"}

	for name, tt := range map[string]struct {
		resp Response
		code string
	}{
		"bare refusal":       {refusal, CodeOperationDisabled},
		"other code":         {Response{Version: Version, Code: CodeLabBusy, Error: "busy"}, CodeInternal},
		"unnamed success":    {Response{Version: Version, OK: true}, CodeInternal},
		"refusal with a lab": {Response{Version: Version, Code: CodeOperationDisabled, Lab: &LabInfo{}}, CodeInternal},
		"refusal with a policy": {Response{Version: Version, Code: CodeOperationDisabled,
			MultiProbePolicy: &MultiProbePolicyInfo{}}, CodeInternal},
		"refusal for version": {Response{Version: Version + 1, Code: CodeOperationDisabled}, CodeInternal},
	} {
		socket := fakeHelper(t, func(Request) Response { return tt.resp })

		if _, err := ProbeEgressMulti(ctx, socket, f.lab.ProfileID, f.lab.Namespace, *req.Capability); ErrorCode(err) !=
			tt.code {
			t.Errorf("%s: %v", name, err)
		}
	}

	// Letters-only operations were always echoed: an unnamed refusal of one stays invalid.
	legacy := f.mint(probeIntent(f.lab))
	socket := fakeHelper(t, func(Request) Response { return refusal })

	if _, err := ProbeEgress(ctx, socket, f.lab.ProfileID, f.lab.Namespace, *legacy.Capability); ErrorCode(err) !=
		CodeInternal {
		t.Fatalf("unnamed refusal of PermitProbe: %v", err)
	}
}
