package helperipc

import (
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/VanChung369/egresslab/services/network-agent/internal/helperauth"
)

const (
	ipcGenerationA = "tunnelgen_0123456789abcdef0123456789abcdef"
	ipcGenerationB = "tunnelgen_ffffffffffffffffffffffffffffffff"
)

// fakeGenerationProbeBackend is a multi-source backend whose tunnel has a generation: A at first, B
// after a reconnect, none after a cleanup.
type fakeGenerationProbeBackend struct {
	*fakeMultiProbeTunnelBackend

	generation      string
	wrongGeneration bool
	probeDeadline   time.Time // of the last generation-bound probe's context; zero if it had none
}

func (f *fakeGenerationProbeBackend) CurrentTunnelGeneration(string) (string, error) {
	if f.generation == "" {
		return "", errors.New("no current generation")
	}

	return f.generation, nil
}

func (f *fakeGenerationProbeBackend) ConnectStage(ctx context.Context, profileID, namespace, stageID string) error {
	err := f.fakeTunnelBackend.ConnectStage(ctx, profileID, namespace, stageID)
	if err == nil {
		f.generation = ipcGenerationB
	}

	return err
}

func (f *fakeGenerationProbeBackend) CleanupStage(ctx context.Context, namespace string) error {
	err := f.fakeTunnelBackend.CleanupStage(ctx, namespace)
	if err == nil {
		f.generation = ""
	}

	return err
}

func (f *fakeGenerationProbeBackend) ProbeConfiguredMultiForGeneration(
	ctx context.Context,
	namespace, generation string,
) (MultiProbeObservation, error) {
	f.probeDeadline, _ = ctx.Deadline()

	if generation == "" || generation != f.generation {
		return MultiProbeObservation{}, errors.New("generation mismatch")
	}

	observation, err := f.fakeMultiProbeTunnelBackend.ProbeConfiguredMulti(ctx, namespace)
	if err != nil {
		return MultiProbeObservation{}, err
	}

	observation.TunnelGeneration = f.generation
	if f.wrongGeneration {
		observation.TunnelGeneration = "tunnelgen_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	}

	return observation, nil
}

func newGenerationProbeFixture(t *testing.T) (*tunnelFixture, *fakeGenerationProbeBackend) {
	t.Helper()

	f, multi := newMultiProbeFixture(t)
	backend := &fakeGenerationProbeBackend{fakeMultiProbeTunnelBackend: multi, generation: ipcGenerationA}

	f.labs.tunnels = backend
	f.labs.multiProbes = backend
	f.labs.generationProbes = backend

	return f, backend
}

func generationProbeIntent(t *testing.T, lab LabInfo, pin, generation string) helperauth.Intent {
	t.Helper()

	intent, err := helperauth.NewGenerationProbeIntent(lab.ProfileID, lab.Namespace, pin, generation)
	if err != nil {
		t.Fatal(err)
	}

	return intent
}

func generationTargetIntent(lab LabInfo) helperauth.Intent {
	return helperauth.Intent{Operation: OpMultiProbeTarget, ProfileID: lab.ProfileID, Namespace: lab.Namespace}
}

func TestGenerationProbeLifecycle(t *testing.T) {
	ctx := context.Background()
	f, backend := newGenerationProbeFixture(t)
	targetIntent := generationTargetIntent(f.lab)

	target, err := f.labs.readMultiProbeTarget(ctx, &targetIntent, f.verifier, multiProbeTestRuntimeID)
	if err != nil || target.Policy != helperauth.OpPermitMultiProbeV2 || target.TunnelGeneration != ipcGenerationA ||
		target.IdentIPv4 != backend.pin.String() || backend.calls != 0 {
		t.Fatalf("target discovery: %+v %v", target, err)
	}

	if policy, err := f.labs.readMultiProbePolicy(ctx, f.verifier, multiProbeTestRuntimeID); err != nil ||
		policy.Policy != helperauth.OpPermitMultiProbeV2 {
		t.Fatalf("a V2 lifecycle advertised %q: %v", policy.Policy, err)
	}

	intent := generationProbeIntent(t, f.lab, backend.pin.String(), target.TunnelGeneration)
	first := f.mint(intent)

	result, err := f.labs.executeMultiProbe(ctx, first, f.verifier)
	if err != nil || result.TunnelGeneration != ipcGenerationA || result.AttemptNonce != first.Capability.Claims.Nonce ||
		f.labs.verifiedEvidence == nil {
		t.Fatalf("V2 probe: %+v %v", result, err)
	}

	// The attempt cannot outlive the time its evidence could still be recorded.
	if backend.probeDeadline.IsZero() || backend.probeDeadline.After(time.Now().Add(verifiedProbeEvidenceTTL)) {
		t.Fatalf("V2 probe context ends at %v, not by the evidence deadline", backend.probeDeadline)
	}

	evidence := f.labs.verifiedEvidence
	if evidence.intent != intent || evidence.ipv4 != result.IPv4 || evidence.nonce != result.AttemptNonce ||
		evidence.helperID != first.Capability.Claims.HelperID || !evidence.fresh(time.Now()) {
		t.Fatalf("invalid trusted evidence: %+v", evidence)
	}

	// A valid V1 capability does not run on a V2 lifecycle, and leaves the evidence alone.
	legacy := f.mint(multiProbeIntent(f.lab, backend.pin.String()))
	if _, err := f.labs.executeMultiProbe(ctx, legacy, f.verifier); labCode(err) != CodeRuntimeUnavailable ||
		f.labs.verifiedEvidence != evidence {
		t.Fatalf("V1 on a V2 lifecycle: %v", err)
	}

	// Minted for generation A and never used: after the reconnect it is still unexpired.
	unused := f.mint(intent)

	disconnect := Request{Version: Version, Operation: OpDisconnect, Intent: &helperauth.Intent{
		Operation: OpDisconnect, ProfileID: f.lab.ProfileID, Namespace: f.lab.Namespace}}

	if _, err := f.execute(disconnect); err != nil || f.labs.verifiedEvidence != nil {
		t.Fatalf("disconnect kept the evidence: %v", err)
	}

	if _, err := f.execute(f.connectRequest()); err != nil {
		t.Fatal(err)
	}

	target, err = f.labs.readMultiProbeTarget(ctx, &targetIntent, f.verifier, multiProbeTestRuntimeID)
	if err != nil || target.TunnelGeneration != ipcGenerationB {
		t.Fatalf("reconnect kept the generation: %+v %v", target, err)
	}

	if _, err := f.labs.executeMultiProbe(ctx, unused, f.verifier); labCode(err) != CodeAuthorizationDenied {
		t.Fatalf("a capability for the old tunnel authorized the new one: %v", err)
	}

	if backend.calls != 1 || f.labs.verifiedEvidence != nil || f.labs.labs[f.lab.ProfileID].State != LabTunnelConfigured {
		t.Fatal("the stale capability changed the new tunnel")
	}

	current := f.mint(generationProbeIntent(t, f.lab, backend.pin.String(), ipcGenerationB))

	result, err = f.labs.executeMultiProbe(ctx, current, f.verifier)
	if err != nil || result.TunnelGeneration != ipcGenerationB || result.AttemptNonce != current.Capability.Claims.Nonce ||
		f.labs.verifiedEvidence == nil || f.labs.verifiedEvidence == evidence || backend.calls != 2 {
		t.Fatalf("new generation: %+v %v", result, err)
	}
}

// A V1 lifecycle (the production helper of this step) refuses V2 and the target read, and V1
// evidence never carries V2 fields.
func TestGenerationProbeDisabledOnV1Lifecycle(t *testing.T) {
	ctx := context.Background()
	f, backend := newMultiProbeFixture(t)

	v2 := f.mint(generationProbeIntent(t, f.lab, backend.pin.String(), ipcGenerationA))
	if _, err := f.labs.executeMultiProbe(ctx, v2, f.verifier); labCode(err) != CodeRuntimeUnavailable ||
		backend.calls != 0 {
		t.Fatalf("V2 on a V1 lifecycle: %v", err)
	}

	targetIntent := generationTargetIntent(f.lab)
	if _, err := f.labs.readMultiProbeTarget(ctx, &targetIntent, f.verifier, multiProbeTestRuntimeID); labCode(err) !=
		CodeRuntimeUnavailable {
		t.Fatalf("target on a V1 lifecycle: %v", err)
	}

	if policy, err := f.labs.readMultiProbePolicy(ctx, f.verifier, multiProbeTestRuntimeID); err != nil ||
		policy.Policy != helperauth.OpPermitMultiProbe {
		t.Fatalf("a V1 lifecycle advertised %q: %v", policy.Policy, err)
	}

	result, err := f.labs.executeMultiProbe(ctx, f.mint(multiProbeIntent(f.lab, backend.pin.String())), f.verifier)
	if err != nil || f.labs.verifiedEvidence != nil {
		t.Fatalf("V1 probe: %v", err)
	}

	raw, err := json.Marshal(result)
	if err != nil || strings.Contains(string(raw), "tunnel_generation") || strings.Contains(string(raw), "attempt_nonce") {
		t.Fatalf("V1 evidence carries V2 fields: %s", raw)
	}

	// The V2 capability was refused before its nonce: it still verifies.
	if err := f.verifier.VerifyAndConsume(*v2.Capability, *v2.Intent); err != nil {
		t.Fatalf("refusal consumed the V2 capability: %v", err)
	}
}

// Refusals before a nonce is consumed, and reads, leave live evidence exactly as it was.
func TestGenerationEvidenceSurvivesRefusals(t *testing.T) {
	ctx := context.Background()
	f, backend := newGenerationProbeFixture(t)
	intent := generationProbeIntent(t, f.lab, backend.pin.String(), ipcGenerationA)

	used := f.mint(intent)
	if _, err := f.labs.executeMultiProbe(ctx, used, f.verifier); err != nil {
		t.Fatal(err)
	}

	evidence := f.labs.verifiedEvidence

	foreign := f.mint(generationProbeIntent(t, f.lab, backend.pin.String(), ipcGenerationB))

	tampered := f.mint(intent)
	tampered.Capability.Signature = used.Capability.Signature

	unsigned := f.mint(intent)
	unsigned.Capability = nil

	otherPin := f.mint(generationProbeIntent(t, f.lab, "8.8.8.8", ipcGenerationA))

	for name, tt := range map[string]struct {
		req  Request
		code string
	}{
		"foreign generation": {foreign, CodeAuthorizationDenied},
		"tampered signature": {tampered, CodeAuthorizationDenied},
		"replay":             {used, CodeAuthorizationDenied},
		"unsigned":           {unsigned, CodeAuthorizationDenied},
		"another pin":        {otherPin, CodeInvalidRequest},
	} {
		if _, err := f.labs.executeMultiProbe(ctx, tt.req, f.verifier); labCode(err) != tt.code {
			t.Errorf("%s: %v", name, err)
		}

		if f.labs.verifiedEvidence != evidence {
			t.Fatalf("%s changed the evidence", name)
		}
	}

	targetIntent := generationTargetIntent(f.lab)
	if _, err := f.labs.readMultiProbeTarget(ctx, &targetIntent, f.verifier, multiProbeTestRuntimeID); err != nil ||
		f.labs.verifiedEvidence != evidence || backend.calls != 1 {
		t.Fatalf("target read: %v", err)
	}

	verify := Request{Version: Version, Operation: OpVerifyLab, Intent: &helperauth.Intent{
		Operation: OpVerifyLab, ProfileID: f.lab.ProfileID, Namespace: f.lab.Namespace}}

	if _, err := f.execute(verify); err != nil || f.labs.verifiedEvidence != evidence {
		t.Fatalf("a successful verify-lab dropped the evidence: %v", err)
	}
}

func TestGenerationEvidenceInvalidation(t *testing.T) {
	for _, mode := range []string{
		"probe failure",
		"wrong returned generation",
		"kernel verification failure",
		"uncertain cleanup",
		"delete lab",
		"shutdown",
	} {
		t.Run(mode, func(t *testing.T) {
			ctx := context.Background()
			f, backend := newGenerationProbeFixture(t)
			intent := generationProbeIntent(t, f.lab, backend.pin.String(), ipcGenerationA)

			if _, err := f.labs.executeMultiProbe(ctx, f.mint(intent), f.verifier); err != nil ||
				f.labs.verifiedEvidence == nil {
				t.Fatalf("initial evidence: %v", err)
			}

			var err error

			switch mode {
			case "shutdown":
				err = f.labs.Close()
			case "delete lab":
				_, err = f.execute(Request{Version: Version, Operation: OpDeleteLab, Intent: &helperauth.Intent{
					Operation: OpDeleteLab, ProfileID: f.lab.ProfileID, Namespace: f.lab.Namespace}})
			case "kernel verification failure":
				backend.verifyErr = errors.New("kernel drift")
				_, err = f.execute(Request{Version: Version, Operation: OpVerifyLab, Intent: &helperauth.Intent{
					Operation: OpVerifyLab, ProfileID: f.lab.ProfileID, Namespace: f.lab.Namespace}})
			default:
				switch mode {
				case "probe failure":
					backend.probeErr = errors.New("source unavailable")
				case "wrong returned generation":
					backend.wrongGeneration = true
				case "uncertain cleanup":
					backend.probeErr = errors.New("probe failed")
					backend.cleanupErr = errors.New("cleanup failed")
				}

				var result MultiProbeInfo
				result, err = f.labs.executeMultiProbe(ctx, f.mint(intent), f.verifier)

				if result.IPv4.IsValid() || result.TunnelGeneration != "" || result.AttemptNonce != "" || result.Sources != nil {
					t.Fatal("a failed probe returned evidence")
				}
			}

			if mode != "shutdown" && mode != "delete lab" && err == nil {
				t.Fatal("failure accepted")
			}

			if f.labs.verifiedEvidence != nil {
				t.Fatal("evidence kept")
			}

			if mode == "uncertain cleanup" && labCode(err) != CodeStateUncertain {
				t.Fatalf("uncertain cleanup not reported: %v", err)
			}
		})
	}
}

// Deleting another profile's lab leaves this profile's evidence. Both labs exist before the tunnel:
// no lab is created while one does.
func TestGenerationEvidenceBelongsToItsProfile(t *testing.T) {
	ctx := context.Background()
	f := newTunnelFixture(t)
	other := f.createLab(t, "profile_ffffffffffffffff")

	multi := &fakeMultiProbeTunnelBackend{fakeTunnelBackend: f.tunnels, pin: netip.MustParseAddr("9.9.9.9")}
	backend := &fakeGenerationProbeBackend{fakeMultiProbeTunnelBackend: multi, generation: ipcGenerationA}
	f.labs.tunnels, f.labs.multiProbes, f.labs.generationProbes = backend, backend, backend

	if _, err := f.execute(f.connectRequest()); err != nil {
		t.Fatal(err)
	}

	if _, err := f.labs.executeMultiProbe(ctx, f.mint(generationProbeIntent(t, f.lab, multi.pin.String(),
		backend.generation)), f.verifier); err != nil {
		t.Fatal(err)
	}

	evidence := f.labs.verifiedEvidence

	if _, err := f.execute(Request{Version: Version, Operation: OpDeleteLab, Intent: &helperauth.Intent{
		Operation: OpDeleteLab, ProfileID: other.ProfileID, Namespace: other.Namespace}}); err != nil {
		t.Fatal(err)
	}

	if evidence == nil || f.labs.verifiedEvidence != evidence {
		t.Fatal("deleting another lab dropped the evidence")
	}
}

func TestGenerationEvidenceFreshness(t *testing.T) {
	ctx := context.Background()
	f, backend := newGenerationProbeFixture(t)
	req := f.mint(generationProbeIntent(t, f.lab, backend.pin.String(), ipcGenerationA))

	if _, err := f.labs.executeMultiProbe(ctx, req, f.verifier); err != nil {
		t.Fatal(err)
	}

	evidence := f.labs.verifiedEvidence
	if evidence == nil || !evidence.fresh(evidence.recordedAt) {
		t.Fatal("fresh evidence refused")
	}

	if evidence.fresh(evidence.expiresAt) || evidence.fresh(evidence.recordedAt.Add(-time.Second)) {
		t.Fatal("expired or backdated evidence accepted")
	}

	if evidence.expiresAt.Sub(evidence.observedAt) > verifiedProbeEvidenceTTL {
		t.Fatal("deadline beyond the freshness window")
	}

	next := f.mint(*req.Intent)

	result, err := f.labs.executeMultiProbe(ctx, next, f.verifier)
	if err != nil || result.AttemptNonce == evidence.nonce || f.labs.verifiedEvidence.nonce != result.AttemptNonce {
		t.Fatalf("attempt identity reused: %v", err)
	}

	if validMultiProbeForCapability(&result, req.Intent, req.Capability) {
		t.Fatal("new evidence matched an older capability")
	}
}

// The deadline is the earlier of acceptance + 60 s and the oldest observation + 60 s, and a
// recording at or past either is refused.
func TestNewVerifiedMultiProbeEvidence(t *testing.T) {
	f, backend := newGenerationProbeFixture(t)
	req := f.mint(generationProbeIntent(t, f.lab, backend.pin.String(), ipcGenerationA))

	accepted := time.Now()
	observation, err := backend.ProbeConfiguredMultiForGeneration(context.Background(), f.lab.Namespace, ipcGenerationA)
	if err != nil {
		t.Fatal(err)
	}

	info := MultiProbeInfo{ProfileID: f.lab.ProfileID, Namespace: f.lab.Namespace, MultiProbeObservation: observation,
		AttemptNonce: req.Capability.Claims.Nonce}
	// From accepted alone (Add moves its wall and monotonic readings together), so a pause cannot
	// reorder the instants: now is 1 ms after the evidence finished.
	now := accepted.Add(info.FinishedAt.Sub(accepted.Round(0)) + time.Millisecond)

	evidence, err := newVerifiedMultiProbeEvidence(info, *req.Capability, accepted, now)
	if err != nil {
		t.Fatal(err)
	}

	byObservation := now.Add(verifiedProbeEvidenceTTL - now.Sub(info.ObservedAt))
	byAcceptance := accepted.Add(verifiedProbeEvidenceTTL)
	if want := byAcceptance; byObservation.Before(want) {
		want = byObservation
		if !evidence.expiresAt.Equal(want) {
			t.Fatalf("deadline %v, want the earlier %v", evidence.expiresAt, want)
		}
	} else if !evidence.expiresAt.Equal(want) {
		t.Fatalf("deadline %v, want the earlier %v", evidence.expiresAt, want)
	}

	// The attempt's own time window still applies: evidence finishing after now is refused.
	if _, err := newVerifiedMultiProbeEvidence(info, *req.Capability, accepted, accepted.Add(-time.Second)); err == nil {
		t.Fatal("evidence recorded before it finished")
	}

	// An attempt accepted 60 s ago under a capability issued before it: valid in every other way,
	// so only expiry can refuse it.
	early := f.mintAt(*req.Intent, time.Now().Add(-70*time.Second))
	old := info
	old.AttemptNonce = early.Capability.Claims.Nonce
	old.Sources = append([]MultiProbeSourceObservation(nil), info.Sources...)
	shiftObservation(-verifiedProbeEvidenceTTL)(&old.MultiProbeObservation)

	if _, err := newVerifiedMultiProbeEvidence(old, *early.Capability, accepted.Add(-verifiedProbeEvidenceTTL),
		now); !errors.Is(err, errVerifiedEvidenceExpired) {
		t.Fatalf("60 s old observation recorded: %v", err)
	}

	for name, edit := range map[string]func(*MultiProbeInfo, *helperauth.SignedCapability){
		"V1 capability": func(_ *MultiProbeInfo, c *helperauth.SignedCapability) {
			c.Claims.Intent.Operation = helperauth.OpPermitMultiProbe
		},
		"another nonce": func(i *MultiProbeInfo, _ *helperauth.SignedCapability) {
			i.AttemptNonce = strings.Repeat("0", 32)
		},
		"another generation": func(i *MultiProbeInfo, _ *helperauth.SignedCapability) { i.TunnelGeneration = ipcGenerationB },
	} {
		bad, capability := info, *req.Capability
		edit(&bad, &capability)

		if _, err := newVerifiedMultiProbeEvidence(bad, capability, accepted, now); err == nil {
			t.Errorf("%s recorded", name)
		}
	}
}

func TestReadMultiProbeTargetRefusals(t *testing.T) {
	ctx := context.Background()
	f, backend := newGenerationProbeFixture(t)
	intent := generationTargetIntent(f.lab)

	cancelled, cancel := context.WithCancel(ctx)
	cancel()

	setState := func(state string) func() {
		return func() {
			lab := f.labs.labs[f.lab.ProfileID]
			lab.State = state
			f.labs.labs[f.lab.ProfileID] = lab
		}
	}

	for name, tt := range map[string]struct {
		setup, undo func()
		intent      helperauth.Intent
		cancelled   bool
		noVerifier  bool
		code        string
	}{
		"busy": {setup: func() { f.labs.mu.Lock() }, undo: func() { f.labs.mu.Unlock() }, code: CodeLabBusy},
		"closed": {setup: func() { f.labs.closed = true }, undo: func() { f.labs.closed = false },
			code: CodeRuntimeUnavailable},
		"cancelled": {cancelled: true, code: CodeRuntimeUnavailable},
		"kernel uncertain": {setup: func() { f.labs.blockCreation = true }, undo: func() { f.labs.blockCreation = false },
			code: CodeStateUncertain},
		"sealed lab":  {setup: setState(LabSealed), undo: setState(LabTunnelConfigured), code: CodeInvalidRequest},
		"faulted lab": {setup: setState(LabFaulted), undo: setState(LabTunnelConfigured), code: CodeLabFaulted},
		"tunnel elsewhere": {setup: func() { f.labs.tunnelProfile = "" },
			undo: func() { f.labs.tunnelProfile = f.lab.ProfileID }, code: CodeStateUncertain},
		"no generation": {setup: func() { backend.generation = "" }, undo: func() { backend.generation = ipcGenerationA },
			code: CodeStateUncertain},
		"policy unreadable": {setup: func() { backend.pinErr = errors.New("no policy") },
			undo: func() { backend.pinErr = nil }, code: CodeRuntimeUnavailable},
		"no verifier": {noVerifier: true, code: CodeRuntimeUnavailable},
		"no lab": {intent: helperauth.Intent{Operation: OpMultiProbeTarget, ProfileID: "profile_ffffffffffffffff",
			Namespace: f.lab.Namespace}, code: CodeLabNotFound},
		"another namespace": {intent: helperauth.Intent{Operation: OpMultiProbeTarget, ProfileID: f.lab.ProfileID,
			Namespace: "egresslab-lab-ffffffffffffffff"}, code: CodeOwnershipMismatch},
		"intent with a pin": {intent: helperauth.Intent{Operation: OpMultiProbeTarget, ProfileID: f.lab.ProfileID,
			Namespace: f.lab.Namespace, ProbeIPv4: "9.9.9.9"}, code: CodeInvalidRequest},
		"intent with a generation": {intent: helperauth.Intent{Operation: OpMultiProbeTarget, ProfileID: f.lab.ProfileID,
			Namespace: f.lab.Namespace, TunnelGeneration: ipcGenerationA}, code: CodeInvalidRequest},
	} {
		callIntent, callCtx, v := intent, ctx, f.verifier
		if tt.intent.Operation != "" {
			callIntent = tt.intent
		}

		if tt.cancelled {
			callCtx = cancelled
		}

		if tt.noVerifier {
			v = nil
		}

		if tt.setup != nil {
			tt.setup()
		}

		target, err := f.labs.readMultiProbeTarget(callCtx, &callIntent, v, multiProbeTestRuntimeID)

		if tt.undo != nil {
			tt.undo()
		}

		if labCode(err) != tt.code || target != (MultiProbeTargetInfo{}) {
			t.Errorf("%s: %+v %v", name, target, err)
		}
	}

	if backend.calls != 0 {
		t.Fatal("a target read ran a probe")
	}
}

func TestMultiProbeTargetResponseValidation(t *testing.T) {
	intent := helperauth.Intent{Operation: OpMultiProbeTarget, ProfileID: lifecycleProfile,
		Namespace: "egresslab-lab-0123456789abcdef"}
	req := Request{Version: Version, Operation: OpMultiProbeTarget, Intent: &intent}

	valid := MultiProbeTargetInfo{
		ProfileID:        intent.ProfileID,
		Namespace:        intent.Namespace,
		TunnelGeneration: ipcGenerationA,
		MultiProbePolicyInfo: MultiProbePolicyInfo{
			Policy:          helperauth.OpPermitMultiProbeV2,
			IdentIPv4:       "9.9.9.9",
			HelperID:        "helper_0123456789abcdef0123456789abcdef",
			RuntimeID:       multiProbeTestRuntimeID,
			PublicKeySHA256: strings.Repeat("ab", 32),
		},
	}

	ok := func(p *MultiProbeTargetInfo) Response {
		return Response{Version: Version, Operation: OpMultiProbeTarget, OK: true, MultiProbeTarget: p}
	}

	if !validMultiProbeTargetResponse(req, ok(&valid)) {
		t.Fatal("valid target refused")
	}

	for name, edit := range map[string]func(*MultiProbeTargetInfo){
		"another profile":    func(p *MultiProbeTargetInfo) { p.ProfileID = "profile_ffffffffffffffff" },
		"another namespace":  func(p *MultiProbeTargetInfo) { p.Namespace = "egresslab-lab-ffffffffffffffff" },
		"invalid generation": func(p *MultiProbeTargetInfo) { p.TunnelGeneration = "tunnelgen_x" },
		"V1 policy":          func(p *MultiProbeTargetInfo) { p.Policy = helperauth.OpPermitMultiProbe },
		"private pin":        func(p *MultiProbeTargetInfo) { p.IdentIPv4 = "10.0.0.1" },
		"invalid epoch":      func(p *MultiProbeTargetInfo) { p.HelperID = "helper_x" },
	} {
		bad := valid
		edit(&bad)

		if validMultiProbeTargetResponse(req, ok(&bad)) {
			t.Errorf("%s accepted", name)
		}
	}

	withCapability := req
	withCapability.Capability = &helperauth.SignedCapability{}

	for name, tt := range map[string]struct {
		req  Request
		resp Response
	}{
		"capability in the request": {withCapability, ok(&valid)},
		"success without target":    {req, ok(nil)},
		"failure with target": {req, Response{Version: Version, Operation: OpMultiProbeTarget, Code: CodeLabBusy,
			MultiProbeTarget: &valid}},
		"unsolicited target": {Request{Version: Version, Operation: OpPing},
			Response{Version: Version, Operation: OpPing, OK: true, MultiProbeTarget: &valid}},
	} {
		if validMultiProbeTargetResponse(tt.req, tt.resp) {
			t.Errorf("%s accepted", name)
		}
	}
}

// V1 evidence carrying a V2 field is refused, and the V2 client refuses anything but a V2
// capability before it contacts the helper.
func TestGenerationFieldsStayInV2(t *testing.T) {
	f, backend := newMultiProbeFixture(t)
	req := f.mint(multiProbeIntent(f.lab, backend.pin.String()))

	observation, err := backend.ProbeConfiguredMulti(context.Background(), f.lab.Namespace)
	if err != nil {
		t.Fatal(err)
	}

	info := MultiProbeInfo{ProfileID: f.lab.ProfileID, Namespace: f.lab.Namespace, MultiProbeObservation: observation}
	if !validMultiProbeForCapability(&info, req.Intent, req.Capability) {
		t.Fatal("valid V1 evidence refused")
	}

	withGeneration := info
	withGeneration.TunnelGeneration = ipcGenerationA

	withNonce := info
	withNonce.AttemptNonce = req.Capability.Claims.Nonce

	for name, bad := range map[string]MultiProbeInfo{"generation": withGeneration, "attempt nonce": withNonce} {
		if validMultiProbeForCapability(&bad, req.Intent, req.Capability) {
			t.Errorf("V1 evidence with a %s accepted", name)
		}
	}

	for name, capability := range map[string]helperauth.SignedCapability{
		"V1 capability": *req.Capability,
		"no generation": {Claims: helperauth.Claims{Intent: helperauth.Intent{Operation: helperauth.OpPermitMultiProbeV2,
			ProfileID: f.lab.ProfileID, Namespace: f.lab.Namespace, ProbeIPv4: "9.9.9.9"}}},
		"V1 operation with a generation": {Claims: helperauth.Claims{Intent: helperauth.Intent{
			Operation: helperauth.OpPermitMultiProbe, ProfileID: f.lab.ProfileID, Namespace: f.lab.Namespace,
			ProbeIPv4: "9.9.9.9", TunnelGeneration: ipcGenerationA}}},
		"another profile": {Claims: helperauth.Claims{Intent: helperauth.Intent{Operation: helperauth.OpPermitMultiProbeV2,
			ProfileID: "profile_ffffffffffffffff", Namespace: f.lab.Namespace, ProbeIPv4: "9.9.9.9",
			TunnelGeneration: ipcGenerationA}}},
	} {
		if _, err := ProbeEgressMultiV2(context.Background(), "/nonexistent/helper.sock", f.lab.ProfileID,
			f.lab.Namespace, capability); ErrorCode(err) != CodeInvalidRequest {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// With the oldest observation just before acceptance, its deadline is the earlier one.
func TestVerifiedEvidenceDeadlineFollowsObservation(t *testing.T) {
	f, backend := newGenerationProbeFixture(t)
	req := f.mintAt(generationProbeIntent(t, f.lab, backend.pin.String(), ipcGenerationA), time.Now().Add(-2*time.Second))

	accepted := time.Now()
	wall := accepted.Round(0).UTC()
	ip := netip.MustParseAddr("8.8.4.4")

	info := MultiProbeInfo{
		ProfileID:    f.lab.ProfileID,
		Namespace:    f.lab.Namespace,
		AttemptNonce: req.Capability.Claims.Nonce,
		MultiProbeObservation: MultiProbeObservation{
			TunnelGeneration: ipcGenerationA,
			IPv4:             ip,
			StartedAt:        wall.Add(-900 * time.Millisecond),
			FinishedAt:       wall.Add(time.Second),
			ObservedAt:       wall.Add(-500 * time.Millisecond),
			HandshakeAt:      wall.Add(-2 * time.Second).Truncate(time.Second),
			Sources: []MultiProbeSourceObservation{
				{helperauth.MultiProbeCloudflareSource, netip.MustParseAddr("1.1.1.1"), ip, wall.Add(-500 * time.Millisecond)},
				{helperauth.MultiProbeIdentSource, backend.pin, ip, wall.Add(-400 * time.Millisecond)},
			},
		}}

	now := accepted.Add(2 * time.Second)

	evidence, err := newVerifiedMultiProbeEvidence(info, *req.Capability, accepted, now)
	if err != nil {
		t.Fatal(err)
	}

	want := now.Add(verifiedProbeEvidenceTTL - now.Sub(info.ObservedAt))
	if !evidence.expiresAt.Equal(want) || !evidence.expiresAt.Before(accepted.Add(verifiedProbeEvidenceTTL)) {
		t.Fatalf("deadline %v, want %v", evidence.expiresAt, want)
	}
}

// fresh refuses a reading taken before the record, even when the evidence would still be young.
func TestVerifiedEvidenceFreshBounds(t *testing.T) {
	base := time.Now()
	e := &verifiedMultiProbeEvidence{
		observedAt: base.Round(0).Add(-10 * time.Second),
		recordedAt: base,
		expiresAt:  base.Add(50 * time.Second),
	}

	for name, tt := range map[string]struct {
		now time.Time
		ok  bool
	}{
		"at the record":       {base, true},
		"before the deadline": {base.Add(49 * time.Second), true},
		"at the deadline":     {base.Add(50 * time.Second), false},
		"before the record":   {base.Add(-time.Millisecond), false},
	} {
		if e.fresh(tt.now) != tt.ok {
			t.Errorf("%s: want %t", name, tt.ok)
		}
	}

	if (*verifiedMultiProbeEvidence)(nil).fresh(base) {
		t.Fatal("nil evidence fresh")
	}
}
