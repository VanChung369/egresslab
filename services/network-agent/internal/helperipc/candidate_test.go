package helperipc

import (
	"context"
	"errors"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/VanChung369/egresslab/services/network-agent/internal/helperauth"
)

// newVerifiedCandidateFixture runs one signed V2 probe (fake kernel backend, no network) and mints
// the reservation its evidence backs.
func newVerifiedCandidateFixture(t *testing.T) (*tunnelFixture, *fakeGenerationProbeBackend, Request) {
	t.Helper()

	f, backend := newGenerationProbeFixture(t)

	probe := f.mint(generationProbeIntent(t, f.lab, backend.pin.String(), backend.generation))
	if _, err := f.labs.executeMultiProbe(context.Background(), probe, f.verifier); err != nil {
		t.Fatal(err)
	}

	evidence := f.labs.verifiedEvidence
	if evidence == nil || !evidence.fresh(time.Now()) {
		t.Fatal("fixture has no verified evidence")
	}

	intent, err := candidateIntentFromEvidence(evidence)
	if err != nil {
		t.Fatal(err)
	}

	return f, backend, f.mint(intent)
}

func runCandidateRequest(f *tunnelFixture, req Request) (CandidateInfo, error) {
	return f.labs.reserveEgressCandidate(context.Background(), req, f.verifier, multiProbeTestRuntimeID)
}

func labRequest(op string, lab LabInfo) Request {
	return Request{Version: Version, Operation: op, Intent: &helperauth.Intent{Operation: op, ProfileID: lab.ProfileID,
		Namespace: lab.Namespace}}
}

func TestCandidateConsumesEvidenceOnce(t *testing.T) {
	f, backend, req := newVerifiedCandidateFixture(t)
	original := f.labs.verifiedEvidence
	before := backend.verifies

	result, err := runCandidateRequest(f, req)
	if err != nil {
		t.Fatal(err)
	}

	if !result.valid() ||
		result.IPv4 != original.ipv4 ||
		result.EvidenceNonce != original.nonce ||
		result.ReservationNonce != req.Capability.Claims.Nonce ||
		result.TunnelGeneration != original.intent.TunnelGeneration ||
		!result.ObservedAt.Equal(original.observedAt) ||
		!result.ExpiresAt.Equal(original.expiresAt) {
		t.Fatalf("invalid candidate: %+v", result)
	}

	if f.labs.verifiedEvidence != nil || f.labs.localCandidate == nil || !f.labs.localCandidate.fresh(time.Now()) {
		t.Fatal("invalid evidence consumption state")
	}

	candidate := f.labs.localCandidate

	if backend.verifies != before+1 || backend.calls != 1 || backend.cleanups != 0 ||
		f.labs.labs.peek(f.lab.ProfileID).State != LabTunnelConfigured {
		t.Fatal("reservation probed again or changed the tunnel")
	}

	if _, err := runCandidateRequest(f, req); labCode(err) != CodeEvidenceUnavailable {
		t.Fatalf("candidate replay accepted: %v", err)
	}

	// A new reservation nonce still cannot consume the same evidence.
	if _, err := runCandidateRequest(f, f.mint(*req.Intent)); labCode(err) != CodeEvidenceUnavailable {
		t.Fatalf("evidence consumed twice: %v", err)
	}

	if f.labs.localCandidate != candidate {
		t.Fatal("a refusal replaced the candidate")
	}

	// The candidate keeps the evidence's deadline; it is not extended.
	if candidate.fresh(original.expiresAt) {
		t.Fatal("expired candidate accepted")
	}
}

func TestCandidateRefusalsPreserveEvidence(t *testing.T) {
	f, backend, req := newVerifiedCandidateFixture(t)
	original := f.labs.verifiedEvidence
	before := backend.verifies

	unsigned := req
	unsigned.Capability = nil

	tampered := req
	capability := *req.Capability
	capability.Signature = "invalid"
	tampered.Capability = &capability

	foreignEvidence := *req.Intent
	foreignEvidence.EvidenceNonce = strings.Repeat("f", 32)

	foreignGeneration := *req.Intent
	foreignGeneration.TunnelGeneration = ipcGenerationB

	wrongPin := *req.Intent
	wrongPin.ProbeIPv4 = "8.8.8.8"

	for name, bad := range map[string]Request{
		"unsigned":           unsigned,
		"tampered signature": tampered,
		"foreign evidence":   f.mint(foreignEvidence),
		"foreign generation": f.mint(foreignGeneration),
		"wrong source pin":   f.mint(wrongPin),
		"expired capability": f.mintAt(*req.Intent, time.Now().Add(-time.Minute)),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := runCandidateRequest(f, bad); labCode(err) != CodeAuthorizationDenied {
				t.Fatalf("unexpected refusal: %v", err)
			}

			if f.labs.verifiedEvidence != original || f.labs.localCandidate != nil || backend.verifies != before {
				t.Fatal("refused request changed state")
			}
		})
	}

	// The probe's own capability, replayed as a reservation: refused before anything changes.
	probeAsReservation := req
	probeCapability := *req.Capability
	probeCapability.Claims.Nonce = original.nonce
	probeAsReservation.Capability = &probeCapability

	if _, err := runCandidateRequest(f, probeAsReservation); labCode(err) != CodeAuthorizationDenied {
		t.Fatalf("evidence nonce reused as the reservation nonce: %v", err)
	}

	if _, err := runCandidateRequest(f, req); err != nil {
		t.Fatalf("valid evidence no longer usable: %v", err)
	}
}

func TestCandidateRefusesUnusableLab(t *testing.T) {
	t.Run("sealed lab", func(t *testing.T) {
		f, _, req := newVerifiedCandidateFixture(t)
		lab := f.labs.labs.peek(f.lab.ProfileID)
		lab.State = LabSealed
		f.labs.labs.set(f.lab.ProfileID, lab)

		if _, err := runCandidateRequest(f, req); labCode(err) != CodeInvalidRequest {
			t.Fatalf("sealed lab: %v", err)
		}
	})

	t.Run("generation moved on", func(t *testing.T) {
		f, backend, req := newVerifiedCandidateFixture(t)
		backend.generation = ipcGenerationB

		if _, err := runCandidateRequest(f, req); labCode(err) != CodeAuthorizationDenied {
			t.Fatalf("stale generation: %v", err)
		}

		if f.labs.verifiedEvidence == nil {
			t.Fatal("refusal consumed the evidence")
		}
	})

	t.Run("policy pin changed since the probe", func(t *testing.T) {
		f, backend, req := newVerifiedCandidateFixture(t)
		evidence := f.labs.verifiedEvidence
		backend.pin = netip.MustParseAddr("8.8.4.4")

		if _, err := runCandidateRequest(f, req); labCode(err) != CodeStateUncertain {
			t.Fatalf("changed policy: %v", err)
		}

		if f.labs.verifiedEvidence != evidence || f.labs.localCandidate != nil {
			t.Fatal("refusal consumed the evidence")
		}
	})

	t.Run("no generation-bound lifecycle", func(t *testing.T) {
		f, _, req := newVerifiedCandidateFixture(t)
		f.labs.generationProbes = nil

		if _, err := runCandidateRequest(f, req); labCode(err) != CodeRuntimeUnavailable {
			t.Fatalf("V1 lifecycle: %v", err)
		}
	})
}

func TestCandidateExpiredEvidence(t *testing.T) {
	f, backend, req := newVerifiedCandidateFixture(t)
	f.labs.verifiedEvidence.expiresAt = time.Now().Add(-time.Second)
	before := backend.verifies

	result, err := runCandidateRequest(f, req)
	if labCode(err) != CodeEvidenceUnavailable || result.IPv4.IsValid() || f.labs.localCandidate != nil ||
		backend.verifies != before {
		t.Fatalf("expired evidence accepted: %+v %v", result, err)
	}

	// The evidence check came first: the reservation capability is still unused.
	if err := f.verifier.VerifyAndConsume(*req.Capability, *req.Intent); err != nil {
		t.Fatalf("expired evidence consumed the capability: %v", err)
	}
}

func TestCandidateConcurrentConsumption(t *testing.T) {
	f, backend, first := newVerifiedCandidateFixture(t)
	second := f.mint(*first.Intent)

	type attempt struct {
		info CandidateInfo
		err  error
	}

	start := make(chan struct{})
	results := make(chan attempt, 2)

	var wg sync.WaitGroup

	for _, req := range []Request{first, second} {
		wg.Add(1)

		go func() {
			defer wg.Done()
			<-start

			info, err := runCandidateRequest(f, req)
			results <- attempt{info, err}
		}()
	}

	close(start)
	wg.Wait()
	close(results)

	successes, refusals := 0, 0

	for r := range results {
		if r.err == nil {
			successes++

			if !r.info.valid() {
				t.Fatal("the winner returned an invalid candidate")
			}

			continue
		}

		refusals++

		switch labCode(r.err) {
		case CodeLabBusy, CodeEvidenceUnavailable:
		default:
			t.Fatalf("unexpected concurrent refusal: %v", r.err)
		}
	}

	if successes != 1 || refusals != 1 || f.labs.verifiedEvidence != nil || f.labs.localCandidate == nil ||
		backend.calls != 1 {
		t.Fatalf("invalid atomic consumption: %d succeeded, %d refused", successes, refusals)
	}
}

func TestCandidateVerificationFailure(t *testing.T) {
	for _, uncertain := range []bool{false, true} {
		name := "confirmed cleanup"
		if uncertain {
			name = "uncertain cleanup"
		}

		t.Run(name, func(t *testing.T) {
			f, backend, req := newVerifiedCandidateFixture(t)
			backend.verifyErr = errors.New("kernel drift")

			want := CodeLabFaulted
			if uncertain {
				backend.cleanupErr = errors.New("cleanup failed")
				want = CodeStateUncertain
			}

			result, err := runCandidateRequest(f, req)
			if labCode(err) != want || result.IPv4.IsValid() || f.labs.verifiedEvidence != nil ||
				f.labs.localCandidate != nil {
				t.Fatalf("failed reservation returned a candidate: %+v %v", result, err)
			}

			if backend.cleanups != 1 || f.labs.labs.peek(f.lab.ProfileID).State != LabFaulted {
				t.Fatal("invalid rollback state")
			}

			if uncertain {
				if f.labs.tunnelProfile != f.lab.ProfileID {
					t.Fatal("uncertain tunnel ownership forgotten")
				}
			} else if f.labs.tunnelProfile != "" {
				t.Fatal("confirmed cleanup kept the tunnel slot")
			}
		})
	}
}

// generationChangingBackend moves to another generation while the tunnel is verified.
type generationChangingBackend struct {
	*fakeGenerationProbeBackend
}

func (b *generationChangingBackend) VerifyConfigured(ctx context.Context, namespace string) error {
	err := b.fakeGenerationProbeBackend.VerifyConfigured(ctx, namespace)
	b.generation = ipcGenerationB

	return err
}

// The generation changes while the reservation verifies the tunnel: no candidate, and the tunnel
// is removed.
func TestCandidateGenerationChangeDuringVerification(t *testing.T) {
	f, backend, req := newVerifiedCandidateFixture(t)

	changing := &generationChangingBackend{backend}
	f.labs.tunnels, f.labs.multiProbes, f.labs.generationProbes = changing, changing, changing

	if _, err := runCandidateRequest(f, req); labCode(err) != CodeStateUncertain {
		t.Fatalf("generation change accepted: %v", err)
	}

	if f.labs.localCandidate != nil || f.labs.labs.peek(f.lab.ProfileID).State != LabFaulted || backend.cleanups != 1 {
		t.Fatal("candidate published or tunnel kept after a generation change")
	}
}

func TestCandidateLifecycleInvalidation(t *testing.T) {
	for _, mode := range []string{"new probe", "failed probe", "disconnect", "delete", "kernel drift", "shutdown"} {
		t.Run(mode, func(t *testing.T) {
			ctx := context.Background()
			f, backend, req := newVerifiedCandidateFixture(t)

			if _, err := runCandidateRequest(f, req); err != nil {
				t.Fatal(err)
			}

			if f.labs.localCandidate == nil {
				t.Fatal("initial candidate missing")
			}

			var err error

			switch mode {
			case "new probe", "failed probe":
				if mode == "failed probe" {
					backend.probeErr = errors.New("source failed")
				}

				next := f.mint(generationProbeIntent(t, f.lab, backend.pin.String(), backend.generation))
				_, err = f.labs.executeMultiProbe(ctx, next, f.verifier)

			case "shutdown":
				err = f.labs.Close()

			case "disconnect":
				_, err = f.execute(labRequest(OpDisconnect, f.lab))

			case "delete":
				_, err = f.execute(labRequest(OpDeleteLab, f.lab))

			case "kernel drift":
				backend.verifyErr = errors.New("kernel drift")
				_, err = f.execute(labRequest(OpVerifyLab, f.lab))
			}

			if wantErr := mode == "kernel drift" || mode == "failed probe"; (err != nil) != wantErr {
				t.Fatalf("unexpected lifecycle result: %v", err)
			}

			if f.labs.localCandidate != nil {
				t.Fatal("invalidated candidate kept")
			}

			if mode == "new probe" {
				if f.labs.verifiedEvidence == nil || f.labs.verifiedEvidence.nonce == req.Intent.EvidenceNonce {
					t.Fatal("the new attempt reused the old evidence")
				}
			} else if f.labs.verifiedEvidence != nil {
				t.Fatal("old evidence kept")
			}
		})
	}
}

func TestCandidateRejectsPreviousGeneration(t *testing.T) {
	ctx := context.Background()
	f, backend, old := newVerifiedCandidateFixture(t)

	// The old reservation capability was never used and may still be valid.
	if _, err := f.execute(labRequest(OpDisconnect, f.lab)); err != nil {
		t.Fatal(err)
	}

	if _, err := f.execute(f.connectRequest()); err != nil {
		t.Fatal(err)
	}

	probe := f.mint(generationProbeIntent(t, f.lab, backend.pin.String(), ipcGenerationB))
	if _, err := f.labs.executeMultiProbe(ctx, probe, f.verifier); err != nil {
		t.Fatal(err)
	}

	current := f.labs.verifiedEvidence

	if _, err := runCandidateRequest(f, old); labCode(err) != CodeAuthorizationDenied {
		t.Fatalf("previous generation candidate accepted: %v", err)
	}

	if f.labs.verifiedEvidence != current || f.labs.localCandidate != nil {
		t.Fatal("a stale request changed the new generation")
	}

	intent, err := candidateIntentFromEvidence(current)
	if err != nil {
		t.Fatal(err)
	}

	result, err := runCandidateRequest(f, f.mint(intent))
	if err != nil || result.TunnelGeneration != ipcGenerationB || result.EvidenceNonce == old.Intent.EvidenceNonce {
		t.Fatalf("new generation reservation failed: %+v %v", result, err)
	}
}

func TestCandidateResponseValidation(t *testing.T) {
	f, _, req := newVerifiedCandidateFixture(t)

	info, err := runCandidateRequest(f, req)
	if err != nil {
		t.Fatal(err)
	}

	valid := Response{Version: Version, Operation: req.Operation, OK: true, Candidate: &info}

	if !validCandidateResponse(req, valid, time.Now()) {
		t.Fatal("valid candidate response refused")
	}

	for name, mutate := range map[string]func(*CandidateInfo){
		"wrong generation":        func(c *CandidateInfo) { c.TunnelGeneration = ipcGenerationB },
		"wrong evidence nonce":    func(c *CandidateInfo) { c.EvidenceNonce = strings.Repeat("f", 32) },
		"wrong reservation nonce": func(c *CandidateInfo) { c.ReservationNonce = strings.Repeat("f", 32) },
		"wrong source policy":     func(c *CandidateInfo) { c.Policy = helperauth.OpPermitMultiProbe },
		"wrong helper":            func(c *CandidateInfo) { c.HelperID = "helper_" + strings.Repeat("f", 32) },
		"extended TTL":            func(c *CandidateInfo) { c.ExpiresAt = c.ObservedAt.Add(61 * time.Second) },
		"private address":         func(c *CandidateInfo) { c.IPv4 = netip.MustParseAddr("10.0.0.1") },
	} {
		t.Run(name, func(t *testing.T) {
			bad := info
			mutate(&bad)

			response := valid
			response.Candidate = &bad

			if validCandidateResponse(req, response, time.Now()) {
				t.Fatal("invalid candidate response accepted")
			}
		})
	}

	if validCandidateResponse(req, valid, info.ExpiresAt) {
		t.Fatal("expired candidate response accepted")
	}

	if validCandidateResponse(req, valid, info.ObservedAt.Add(-time.Second)) {
		t.Fatal("candidate received before its observation accepted")
	}

	networkReady := valid
	networkReady.NetworkReady = true

	if validCandidateResponse(req, networkReady, time.Now()) {
		t.Fatal("network_ready candidate accepted")
	}

	failure := valid
	failure.OK = false

	if validCandidateResponse(req, failure, time.Now()) {
		t.Fatal("failure response carried a candidate")
	}

	if validCandidateResponse(Request{Version: Version, Operation: OpPing}, valid, time.Now()) {
		t.Fatal("unsolicited candidate accepted")
	}
}
