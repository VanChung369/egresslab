package helperipc

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/VanChung369/egresslab/services/network-agent/internal/helperauth"
)

const (
	testLeaseAuthority   = "authority_0123456789abcdef0123456789abcdef"
	testLeaseReservation = "reservation_0123456789abcdef0123456789abcdef"
)

// newPreparedLeaseFixture runs the signed V2 probe and candidate reservation (Step 31A fixture) and
// mints the preparation that candidate backs.
func newPreparedLeaseFixture(t *testing.T) (*tunnelFixture, *fakeGenerationProbeBackend, Request) {
	t.Helper()

	f, backend, req := newVerifiedCandidateFixture(t)

	candidate, err := runCandidateRequest(f, req)
	if err != nil {
		t.Fatal(err)
	}

	intent, err := prepareLeaseIntent(candidate, testLeaseAuthority, testLeaseReservation)
	if err != nil {
		t.Fatal(err)
	}

	return f, backend, f.mint(intent)
}

func runPrepareLease(f *tunnelFixture, req Request) (PreparedLeaseInfo, error) {
	return f.labs.prepareEgressLease(context.Background(), req, f.verifier, multiProbeTestRuntimeID)
}

func TestPreparedLeaseConsumesCandidateOnce(t *testing.T) {
	f, backend, req := newPreparedLeaseFixture(t)
	original := f.labs.localCandidate
	before := backend.verifies

	result, err := runPrepareLease(f, req)
	if err != nil {
		t.Fatal(err)
	}

	if !result.matchesCapability(req.Intent, req.Capability) ||
		result.AuthorityID != testLeaseAuthority ||
		result.ReservationID != testLeaseReservation ||
		result.CandidateInfo != original.info ||
		!result.ExpiresAt.Equal(original.evidence.expiresAt) {
		t.Fatalf("invalid prepared lease: %+v", result)
	}

	prepared := f.labs.preparedLease
	if f.labs.localCandidate != nil || f.labs.verifiedEvidence != nil || prepared == nil || !prepared.fresh(time.Now()) {
		t.Fatal("invalid consumption state")
	}

	if !prepared.evidence.expiresAt.Equal(original.evidence.expiresAt) {
		t.Fatal("preparation extended the evidence deadline")
	}

	if backend.verifies != before+1 || backend.calls != 1 || backend.cleanups != 0 ||
		f.labs.labs.peek(f.lab.ProfileID).State != LabTunnelConfigured {
		t.Fatal("preparation probed again or changed the tunnel")
	}

	if _, err := runPrepareLease(f, req); labCode(err) != CodeLabBusy {
		t.Fatalf("duplicate preparation: %v", err)
	}

	if _, err := runPrepareLease(f, f.mint(*req.Intent)); labCode(err) != CodeLabBusy {
		t.Fatalf("candidate reused: %v", err)
	}

	if f.labs.preparedLease != prepared {
		t.Fatal("existing prepared lease overwritten")
	}

	if prepared.fresh(original.evidence.expiresAt) {
		t.Fatal("expired lease still fresh")
	}
}

func TestPreparedLeaseRefusalPreservesCandidate(t *testing.T) {
	f, backend, req := newPreparedLeaseFixture(t)
	original := f.labs.localCandidate
	before := backend.verifies

	for name, mutate := range map[string]func(*helperauth.Intent){
		"foreign runtime":      func(i *helperauth.Intent) { i.RuntimeID = "runtime_ffffffffffffffffffffffffffffffff" },
		"foreign generation":   func(i *helperauth.Intent) { i.TunnelGeneration = ipcGenerationB },
		"foreign evidence":     func(i *helperauth.Intent) { i.EvidenceNonce = "ffffffffffffffffffffffffffffffff" },
		"foreign candidate":    func(i *helperauth.Intent) { i.ReservationNonce = "ffffffffffffffffffffffffffffffff" },
		"different egress":     func(i *helperauth.Intent) { i.EgressIPv4 = "8.8.8.8" },
		"different source pin": func(i *helperauth.Intent) { i.ProbeIPv4 = "8.8.8.8" },
	} {
		t.Run(name, func(t *testing.T) {
			bad := *req.Intent
			mutate(&bad)

			// Correctly signed, but naming evidence the helper does not hold.
			if _, err := runPrepareLease(f, f.mint(bad)); labCode(err) != CodeAuthorizationDenied {
				t.Fatalf("incorrect binding accepted: %v", err)
			}

			if f.labs.localCandidate != original || f.labs.preparedLease != nil || backend.verifies != before {
				t.Fatal("a refusal consumed the candidate")
			}
		})
	}

	// The helper cannot know which authority IDs exist; a changed one breaks the signature.
	intent := *req.Intent
	intent.AuthorityID = "authority_ffffffffffffffffffffffffffffffff"

	capability := *req.Capability
	capability.Claims.Intent = intent

	tampered := req
	tampered.Intent, tampered.Capability = &intent, &capability

	if _, err := runPrepareLease(f, tampered); labCode(err) != CodeAuthorizationDenied {
		t.Fatalf("tampered authority accepted: %v", err)
	}

	if f.labs.localCandidate != original {
		t.Fatal("an invalid signature consumed the candidate")
	}

	// The helper's policy is no longer the one the candidate was made under.
	if _, err := f.labs.prepareEgressLease(context.Background(), req, f.verifier,
		"runtime_ffffffffffffffffffffffffffffffff"); labCode(err) != CodeStateUncertain || f.labs.localCandidate != original {
		t.Fatalf("changed policy accepted: %v", err)
	}

	if _, err := runPrepareLease(f, req); err != nil {
		t.Fatal("valid candidate no longer usable:", err)
	}
}

func TestPreparedLeaseRejectsExpiredCandidate(t *testing.T) {
	f, backend, req := newPreparedLeaseFixture(t)
	f.labs.localCandidate.evidence.expiresAt = time.Now().Add(-time.Second)
	before := backend.verifies

	result, err := runPrepareLease(f, req)
	if labCode(err) != CodeEvidenceUnavailable || result.IPv4.IsValid() || f.labs.preparedLease != nil ||
		backend.verifies != before {
		t.Fatalf("expired candidate prepared: %+v %v", result, err)
	}

	// Refused before the capability was accepted.
	if err := f.verifier.VerifyAndConsume(*req.Capability, *req.Intent); err != nil {
		t.Fatal("expired candidate consumed the capability:", err)
	}
}

func TestPreparedLeaseConcurrentConsumption(t *testing.T) {
	f, backend, first := newPreparedLeaseFixture(t)
	second := f.mint(*first.Intent)
	before := backend.verifies

	start := make(chan struct{})
	results := make(chan error, 2)

	var wg sync.WaitGroup
	for _, req := range []Request{first, second} {
		wg.Add(1)

		go func() {
			defer wg.Done()
			<-start

			_, err := runPrepareLease(f, req)
			results <- err
		}()
	}

	close(start)
	wg.Wait()
	close(results)

	granted, refused := 0, 0
	for err := range results {
		switch {
		case err == nil:
			granted++
		case labCode(err) == CodeLabBusy:
			refused++
		default:
			t.Fatalf("unexpected concurrent refusal: %v", err)
		}
	}

	if granted != 1 || refused != 1 || f.labs.localCandidate != nil || f.labs.preparedLease == nil ||
		backend.verifies != before+1 {
		t.Fatalf("atomic preparation violated: granted=%d refused=%d", granted, refused)
	}
}

func TestPreparedLeaseVerificationFailure(t *testing.T) {
	for _, uncertain := range []bool{false, true} {
		name := "confirmed cleanup"
		if uncertain {
			name = "uncertain cleanup"
		}

		t.Run(name, func(t *testing.T) {
			f, backend, req := newPreparedLeaseFixture(t)
			backend.verifyErr = errors.New("kernel drift")

			expected := CodeLabFaulted
			if uncertain {
				backend.cleanupErr = errors.New("cleanup failed")
				expected = CodeStateUncertain
			}

			result, err := runPrepareLease(f, req)
			if labCode(err) != expected || result.IPv4.IsValid() || f.labs.localCandidate != nil ||
				f.labs.preparedLease != nil || f.labs.verifiedEvidence != nil {
				t.Fatalf("failed preparation published a lease: %v", err)
			}

			if backend.cleanups != 1 || f.labs.labs.peek(f.lab.ProfileID).State != LabFaulted {
				t.Fatal("incorrect rollback state")
			}

			if uncertain && f.labs.tunnelProfile != f.lab.ProfileID {
				t.Fatal("uncertain ownership forgotten")
			}

			if !uncertain && f.labs.tunnelProfile != "" {
				t.Fatal("confirmed cleanup kept the tunnel slot")
			}
		})
	}
}

func TestPreparedLeaseGenerationChange(t *testing.T) {
	f, backend, req := newPreparedLeaseFixture(t)

	changing := &generationChangingBackend{backend}
	f.labs.tunnels, f.labs.multiProbes, f.labs.generationProbes = changing, changing, changing

	if _, err := runPrepareLease(f, req); labCode(err) != CodeStateUncertain {
		t.Fatalf("generation change accepted: %v", err)
	}

	if f.labs.preparedLease != nil || f.labs.localCandidate != nil || backend.cleanups != 1 ||
		f.labs.labs.peek(f.lab.ProfileID).State != LabFaulted {
		t.Fatal("invalid state after the generation change")
	}
}

// Neither a new probe nor a new candidate replaces a prepared lease, fresh or expired.
func TestPreparedLeaseBlocksNewProbe(t *testing.T) {
	f, backend, req := newPreparedLeaseFixture(t)

	candidateIntent := *req.Intent

	if _, err := runPrepareLease(f, req); err != nil {
		t.Fatal(err)
	}

	prepared := f.labs.preparedLease

	reserve, err := helperauth.NewReserveEgressCandidateIntent(candidateIntent.ProfileID, candidateIntent.Namespace,
		candidateIntent.ProbeIPv4, candidateIntent.TunnelGeneration, candidateIntent.EvidenceNonce)
	if err != nil {
		t.Fatal(err)
	}

	for _, expired := range []bool{false, true} {
		if expired {
			prepared.evidence.expiresAt = time.Now().Add(-time.Second)
		}

		probe := f.mint(generationProbeIntent(t, f.lab, backend.pin.String(), backend.generation))
		if _, err := f.labs.executeMultiProbe(context.Background(), probe, f.verifier); labCode(err) != CodeLabBusy {
			t.Fatalf("new probe replaced the prepared lease: %v", err)
		}

		if _, err := runCandidateRequest(f, f.mint(reserve)); labCode(err) != CodeLabBusy {
			t.Fatalf("new candidate beside the prepared lease: %v", err)
		}

		if f.labs.preparedLease != prepared || f.labs.verifiedEvidence != nil || f.labs.localCandidate != nil ||
			backend.calls != 1 {
			t.Fatal("prepared lease state changed")
		}
	}
}

func TestPreparedLeaseLifecycleInvalidation(t *testing.T) {
	for _, mode := range []string{"disconnect", "delete", "kernel drift", "shutdown"} {
		t.Run(mode, func(t *testing.T) {
			f, backend, req := newPreparedLeaseFixture(t)

			if _, err := runPrepareLease(f, req); err != nil {
				t.Fatal(err)
			}

			var err error

			switch mode {
			case "disconnect":
				_, err = f.execute(labRequest(OpDisconnect, f.lab))
			case "delete":
				_, err = f.execute(labRequest(OpDeleteLab, f.lab))
			case "kernel drift":
				backend.verifyErr = errors.New("kernel drift")
				_, err = f.execute(labRequest(OpVerifyLab, f.lab))
			case "shutdown":
				err = f.labs.Close()
			}

			if (err != nil) != (mode == "kernel drift") {
				t.Fatalf("unexpected lifecycle result: %v", err)
			}

			if f.labs.preparedLease != nil || f.labs.localCandidate != nil || f.labs.verifiedEvidence != nil {
				t.Fatal("local authorization state retained")
			}
		})
	}
}

// An old, never-used preparation capability, still inside its 30 s lifetime, cannot bind the next
// generation's candidate.
func TestPreparedLeaseRejectsPreviousGeneration(t *testing.T) {
	f, backend, old := newPreparedLeaseFixture(t)

	if _, err := f.execute(labRequest(OpDisconnect, f.lab)); err != nil {
		t.Fatal(err)
	}

	if _, err := f.execute(f.connectRequest()); err != nil {
		t.Fatal(err)
	}

	next := f.mint(generationProbeIntent(t, f.lab, backend.pin.String(), ipcGenerationB))
	if _, err := f.labs.executeMultiProbe(context.Background(), next, f.verifier); err != nil {
		t.Fatal(err)
	}

	candidateIntent, err := candidateIntentFromEvidence(f.labs.verifiedEvidence)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := runCandidateRequest(f, f.mint(candidateIntent)); err != nil {
		t.Fatal(err)
	}

	current := f.labs.localCandidate

	if _, err := runPrepareLease(f, old); labCode(err) != CodeAuthorizationDenied {
		t.Fatalf("old generation prepared: %v", err)
	}

	if f.labs.localCandidate != current || f.labs.preparedLease != nil {
		t.Fatal("stale authorization modified the new generation")
	}
}

func TestPreparedLeaseResponseValidation(t *testing.T) {
	f, _, req := newPreparedLeaseFixture(t)

	info, err := runPrepareLease(f, req)
	if err != nil {
		t.Fatal(err)
	}

	valid := Response{Version: Version, Operation: req.Operation, OK: true, PreparedLease: &info}
	if !validPreparedLeaseResponse(req, valid, time.Now()) {
		t.Fatal("valid receipt refused")
	}

	for name, mutate := range map[string]func(*PreparedLeaseInfo){
		"wrong authority":         func(p *PreparedLeaseInfo) { p.AuthorityID = "authority_ffffffffffffffffffffffffffffffff" },
		"wrong reservation":       func(p *PreparedLeaseInfo) { p.ReservationID = "reservation_ffffffffffffffffffffffffffffffff" },
		"wrong preparation nonce": func(p *PreparedLeaseInfo) { p.PreparationNonce = "ffffffffffffffffffffffffffffffff" },
		"wrong generation":        func(p *PreparedLeaseInfo) { p.TunnelGeneration = ipcGenerationB },
		"duplicate nonce":         func(p *PreparedLeaseInfo) { p.PreparationNonce = p.ReservationNonce },
		"extended TTL":            func(p *PreparedLeaseInfo) { p.ExpiresAt = p.ObservedAt.Add(61 * time.Second) },
	} {
		t.Run(name, func(t *testing.T) {
			bad := info
			mutate(&bad)

			resp := valid
			resp.PreparedLease = &bad

			if validPreparedLeaseResponse(req, resp, time.Now()) {
				t.Fatal("invalid receipt accepted")
			}
		})
	}

	if validPreparedLeaseResponse(req, valid, info.ExpiresAt) {
		t.Fatal("expired receipt accepted")
	}

	failure := valid
	failure.OK = false
	if validPreparedLeaseResponse(req, failure, time.Now()) {
		t.Fatal("a failure response carried a lease")
	}

	ready := valid
	ready.NetworkReady = true
	if validPreparedLeaseResponse(req, ready, time.Now()) {
		t.Fatal("a prepared lease reported networking ready")
	}

	if validPreparedLeaseResponse(Request{Version: Version, Operation: OpPing}, valid, time.Now()) {
		t.Fatal("unsolicited prepared lease accepted")
	}

	// An older helper's bare refusal may carry no lease either.
	legacy := Response{Version: Version, Code: CodeOperationDisabled, PreparedLease: &info}
	if olderHelperDisabled(Request{Version: Version, Operation: helperauth.OpPermitMultiProbe}, legacy) {
		t.Fatal("legacy refusal with a prepared lease accepted")
	}

	if operationResponseTimeout(helperauth.OpPrepareEgressLease) != lifecycleResponseTimeout {
		t.Fatal("preparation uses the short IPC timeout")
	}
}

// Every earlier operation's IPC validator refuses each lease field, before any capability check.
func TestPreparedLeaseFieldsRefusedElsewhere(t *testing.T) {
	const (
		profile   = "profile_0123456789abcdef"
		namespace = "egresslab-lab-0123456789abcdef"
		stage     = "wgstage_0123456789abcdef0123456789abcdef"
	)

	v1, err := helperauth.NewMultiProbeIntent(profile, namespace, "9.9.9.9")
	if err != nil {
		t.Fatal(err)
	}

	v2, err := helperauth.NewGenerationProbeIntent(profile, namespace, "9.9.9.9", ipcGenerationA)
	if err != nil {
		t.Fatal(err)
	}

	candidate, err := helperauth.NewReserveEgressCandidateIntent(profile, namespace, "9.9.9.9", ipcGenerationA,
		"ffeeddccbbaa99887766554433221100")
	if err != nil {
		t.Fatal(err)
	}

	lifecycle := func(op string) func(*helperauth.Intent) bool {
		return func(in *helperauth.Intent) bool { return validLifecycleIntent(op, in) }
	}

	cases := map[string]struct {
		intent helperauth.Intent
		valid  func(*helperauth.Intent) bool
	}{
		"CreateLab":     {helperauth.Intent{Operation: helperauth.OpCreateLab, ProfileID: profile}, lifecycle(helperauth.OpCreateLab)},
		"ConnectTunnel": {helperauth.Intent{Operation: helperauth.OpConnectTunnel, ProfileID: profile, Namespace: namespace, StageID: stage}, lifecycle(helperauth.OpConnectTunnel)},
		"VerifyLab":     {helperauth.Intent{Operation: OpVerifyLab, ProfileID: profile, Namespace: namespace}, lifecycle(OpVerifyLab)},
		"DeleteLab":     {helperauth.Intent{Operation: OpDeleteLab, ProfileID: profile, Namespace: namespace}, lifecycle(OpDeleteLab)},
		"Disconnect":    {helperauth.Intent{Operation: OpDisconnect, ProfileID: profile, Namespace: namespace}, lifecycle(OpDisconnect)},
		"PermitProbe":   {helperauth.Intent{Operation: helperauth.OpPermitProbe, ProfileID: profile, Namespace: namespace, ProbeIPv4: ProbeDestinationIPv4}, validProbeIntent},
		"StageInfo":     {helperauth.Intent{Operation: OpStageInfo, ProfileID: profile}, validStageIntent},
		"MultiProbeV1":  {v1, validMultiProbeIntent},
		"MultiProbeV2":  {v2, validMultiProbeIntent},
		"Target":        {helperauth.Intent{Operation: OpMultiProbeTarget, ProfileID: profile, Namespace: namespace}, validMultiProbeTargetIntent},
		"Candidate":     {candidate, validCandidateIntent},
	}

	fields := map[string]func(*helperauth.Intent){
		"reservation nonce": func(i *helperauth.Intent) { i.ReservationNonce = "aabbccddeeff00112233445566778899" },
		"runtime":           func(i *helperauth.Intent) { i.RuntimeID = multiProbeTestRuntimeID },
		"authority":         func(i *helperauth.Intent) { i.AuthorityID = testLeaseAuthority },
		"reservation":       func(i *helperauth.Intent) { i.ReservationID = testLeaseReservation },
		"egress":            func(i *helperauth.Intent) { i.EgressIPv4 = "8.8.4.4" },
	}

	for name, tc := range cases {
		base := tc.intent
		if !tc.valid(&base) {
			t.Fatalf("%s: base intent refused", name)
		}

		for field, set := range fields {
			bad := tc.intent
			set(&bad)

			if tc.valid(&bad) {
				t.Errorf("%s accepted the lease %s field", name, field)
			}
		}
	}
}
