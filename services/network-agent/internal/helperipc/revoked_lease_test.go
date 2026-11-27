package helperipc

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/VanChung369/egresslab/services/network-agent/internal/helperauth"
)

func revokeRequest(t *testing.T, f *tunnelFixture, preparation Request) Request {
	t.Helper()

	intent, err := helperauth.NewRevokeEgressLeaseIntent(*preparation.Intent)
	if err != nil {
		t.Fatal(err)
	}

	return f.mint(intent)
}

func runRevokeLease(f *tunnelFixture, req Request) (RevokedLeaseInfo, error) {
	return f.labs.revokeEgressLease(context.Background(), req, f.verifier, multiProbeTestRuntimeID)
}

// unreadableGenerationBackend reports no generation, like the agent for a faulted or removed tunnel.
type unreadableGenerationBackend struct {
	*fakeGenerationProbeBackend

	unreadable bool
}

func (b *unreadableGenerationBackend) CurrentTunnelGeneration(namespace string) (string, error) {
	if b.unreadable {
		return "", errors.New("managed tunnel faulted")
	}

	return b.fakeGenerationProbeBackend.CurrentTunnelGeneration(namespace)
}

func TestRevokePreparedLease(t *testing.T) {
	f, backend, preparation := newPreparedLeaseFixture(t)

	if _, err := runPrepareLease(f, preparation); err != nil {
		t.Fatal(err)
	}

	req := revokeRequest(t, f, preparation)

	result, err := runRevokeLease(f, req)
	if err != nil || !result.matchesCapability(req.Intent, req.Capability) || !result.GenerationRetired {
		t.Fatalf("revocation failed: %+v %v", result, err)
	}

	record := f.labs.candidateRetirements[req.Intent.ReservationNonce]
	if record == nil || !record.retired || record.authorityID != testLeaseAuthority ||
		record.reservationID != testLeaseReservation || record.preparationNonce != preparation.Capability.Claims.Nonce ||
		f.labs.preparedLease != nil || f.labs.localCandidate != nil || f.labs.verifiedEvidence != nil ||
		f.labs.candidateGeneration != "" || f.labs.tunnelProfile != "" || backend.generation != "" || backend.cleanups != 1 {
		t.Fatal("generation was not retired")
	}

	if f.labs.labs.peek(f.lab.ProfileID).State != LabSealed {
		t.Fatal("revoked lab was not sealed")
	}
}

func TestRevokeUnpreparedCandidate(t *testing.T) {
	f, backend, preparation := newPreparedLeaseFixture(t)
	req := revokeRequest(t, f, preparation)

	result, err := runRevokeLease(f, req)
	if err != nil || !result.GenerationRetired {
		t.Fatalf("candidate revocation failed: %v", err)
	}

	// The preparation capability was never used and is still within its TTL.
	if _, err := runPrepareLease(f, preparation); err == nil {
		t.Fatal("late preparation resurrected a retired lease")
	}

	if f.labs.preparedLease != nil || f.labs.localCandidate != nil || backend.cleanups != 1 {
		t.Fatal("retired authorization was restored")
	}

	if record := f.labs.candidateRetirements[req.Intent.ReservationNonce]; record.authorityID != testLeaseAuthority ||
		record.reservationID != testLeaseReservation || record.preparationNonce != "" {
		t.Fatal("the revocation did not bind the record")
	}
}

func TestRevokeExpiredPreparedLease(t *testing.T) {
	f, _, preparation := newPreparedLeaseFixture(t)

	if _, err := runPrepareLease(f, preparation); err != nil {
		t.Fatal(err)
	}

	f.labs.preparedLease.evidence.expiresAt = time.Now().Add(-time.Second)

	if result, err := runRevokeLease(f, revokeRequest(t, f, preparation)); err != nil || !result.GenerationRetired {
		t.Fatalf("expired lease could not be revoked: %v", err)
	}
}

func TestRevokeLeaseRejectsWrongBinding(t *testing.T) {
	f, backend, preparation := newPreparedLeaseFixture(t)

	if _, err := runPrepareLease(f, preparation); err != nil {
		t.Fatal(err)
	}

	valid := revokeRequest(t, f, preparation)

	for name, mutate := range map[string]func(*helperauth.Intent){
		"other authority":   func(i *helperauth.Intent) { i.AuthorityID = "authority_ffffffffffffffffffffffffffffffff" },
		"other reservation": func(i *helperauth.Intent) { i.ReservationID = "reservation_ffffffffffffffffffffffffffffffff" },
		"other generation":  func(i *helperauth.Intent) { i.TunnelGeneration = ipcGenerationB },
		"other evidence":    func(i *helperauth.Intent) { i.EvidenceNonce = "ffffffffffffffffffffffffffffffff" },
		"other candidate":   func(i *helperauth.Intent) { i.ReservationNonce = "ffffffffffffffffffffffffffffffff" },
		"other IP":          func(i *helperauth.Intent) { i.EgressIPv4 = "8.8.8.8" },
		"other runtime":     func(i *helperauth.Intent) { i.RuntimeID = "runtime_ffffffffffffffffffffffffffffffff" },
	} {
		t.Run(name, func(t *testing.T) {
			bad := *valid.Intent
			mutate(&bad)

			if _, err := runRevokeLease(f, f.mint(bad)); labCode(err) != CodeAuthorizationDenied {
				t.Fatalf("wrong binding accepted: %v", err)
			}

			if backend.cleanups != 0 || f.labs.preparedLease == nil {
				t.Fatal("an incorrect request modified the tunnel")
			}
		})
	}

	unsigned := valid
	unsigned.Capability = nil

	if _, err := runRevokeLease(f, unsigned); labCode(err) != CodeAuthorizationDenied {
		t.Fatalf("unsigned revocation accepted: %v", err)
	}

	// The capability names the intent; a request carrying another one is refused.
	swapped := valid
	other := *valid.Intent
	other.ReservationID = "reservation_ffffffffffffffffffffffffffffffff"
	swapped.Intent = &other

	if _, err := runRevokeLease(f, swapped); labCode(err) != CodeAuthorizationDenied {
		t.Fatalf("mismatched capability accepted: %v", err)
	}

	if _, err := runRevokeLease(f, preparation); labCode(err) != CodeInvalidRequest {
		t.Fatalf("preparation accepted as revocation: %v", err)
	}

	if _, err := runRevokeLease(f, valid); err != nil {
		t.Fatal(err)
	}
}

// A helper restart loses the records; a missing record is never retirement.
func TestRevokeWithoutRecord(t *testing.T) {
	f, backend, preparation := newPreparedLeaseFixture(t)
	req := revokeRequest(t, f, preparation)
	f.labs.candidateRetirements = nil

	if _, err := runRevokeLease(f, req); labCode(err) != CodeAuthorizationDenied || backend.cleanups != 0 ||
		f.labs.tunnelProfile == "" {
		t.Fatalf("revocation without a record: %v", err)
	}
}

func TestRevokeLeaseCleanupFailure(t *testing.T) {
	f, backend, preparation := newPreparedLeaseFixture(t)

	if _, err := runPrepareLease(f, preparation); err != nil {
		t.Fatal(err)
	}

	req := revokeRequest(t, f, preparation)
	backend.cleanupErr = errors.New("synthetic cleanup failure")

	result, err := runRevokeLease(f, req)
	record := f.labs.candidateRetirements[req.Intent.ReservationNonce]

	if labCode(err) != CodeStateUncertain || result.GenerationRetired || record == nil || record.retired {
		t.Fatal("a failed cleanup produced retirement proof")
	}

	if f.labs.preparedLease != nil || f.labs.tunnelProfile != f.lab.ProfileID || f.labs.candidateGeneration == "" ||
		f.labs.labs.peek(f.lab.ProfileID).State != LabFaulted {
		t.Fatal("uncertain tunnel ownership was forgotten")
	}

	// A connect cannot take the slot while the candidate-bearing generation is in it.
	if _, err := f.execute(f.connectRequest()); err == nil {
		t.Fatal("connect over an unretired generation")
	}

	backend.cleanupErr = nil

	// A separately signed attempt, as an operator would approve it; nothing retries by itself.
	result, err = runRevokeLease(f, f.mint(*req.Intent))
	if err != nil || !result.GenerationRetired || !record.retired || backend.cleanups != 2 {
		t.Fatalf("confirmed cleanup was not recorded: %v", err)
	}
}

// The agent cannot read the generation of a faulted tunnel; the confirmed cleanup is the proof.
func TestRevokeFaultedLabWithUnreadableGeneration(t *testing.T) {
	f, backend, preparation := newPreparedLeaseFixture(t)
	unreadable := &unreadableGenerationBackend{fakeGenerationProbeBackend: backend}
	f.labs.tunnels, f.labs.multiProbes, f.labs.generationProbes = unreadable, unreadable, unreadable

	if _, err := runPrepareLease(f, preparation); err != nil {
		t.Fatal(err)
	}

	req := revokeRequest(t, f, preparation)

	// A configured tunnel without a readable generation is uncertain, before the nonce is consumed.
	unreadable.unreadable = true

	if _, err := runRevokeLease(f, req); labCode(err) != CodeStateUncertain || backend.cleanups != 0 ||
		f.labs.preparedLease == nil {
		t.Fatalf("unreadable configured generation: %v", err)
	}

	unreadable.unreadable = false
	backend.cleanupErr = errors.New("synthetic cleanup failure")

	if _, err := f.execute(labRequest(OpDisconnect, f.lab)); labCode(err) != CodeStateUncertain {
		t.Fatalf("failed disconnect: %v", err)
	}

	unreadable.unreadable = true
	backend.cleanupErr = nil

	result, err := runRevokeLease(f, req)
	if err != nil || !result.GenerationRetired || backend.cleanups != 2 ||
		!f.labs.candidateRetirements[req.Intent.ReservationNonce].retired {
		t.Fatalf("faulted generation not retired: %v", err)
	}
}

func TestRevokeAfterPreparationFailure(t *testing.T) {
	f, backend, preparation := newPreparedLeaseFixture(t)
	backend.verifyErr = errors.New("synthetic kernel drift")

	if _, err := runPrepareLease(f, preparation); err == nil {
		t.Fatal("preparation should have failed")
	}

	record := f.labs.candidateRetirements[preparation.Intent.ReservationNonce]
	if record == nil || !record.retired || f.labs.preparedLease != nil ||
		record.preparationNonce != preparation.Capability.Claims.Nonce || record.reservationID != testLeaseReservation {
		t.Fatal("the confirmed rollback or the binding was not recorded")
	}

	before := backend.cleanups

	result, err := runRevokeLease(f, revokeRequest(t, f, preparation))
	if err != nil || !result.GenerationRetired || backend.cleanups != before {
		t.Fatal("previously confirmed cleanup was lost")
	}
}

func TestRevokeLeaseRepeatedConfirmation(t *testing.T) {
	f, backend, preparation := newPreparedLeaseFixture(t)
	first := revokeRequest(t, f, preparation)

	result, err := runRevokeLease(f, first)
	if err != nil || !result.GenerationRetired {
		t.Fatal(err)
	}

	before := backend.cleanups

	if _, err := runRevokeLease(f, first); labCode(err) != CodeAuthorizationDenied {
		t.Fatalf("revocation replay accepted: %v", err)
	}

	confirmed, err := runRevokeLease(f, f.mint(*first.Intent))
	if err != nil || !confirmed.GenerationRetired || confirmed.RevocationNonce == result.RevocationNonce ||
		backend.cleanups != before {
		t.Fatal("retirement confirmation was not idempotent")
	}

	// A record bound by its first revocation never moves to another reservation.
	other := *first.Intent
	other.ReservationID = "reservation_ffffffffffffffffffffffffffffffff"

	if _, err := runRevokeLease(f, f.mint(other)); labCode(err) != CodeAuthorizationDenied {
		t.Fatalf("a retired record moved to another reservation: %v", err)
	}
}

// Required before durable release: a late revocation of generation A never touches generation B.
func TestRevokeLeasePreservesNewGeneration(t *testing.T) {
	f, backend, oldPreparation := newPreparedLeaseFixture(t)
	old := revokeRequest(t, f, oldPreparation)

	if _, err := f.execute(labRequest(OpDisconnect, f.lab)); err != nil {
		t.Fatal(err)
	}

	if _, err := f.execute(f.connectRequest()); err != nil {
		t.Fatal(err)
	}

	if backend.generation != ipcGenerationB {
		t.Fatal("new generation missing")
	}

	probe := f.mint(generationProbeIntent(t, f.lab, backend.pin.String(), ipcGenerationB))
	if _, err := f.labs.executeMultiProbe(context.Background(), probe, f.verifier); err != nil {
		t.Fatal(err)
	}

	intent, err := candidateIntentFromEvidence(f.labs.verifiedEvidence)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := runCandidateRequest(f, f.mint(intent)); err != nil {
		t.Fatal(err)
	}

	current := f.labs.localCandidate
	before := backend.cleanups

	result, err := runRevokeLease(f, old)
	if err != nil || !result.GenerationRetired || result.Intent.TunnelGeneration != ipcGenerationA {
		t.Fatalf("old retirement unavailable: %v", err)
	}

	if backend.cleanups != before || backend.generation != ipcGenerationB || f.labs.localCandidate != current ||
		f.labs.candidateGeneration != ipcGenerationB || f.labs.tunnelProfile != f.lab.ProfileID {
		t.Fatal("old revocation modified the new generation")
	}
}

// Every candidate of a generation retires with it.
func TestRevokeSecondCandidateOfGeneration(t *testing.T) {
	f, backend, req := newVerifiedCandidateFixture(t)

	first, err := runCandidateRequest(f, req)
	if err != nil {
		t.Fatal(err)
	}

	probe := f.mint(generationProbeIntent(t, f.lab, backend.pin.String(), ipcGenerationA))
	if _, err := f.labs.executeMultiProbe(context.Background(), probe, f.verifier); err != nil {
		t.Fatal(err)
	}

	intent, err := candidateIntentFromEvidence(f.labs.verifiedEvidence)
	if err != nil {
		t.Fatal(err)
	}

	second, err := runCandidateRequest(f, f.mint(intent))
	if err != nil || len(f.labs.candidateRetirements) != 2 {
		t.Fatalf("second candidate: %v", err)
	}

	if _, err := f.execute(labRequest(OpDisconnect, f.lab)); err != nil {
		t.Fatal(err)
	}

	for _, c := range []CandidateInfo{first, second} {
		if !f.labs.candidateRetirements[c.ReservationNonce].retired {
			t.Fatal("a candidate of the removed generation was not retired")
		}
	}

	binding, err := prepareLeaseIntent(first, testLeaseAuthority, testLeaseReservation)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := runRevokeLease(f, revokeRequest(t, f, f.mint(binding))); err != nil || backend.cleanups != 1 {
		t.Fatalf("retired first candidate not confirmed: %v", err)
	}
}

// blockCreation stops new resources, not the removal of a tunnel by its owner.
func TestRevokeWhileCreationBlocked(t *testing.T) {
	f, _, preparation := newPreparedLeaseFixture(t)
	f.labs.blockCreation = true

	if result, err := runRevokeLease(f, revokeRequest(t, f, preparation)); err != nil || !result.GenerationRetired {
		t.Fatalf("revocation refused while creation is blocked: %v", err)
	}
}

func TestPreparationRevocationRace(t *testing.T) {
	f, _, preparation := newPreparedLeaseFixture(t)
	revoke := revokeRequest(t, f, preparation)

	var prepareErr, revokeErr error
	var wg sync.WaitGroup

	start := make(chan struct{})
	wg.Add(2)

	go func() {
		defer wg.Done()
		<-start

		_, prepareErr = runPrepareLease(f, preparation)
	}()

	go func() {
		defer wg.Done()
		<-start

		_, revokeErr = runRevokeLease(f, revoke)
	}()

	close(start)
	wg.Wait()

	record := f.labs.candidateRetirements[revoke.Intent.ReservationNonce]

	if revokeErr == nil {
		if !record.retired || f.labs.preparedLease != nil || f.labs.localCandidate != nil {
			t.Fatal("authorization survived a confirmed revocation")
		}

		return
	}

	if labCode(revokeErr) != CodeLabBusy {
		t.Fatalf("unexpected race outcome: prepare=%v revoke=%v", prepareErr, revokeErr)
	}

	if _, err := runRevokeLease(f, f.mint(*revoke.Intent)); err != nil {
		t.Fatal(err)
	}

	if !record.retired || f.labs.preparedLease != nil {
		t.Fatal("generation survived revocation")
	}
}

// Refused, never evicted: an old record may still back a durable hold.
func TestCandidateRetirementLimit(t *testing.T) {
	f, backend, req := newVerifiedCandidateFixture(t)
	f.labs.candidateRetirements = make(map[string]*candidateRetirementRecord)

	for i := 0; i < maxCandidateRetirements; i++ {
		f.labs.candidateRetirements[fmt.Sprintf("%032x", i)] = &candidateRetirementRecord{}
	}

	evidence := f.labs.verifiedEvidence
	before := backend.verifies

	if _, err := runCandidateRequest(f, req); labCode(err) != CodeLabLimit {
		t.Fatalf("retirement limit was bypassed: %v", err)
	}

	if len(f.labs.candidateRetirements) != maxCandidateRetirements || f.labs.verifiedEvidence != evidence ||
		backend.verifies != before {
		t.Fatal("capacity refusal evicted records or consumed evidence")
	}

	delete(f.labs.candidateRetirements, fmt.Sprintf("%032x", 0))

	if _, err := runCandidateRequest(f, req); err != nil || len(f.labs.candidateRetirements) != maxCandidateRetirements {
		t.Fatalf("last free record refused: %v", err)
	}
}

func TestRevocationRejectsGenerationDrift(t *testing.T) {
	f, backend, preparation := newPreparedLeaseFixture(t)
	changing := &generationChangingBackend{backend}
	f.labs.tunnels, f.labs.multiProbes, f.labs.generationProbes = changing, changing, changing

	if _, err := runPrepareLease(f, preparation); labCode(err) != CodeStateUncertain {
		t.Fatalf("unexpected preparation result: %v", err)
	}

	record := f.labs.candidateRetirements[preparation.Intent.ReservationNonce]
	if record == nil || record.retired {
		t.Fatal("contradictory generation produced retirement proof")
	}

	if receipt, err := runRevokeLease(f, revokeRequest(t, f, preparation)); err == nil || receipt.GenerationRetired {
		t.Fatal("uncertain generation was confirmed retired")
	}
}

// A backend that names another generation fails DeleteLab after a successful cleanup: the slot is
// free, no proof is given, and a second DeleteLab removes the namespace.
func TestDeleteLabWithContradictoryGeneration(t *testing.T) {
	f, backend, req := newVerifiedCandidateFixture(t)

	candidate, err := runCandidateRequest(f, req)
	if err != nil {
		t.Fatal(err)
	}

	backend.generation = ipcGenerationB

	if _, err := f.execute(labRequest(OpDeleteLab, f.lab)); labCode(err) != CodeStateUncertain {
		t.Fatalf("contradictory generation accepted: %v", err)
	}

	record := f.labs.candidateRetirements[candidate.ReservationNonce]
	if record.retired || f.labs.tunnelProfile != "" || f.labs.candidateGeneration != "" || backend.cleanups != 1 ||
		f.labs.labs.peek(f.lab.ProfileID).State != LabFaulted {
		t.Fatal("contradictory cleanup recorded as retirement or kept the slot")
	}

	if lab, err := f.execute(labRequest(OpDeleteLab, f.lab)); err != nil || lab.State != LabDeleted {
		t.Fatalf("second DeleteLab: %v", err)
	}

	binding, err := prepareLeaseIntent(candidate, testLeaseAuthority, testLeaseReservation)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := runRevokeLease(f, revokeRequest(t, f, f.mint(binding))); labCode(err) != CodeStateUncertain {
		t.Fatalf("unretired generation of a deleted lab confirmed: %v", err)
	}
}

func TestRevocationInconsistentGeneration(t *testing.T) {
	f, backend, preparation := newPreparedLeaseFixture(t)
	req := revokeRequest(t, f, preparation)
	backend.generation = ipcGenerationB

	if _, err := runRevokeLease(f, req); labCode(err) != CodeStateUncertain || backend.cleanups != 0 {
		t.Fatalf("revocation with a contradictory backend: %v", err)
	}

	// The backend naming A again does not erase the contradiction.
	backend.generation = ipcGenerationA

	if _, err := runRevokeLease(f, req); labCode(err) != CodeStateUncertain || backend.cleanups != 0 {
		t.Fatalf("a remembered contradiction was forgotten: %v", err)
	}

	f.labs.candidateGenerationContradicted = false

	if _, err := runRevokeLease(f, req); err != nil {
		t.Fatalf("refusal consumed the capability: %v", err)
	}
}

// A contradiction seen by a failed cleanup survives into the retry, when the faulted tunnel no
// longer names any generation.
func TestContradictionSurvivesCleanupRetry(t *testing.T) {
	f, backend, req := newVerifiedCandidateFixture(t)
	unreadable := &unreadableGenerationBackend{fakeGenerationProbeBackend: backend}
	f.labs.tunnels, f.labs.multiProbes, f.labs.generationProbes = unreadable, unreadable, unreadable

	candidate, err := runCandidateRequest(f, req)
	if err != nil {
		t.Fatal(err)
	}

	backend.generation = ipcGenerationB
	backend.cleanupErr = errors.New("synthetic cleanup failure")

	if _, err := f.execute(labRequest(OpDisconnect, f.lab)); labCode(err) != CodeStateUncertain ||
		f.labs.tunnelProfile != f.lab.ProfileID {
		t.Fatalf("failed cleanup: %v", err)
	}

	unreadable.unreadable = true
	backend.cleanupErr = nil

	if _, err := f.execute(labRequest(OpDisconnect, f.lab)); labCode(err) != CodeStateUncertain {
		t.Fatalf("retried cleanup gave proof: %v", err)
	}

	if f.labs.candidateRetirements[candidate.ReservationNonce].retired || f.labs.tunnelProfile != "" ||
		f.labs.candidateGenerationContradicted || backend.cleanups != 2 {
		t.Fatal("a known contradiction became retirement proof")
	}

	binding, err := prepareLeaseIntent(candidate, testLeaseAuthority, testLeaseReservation)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := runRevokeLease(f, revokeRequest(t, f, f.mint(binding))); labCode(err) != CodeStateUncertain {
		t.Fatalf("contradicted generation confirmed: %v", err)
	}
}

func TestPreparationRequiresRetirementRecord(t *testing.T) {
	for name, mutate := range map[string]func(*candidateRetirementRecord){
		"retired": func(r *candidateRetirementRecord) { r.retired = true },
		"other reservation": func(r *candidateRetirementRecord) {
			r.bind(testLeaseAuthority, "reservation_ffffffffffffffffffffffffffffffff")
		},
		"other candidate": func(r *candidateRetirementRecord) { r.candidate.ExpiresAt = r.candidate.ExpiresAt.Add(-time.Second) },
	} {
		t.Run(name, func(t *testing.T) {
			f, backend, preparation := newPreparedLeaseFixture(t)
			mutate(f.labs.candidateRetirements[preparation.Intent.ReservationNonce])
			candidate := f.labs.localCandidate

			if _, err := runPrepareLease(f, preparation); labCode(err) != CodeStateUncertain ||
				f.labs.localCandidate != candidate || backend.cleanups != 0 {
				t.Fatalf("preparation without its record: %v", err)
			}
		})
	}
}

func TestRevokedLeaseResponseValidation(t *testing.T) {
	f, _, preparation := newPreparedLeaseFixture(t)
	req := revokeRequest(t, f, preparation)

	info, err := runRevokeLease(f, req)
	if err != nil {
		t.Fatal(err)
	}

	valid := Response{Version: Version, Operation: req.Operation, OK: true, RevokedLease: &info}
	if !validRevokedLeaseResponse(req, valid) {
		t.Fatal("valid receipt refused")
	}

	for name, mutate := range map[string]func(*RevokedLeaseInfo){
		"not retired":       func(r *RevokedLeaseInfo) { r.GenerationRetired = false },
		"wrong nonce":       func(r *RevokedLeaseInfo) { r.RevocationNonce = "ffffffffffffffffffffffffffffffff" },
		"evidence nonce":    func(r *RevokedLeaseInfo) { r.RevocationNonce = r.Intent.EvidenceNonce },
		"candidate nonce":   func(r *RevokedLeaseInfo) { r.RevocationNonce = r.Intent.ReservationNonce },
		"wrong helper":      func(r *RevokedLeaseInfo) { r.HelperID = "helper_ffffffffffffffffffffffffffffffff" },
		"invalid key":       func(r *RevokedLeaseInfo) { r.PublicKeySHA256 = "key" },
		"other reservation": func(r *RevokedLeaseInfo) { r.Intent.ReservationID = "reservation_ffffffffffffffffffffffffffffffff" },
		"preparation":       func(r *RevokedLeaseInfo) { r.Intent.Operation = helperauth.OpPrepareEgressLease },
	} {
		t.Run(name, func(t *testing.T) {
			bad := info
			mutate(&bad)

			resp := valid
			resp.RevokedLease = &bad

			if validRevokedLeaseResponse(req, resp) {
				t.Fatal("invalid receipt accepted")
			}
		})
	}

	for name, resp := range map[string]Response{
		"failure with receipt": {Version: Version, Operation: req.Operation, Code: CodeStateUncertain, RevokedLease: &info},
		"networking ready":     {Version: Version, Operation: req.Operation, OK: true, NetworkReady: true, RevokedLease: &info},
		"missing receipt":      {Version: Version, Operation: req.Operation, OK: true},
	} {
		if validRevokedLeaseResponse(req, resp) {
			t.Errorf("%s accepted", name)
		}
	}

	if validRevokedLeaseResponse(Request{Version: Version, Operation: OpPing}, valid) {
		t.Fatal("unsolicited receipt accepted")
	}

	legacy := Response{Version: Version, Code: CodeOperationDisabled, RevokedLease: &info}
	if olderHelperDisabled(Request{Version: Version, Operation: helperauth.OpPermitMultiProbe}, legacy) {
		t.Fatal("legacy refusal with a receipt accepted")
	}

	if operationResponseTimeout(helperauth.OpRevokeEgressLease) != lifecycleResponseTimeout {
		t.Fatal("revocation uses the short IPC timeout")
	}
}

func TestRevocationDisabledWithoutGenerations(t *testing.T) {
	f, backend, preparation := newPreparedLeaseFixture(t)
	req := revokeRequest(t, f, preparation)
	f.labs.generationProbes = nil

	if _, err := runRevokeLease(f, req); labCode(err) != CodeRuntimeUnavailable || backend.cleanups != 0 {
		t.Fatalf("revocation without the V2 lifecycle: %v", err)
	}
}

// Defensive checks against helper state that the lifecycle never produces on its own.
func TestRetirementStateGuards(t *testing.T) {
	t.Run("candidate on another generation", func(t *testing.T) {
		f, backend, req := newVerifiedCandidateFixture(t)
		f.labs.candidateGeneration = ipcGenerationB
		evidence := f.labs.verifiedEvidence
		before := backend.verifies

		if _, err := runCandidateRequest(f, req); labCode(err) != CodeStateUncertain || f.labs.verifiedEvidence != evidence ||
			backend.verifies != before {
			t.Fatalf("candidate tracked beside another generation: %v", err)
		}
	})

	t.Run("connect over a tracked generation", func(t *testing.T) {
		f, backend := newGenerationProbeFixture(t)

		if _, err := f.execute(labRequest(OpDisconnect, f.lab)); err != nil {
			t.Fatal(err)
		}

		f.labs.candidateGeneration = ipcGenerationA
		before := backend.connects
		connect := f.connectRequest()

		if _, err := f.execute(connect); labCode(err) != CodeStateUncertain || backend.connects != before {
			t.Fatalf("connect over a candidate-bearing generation: %v", err)
		}

		f.labs.candidateGeneration = ""

		if _, err := f.execute(connect); err != nil {
			t.Fatalf("the refusal consumed the capability: %v", err)
		}
	})

	t.Run("only the cleaned generation retires", func(t *testing.T) {
		f, _, req := newVerifiedCandidateFixture(t)

		candidate, err := runCandidateRequest(f, req)
		if err != nil {
			t.Fatal(err)
		}

		otherGeneration := candidate
		otherGeneration.TunnelGeneration = ipcGenerationB
		otherProfile := candidate
		otherProfile.ProfileID = "profile_ffffffffffffffff"

		f.labs.candidateRetirements["ffffffffffffffffffffffffffffff01"] = &candidateRetirementRecord{candidate: otherGeneration}
		f.labs.candidateRetirements["ffffffffffffffffffffffffffffff02"] = &candidateRetirementRecord{candidate: otherProfile}

		if _, err := f.execute(labRequest(OpDisconnect, f.lab)); err != nil {
			t.Fatal(err)
		}

		if !f.labs.candidateRetirements[candidate.ReservationNonce].retired ||
			f.labs.candidateRetirements["ffffffffffffffffffffffffffffff01"].retired ||
			f.labs.candidateRetirements["ffffffffffffffffffffffffffffff02"].retired {
			t.Fatal("a cleanup retired another generation or profile")
		}
	})
}

// Once the backend contradicted the tracked generation, nothing new is authorized on it, even when
// the backend names it again.
func TestContradictedGenerationGetsNoAuthorization(t *testing.T) {
	t.Run("preparation", func(t *testing.T) {
		f, backend, preparation := newPreparedLeaseFixture(t)
		backend.generation = ipcGenerationB

		if _, err := f.labs.currentGenerationLocked(f.lab.Namespace); err != nil || !f.labs.candidateGenerationContradicted {
			t.Fatal("contradiction not recorded")
		}

		backend.generation = ipcGenerationA
		candidate := f.labs.localCandidate

		if _, err := runPrepareLease(f, preparation); labCode(err) != CodeStateUncertain || f.labs.preparedLease != nil ||
			f.labs.localCandidate != candidate {
			t.Fatalf("lease prepared on a contradicted generation: %v", err)
		}

		f.labs.candidateGenerationContradicted = false

		if _, err := runPrepareLease(f, preparation); err != nil {
			t.Fatalf("the refusal consumed the capability: %v", err)
		}
	})

	t.Run("candidate", func(t *testing.T) {
		f, backend, req := newVerifiedCandidateFixture(t)

		if _, err := runCandidateRequest(f, req); err != nil {
			t.Fatal(err)
		}

		probe := f.mint(generationProbeIntent(t, f.lab, backend.pin.String(), ipcGenerationA))
		if _, err := f.labs.executeMultiProbe(context.Background(), probe, f.verifier); err != nil {
			t.Fatal(err)
		}

		intent, err := candidateIntentFromEvidence(f.labs.verifiedEvidence)
		if err != nil {
			t.Fatal(err)
		}

		f.labs.candidateGenerationContradicted = true
		evidence := f.labs.verifiedEvidence

		if _, err := runCandidateRequest(f, f.mint(intent)); labCode(err) != CodeStateUncertain ||
			f.labs.verifiedEvidence != evidence || len(f.labs.candidateRetirements) != 1 {
			t.Fatalf("candidate on a contradicted generation: %v", err)
		}
	})
}

func TestRevocationReceiptDespiteSealedCheckFailure(t *testing.T) {
	f, backend, preparation := newPreparedLeaseFixture(t)

	if _, err := runPrepareLease(f, preparation); err != nil {
		t.Fatal(err)
	}

	f.backend.verifyErr = errors.New("synthetic firewall drift")

	result, err := runRevokeLease(f, revokeRequest(t, f, preparation))
	if err != nil || !result.GenerationRetired || backend.cleanups != 1 ||
		!f.labs.candidateRetirements[preparation.Intent.ReservationNonce].retired {
		t.Fatalf("retired generation without a receipt: %v", err)
	}

	if f.labs.labs.peek(f.lab.ProfileID).State != LabFaulted {
		t.Fatal("a lab that failed its sealed check was not faulted")
	}
}

// cancelingCleanupBackend ends the operation's context right after a successful cleanup.
type cancelingCleanupBackend struct {
	*fakeGenerationProbeBackend

	cancel context.CancelFunc
}

func (b *cancelingCleanupBackend) CleanupStage(ctx context.Context, namespace string) error {
	err := b.fakeGenerationProbeBackend.CleanupStage(ctx, namespace)
	b.cancel()

	return err
}

func TestRevocationReceiptAfterDeadlineInSealedCheck(t *testing.T) {
	f, backend, preparation := newPreparedLeaseFixture(t)
	req := revokeRequest(t, f, preparation)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	canceling := &cancelingCleanupBackend{fakeGenerationProbeBackend: backend, cancel: cancel}
	f.labs.tunnels, f.labs.multiProbes, f.labs.generationProbes = canceling, canceling, canceling

	result, err := f.labs.revokeEgressLease(ctx, req, f.verifier, multiProbeTestRuntimeID)
	if err != nil || !result.GenerationRetired || backend.cleanups != 1 {
		t.Fatalf("retired generation without a receipt after the deadline: %v", err)
	}
}

// A stalled log delays neither the receipt nor other lifecycle operations.
func TestRevocationFaultLogOffResponsePath(t *testing.T) {
	f, _, preparation := newPreparedLeaseFixture(t)
	f.backend.verifyErr = errors.New("synthetic firewall drift")

	lines := make(chan string, 1)
	release := make(chan struct{})
	var locked atomic.Bool

	f.labs.logf = func(format string, args ...any) {
		if f.labs.mu.TryLock() {
			f.labs.mu.Unlock()
		} else {
			locked.Store(true)
		}

		lines <- fmt.Sprintf(format, args...)
		<-release
	}
	t.Cleanup(func() { close(release) })

	req := revokeRequest(t, f, preparation)
	done := make(chan error, 1)

	go func() {
		_, err := runRevokeLease(f, req)
		done <- err
	}()

	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("a stalled log held up the receipt")
	}

	select {
	case line := <-lines:
		if !strings.Contains(line, "synthetic firewall drift") || locked.Load() {
			t.Fatalf("fault log %q, written under the lifecycle lock: %t", line, locked.Load())
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the fault was not logged")
	}
}
