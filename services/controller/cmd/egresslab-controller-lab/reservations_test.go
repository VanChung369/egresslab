//go:build windows || linux || darwin

package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/VanChung369/egresslab/services/controller/internal/control"
	"github.com/VanChung369/egresslab/services/controller/internal/labruntime"
)

func TestControllerReservationAuthority(t *testing.T) {
	h := newHarness(t)

	if err := h.run("init-reservations"); err == nil || !strings.Contains(err.Error(), "requires -approve") {
		t.Fatalf("unapproved initialization: %v", err)
	}

	h.requireCode(codeReservationUnavailable, "list-reservations")

	h.mustRun("-approve", "init-reservations")
	h.mustRun("list-reservations")

	var result reservationListResult
	if err := json.Unmarshal(h.out.Bytes(), &result); err != nil {
		t.Fatal(err)
	}

	if result.Authority.ID == "" || result.Reservations == nil || len(result.Reservations) != 0 || result.NetworkReady {
		t.Fatalf("incorrect authority response: %s", h.out.String())
	}

	if h.reached != 0 {
		t.Fatal("a local authority command reached a runtime")
	}

	h.requireCode(codeReservationAuthorityExists, "-approve", "init-reservations")

	// Another configuration directory does not select another authority.
	t.Setenv("EGRESSLAB_DATA_DIR", t.TempDir())
	h.mustRun("list-reservations")

	var second reservationListResult
	if err := json.Unmarshal(h.out.Bytes(), &second); err != nil {
		t.Fatal(err)
	}

	if second.Authority != result.Authority {
		t.Fatal("a data-directory change selected another authority")
	}

	// Another controller key is refused, for listing and before any runtime call.
	h.keys = &memoryKeys{}
	if err := h.keys.Initialize(); err != nil {
		t.Fatal(err)
	}

	h.requireCode(codeReservationAuthorityMismatch, "list-reservations")
	h.requireCode(codeReservationAuthorityMismatch, "-approve", "-wsl-distro", "Ubuntu-A", "reserve-egress", h.profile.ID, labNS)

	if a := h.runtimes["Ubuntu-A"]; len(a.calls) != 0 {
		t.Fatalf("a foreign key reached the helper: %v", a.calls)
	}
}

// The production root ignores EGRESSLAB_DATA_DIR; computing it creates nothing.
func TestDefaultReservationRoot(t *testing.T) {
	config, err := os.UserConfigDir()
	if err != nil {
		t.Skipf("no user configuration directory: %v", err)
	}

	t.Setenv("EGRESSLAB_DATA_DIR", t.TempDir())

	root, err := defaultReservationRoot()
	if err != nil || root != filepath.Join(config, "EgressLab") {
		t.Fatalf("reservation root %q: %v", root, err)
	}

	dataDir, err := dataDirectory()
	if err != nil || dataDir == root {
		t.Fatalf("data directory %q selected the authority root", dataDir)
	}
}

// setupReservationLab trusts runtime distro and gives the profile a configured tunnel there, with
// observations stamped on the real clock the workflow uses.
func setupReservationLab(t *testing.T, h *harness, distro string, profileID string) *fakeRuntime {
	t.Helper()

	rt := h.runtimes[distro]
	namespace := labNS
	if rt.namespace != "" {
		namespace = rt.namespace
	}

	rt.stage = control.LabStageInfo{ProfileID: profileID, StageID: cliTestStage, Compatible: true}
	rt.multiProbeEdit = func(info *control.LabMultiProbeInfo) {
		now := time.Now().UTC()
		info.StartedAt, info.FinishedAt, info.ObservedAt, info.HandshakeAt = now, now, now, now.Add(-time.Second)

		for i := range info.Sources {
			info.Sources[i].ObservedAt = now
		}
	}

	h.mustRun("-approve", "-wsl-distro", distro, "trust-runtime")
	h.mustRun("-approve", "-wsl-distro", distro, "create-lab", profileID)
	h.mustRun("-approve", "-wsl-distro", distro, "connect-tunnel", profileID, namespace, cliTestStage)

	return rt
}

func reservationList(t *testing.T, h *harness) reservationListResult {
	t.Helper()

	h.mustRun("list-reservations")

	var listed reservationListResult
	if err := json.Unmarshal(h.out.Bytes(), &listed); err != nil {
		t.Fatal(err)
	}

	return listed
}

func TestControllerReserveEgress(t *testing.T) {
	h := newHarness(t)
	h.now = time.Now
	p := h.profile.ID

	h.mustRun("-approve", "init-reservations")
	a := setupReservationLab(t, h, "Ubuntu-A", p)

	command := []string{"-wsl-distro", "Ubuntu-A", "reserve-egress", p, labNS}
	if err := h.run(command...); err == nil || !strings.Contains(err.Error(), "requires -approve") {
		t.Fatalf("unapproved reservation: %v", err)
	}

	for _, extra := range [][]string{{"8.8.4.4"}, {"--ignore-collision"}} {
		if err := h.run(append(append([]string{"-approve"}, command...), extra...)...); err == nil ||
			!strings.Contains(err.Error(), "usage") {
			t.Fatalf("extra argument %v accepted: %v", extra, err)
		}
	}

	stateBefore, _ := os.ReadFile(filepath.Join(h.dir, "state.json"))
	runtimesBefore, _ := os.ReadFile(filepath.Join(h.dir, "runtimes.json"))

	approved := append([]string{"-approve"}, command...)
	h.mustRun(approved...)

	var result reservationCommandResult
	if err := json.Unmarshal(h.out.Bytes(), &result); err != nil {
		t.Fatal(err)
	}

	if result.State != "prepared" || result.AuthorityID == "" || result.Reservation.ID == "" ||
		result.Reservation.Owner.ProfileID != p || result.Reservation.Owner.RuntimeID != runtimeA ||
		result.Reservation.IPv4.String() != "8.8.4.4" || result.ActivationAllowed || result.NetworkReady ||
		result.PreparedLease.ReservationID != result.Reservation.ID ||
		result.PreparedLease.AuthorityID != result.AuthorityID ||
		result.PreparedLease.IPv4 != result.Reservation.IPv4 ||
		len(a.multiProbeCalls) != 1 || len(a.candidateCalls) != 1 || len(a.prepareCalls) != 1 {
		t.Fatalf("incorrect reservation workflow: %s", h.out.String())
	}

	// A hold is not an active profile: no profile, endpoint or binding changes.
	stateAfter, _ := os.ReadFile(filepath.Join(h.dir, "state.json"))
	runtimesAfter, _ := os.ReadFile(filepath.Join(h.dir, "runtimes.json"))

	if !bytes.Equal(stateBefore, stateAfter) || !bytes.Equal(runtimesBefore, runtimesAfter) {
		t.Fatal("reservation changed the controller state")
	}

	if listed := reservationList(t, h); len(listed.Reservations) != 1 || listed.Reservations[0].ID != result.Reservation.ID {
		t.Fatal("reservation not persisted")
	}

	h.requireCode(codeReservationHeld, approved...)

	if len(a.multiProbeCalls) != 1 || len(a.candidateCalls) != 1 || len(a.prepareCalls) != 1 {
		t.Fatal("an existing reservation triggered another probe")
	}
}

func TestControllerReserveWithoutAuthority(t *testing.T) {
	h := newHarness(t)

	h.requireCode(codeReservationUnavailable, "-approve", "-wsl-distro", "Ubuntu-A", "reserve-egress", h.profile.ID, labNS)

	if a := h.runtimes["Ubuntu-A"]; len(a.calls) != 0 || len(a.multiProbeCalls) != 0 || len(a.candidateCalls) != 0 {
		t.Fatal("a missing authority reached the helper")
	}
}

// A profile bound on Ubuntu-A cannot be reserved through Ubuntu-B's transport.
func TestControllerReserveWrongRuntime(t *testing.T) {
	h := newHarness(t)
	h.now = time.Now
	p := h.profile.ID

	h.mustRun("-approve", "init-reservations")
	a := setupReservationLab(t, h, "Ubuntu-A", p)
	h.mustRun("-approve", "-wsl-distro", "Ubuntu-B", "trust-runtime")

	h.requireCode(labruntime.CodeOwnershipMismatch, "-approve", "-wsl-distro", "Ubuntu-B", "reserve-egress", p, labNS)

	b := h.runtimes["Ubuntu-B"]
	if len(a.multiProbeCalls) != 0 || len(b.multiProbeCalls) != 0 || len(a.candidateCalls) != 0 || len(b.candidateCalls) != 0 {
		t.Fatal("the wrong runtime was probed")
	}

	if listed := reservationList(t, h); len(listed.Reservations) != 0 {
		t.Fatal("a hold was created through the wrong runtime")
	}
}

// Two runtimes see the same exit address: both consume a candidate, one hold is granted.
func TestControllerReserveCollision(t *testing.T) {
	h := newHarness(t)
	h.now = time.Now

	store, err := control.NewStore(filepath.Join(h.dir, "state.json"))
	if err != nil {
		t.Fatal(err)
	}

	other, err := store.CreateProfile("Second lab profile")
	if err != nil {
		t.Fatal(err)
	}

	const otherNS = "egresslab-lab-fedcba9876543210"

	h.runtimes["Ubuntu-B"].namespace = otherNS
	h.runtimes["Ubuntu-B"].info.HelperID = epoch2

	h.mustRun("-approve", "init-reservations")
	a := setupReservationLab(t, h, "Ubuntu-A", h.profile.ID)
	b := setupReservationLab(t, h, "Ubuntu-B", other.ID)

	h.mustRun("-approve", "-wsl-distro", "Ubuntu-A", "reserve-egress", h.profile.ID, labNS)
	h.requireCode(codeReservationCollision, "-approve", "-wsl-distro", "Ubuntu-B", "reserve-egress", other.ID, otherNS)

	if len(a.candidateCalls) != 1 || len(b.candidateCalls) != 1 {
		t.Fatal("both runtimes should have consumed a candidate")
	}

	if len(a.prepareCalls) != 1 || len(b.prepareCalls) != 0 {
		t.Fatal("the colliding runtime reached lease preparation")
	}

	listed := reservationList(t, h)
	if len(listed.Reservations) != 1 || listed.Reservations[0].Owner.RuntimeID != runtimeA {
		t.Fatal("the collision replaced the first hold")
	}
}

// A coded helper refusal survives the mapping, and leaves no hold.
func TestControllerReserveCandidateRefused(t *testing.T) {
	h := newHarness(t)
	h.now = time.Now
	p := h.profile.ID

	h.mustRun("-approve", "init-reservations")
	a := setupReservationLab(t, h, "Ubuntu-A", p)
	a.candidateErr = labruntime.Errorf(labruntime.CodeEvidenceUnavailable, "evidence expired")

	h.requireCode(labruntime.CodeEvidenceUnavailable, "-approve", "-wsl-distro", "Ubuntu-A", "reserve-egress", p, labNS)

	if listed := reservationList(t, h); len(listed.Reservations) != 0 {
		t.Fatal("a refused candidate created a hold")
	}
}

func TestReservationCommandError(t *testing.T) {
	for _, tt := range []struct {
		err  error
		code string
	}{
		{control.ErrReservationIPCollision, codeReservationCollision},
		{control.ErrReservationBusy, codeReservationBusy},
		{control.ErrReservationAuthorityMismatch, codeReservationAuthorityMismatch},
		{control.ErrReservationAuthorityExists, codeReservationAuthorityExists},
		{control.ErrReservationJournalCorrupt, codeReservationJournalCorrupt},
		{control.ErrReservationProfileHeld, codeReservationHeld},
		{control.ErrReservationLimit, codeReservationLimit},
		{control.ErrReservationCandidateExpired, codeReservationExpired},
		{control.ErrReservationCandidateInvalid, codeReservationInvalid},
		{control.ErrReservationUnavailable, codeReservationUnavailable},
		{control.ErrReservationCommittedExpired, labruntime.CodeStateUncertain},
		{control.ErrReservationStateUncertain, labruntime.CodeStateUncertain},
		// After the commit, even a coded helper refusal or an uncertain outcome reads as unconfirmed.
		{fmt.Errorf("%w: %w", control.ErrLeasePreparationUnconfirmed,
			labruntime.Errorf(labruntime.CodeEvidenceUnavailable, "expired")), codeLeasePreparationUnconfirmed},
		{fmt.Errorf("%w: %w", control.ErrLeasePreparationUnconfirmed, control.ErrReservationStateUncertain),
			codeLeasePreparationUnconfirmed},
		// Uncertain wins over anything joined with it.
		{errors.Join(control.ErrReservationStateUncertain, control.ErrReservationCandidateExpired), labruntime.CodeStateUncertain},
		{labruntime.Errorf(labruntime.CodeEvidenceUnavailable, "expired evidence"), labruntime.CodeEvidenceUnavailable},
	} {
		if err := reservationCommandError(tt.err); labruntime.ErrorCode(err) != tt.code {
			t.Errorf("%v mapped to %v, want %s", tt.err, err, tt.code)
		}
	}
}

// A sealed lab is refused before anything is signed or probed.
func TestControllerReserveSealedLab(t *testing.T) {
	h := newHarness(t)
	h.now = time.Now
	p := h.profile.ID

	h.mustRun("-approve", "init-reservations")
	h.mustRun("-approve", "-wsl-distro", "Ubuntu-A", "trust-runtime")
	h.mustRun("-approve", "-wsl-distro", "Ubuntu-A", "create-lab", p)

	signs := h.keys.signs
	h.requireCode(labruntime.CodeLabFaulted, "-approve", "-wsl-distro", "Ubuntu-A", "reserve-egress", p, labNS)

	if a := h.runtimes["Ubuntu-A"]; len(a.multiProbeCalls) != 0 || len(a.candidateCalls) != 0 || h.keys.signs != signs {
		t.Fatal("a sealed lab was probed or signed for")
	}
}

type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) { return 0, errors.New("disk full") }

// The hold is durable before the receipt is written: a lost receipt is uncertain, not a refusal.
func TestControllerReserveLostReceipt(t *testing.T) {
	h := newHarness(t)
	h.now = time.Now
	p := h.profile.ID

	h.mustRun("-approve", "init-reservations")
	setupReservationLab(t, h, "Ubuntu-A", p)

	h.stdout = failingWriter{}
	h.requireCode(labruntime.CodeStateUncertain, "-approve", "-wsl-distro", "Ubuntu-A", "reserve-egress", p, labNS)
	h.stdout = nil

	if listed := reservationList(t, h); len(listed.Reservations) != 1 {
		t.Fatal("the committed hold is missing")
	}
}

// A failure after the durable commit keeps the hold and says so; nothing retries.
func TestControllerPreparationUnconfirmed(t *testing.T) {
	h := newHarness(t)
	h.now = time.Now
	p := h.profile.ID

	h.mustRun("-approve", "init-reservations")
	a := setupReservationLab(t, h, "Ubuntu-A", p)
	a.prepareErr = labruntime.Errorf(labruntime.CodeEvidenceUnavailable, "candidate expired")

	reserve := []string{"-approve", "-wsl-distro", "Ubuntu-A", "reserve-egress", p, labNS}
	h.requireCode(codeLeasePreparationUnconfirmed, reserve...)

	if listed := reservationList(t, h); len(listed.Reservations) != 1 || len(a.prepareCalls) != 1 {
		t.Fatal("a preparation failure lost the hold or retried")
	}

	h.requireCode(codeReservationHeld, reserve...)

	if len(a.prepareCalls) != 1 {
		t.Fatal("the existing hold triggered another preparation")
	}
}

func setupReleaseCLI(t *testing.T) (*harness, *fakeRuntime, string) {
	t.Helper()

	h := newHarness(t)
	h.now = time.Now

	h.mustRun("-approve", "init-reservations")
	rt := setupReservationLab(t, h, "Ubuntu-A", h.profile.ID)
	h.mustRun("-approve", "-wsl-distro", "Ubuntu-A", "reserve-egress", h.profile.ID, labNS)

	listed := reservationList(t, h)
	if len(listed.Reservations) != 1 {
		t.Fatal("reservation fixture missing")
	}

	return h, rt, listed.Reservations[0].ID
}

func releaseCommand(distro, id string) []string {
	return []string{"-approve", "-wsl-distro", distro, "release-egress", id}
}

func TestControllerReleaseEgress(t *testing.T) {
	h, a, id := setupReleaseCLI(t)

	if err := h.run("-wsl-distro", "Ubuntu-A", "release-egress", id); err == nil ||
		!strings.Contains(err.Error(), "requires -approve") {
		t.Fatal("an unapproved release accepted")
	}

	before := h.keys.signs
	h.mustRun(releaseCommand("Ubuntu-A", id)...)

	var result reservationReleaseCommandResult
	if err := json.Unmarshal(h.out.Bytes(), &result); err != nil {
		t.Fatal(err)
	}

	if result.State != "released" || result.Reservation.ID != id || !result.RevokedLease.GenerationRetired ||
		result.RevokedLease.Intent.ReservationID != id || result.ReleasedAt.IsZero() || result.ActivationAllowed ||
		result.NetworkReady || len(a.revokeCalls) != 1 || h.keys.signs != before+1 || a.tunnelProfile != "" ||
		a.tunnelGeneration != "" || !strings.Contains(h.out.String(), `"network_ready": false`) {
		t.Fatalf("incorrect CLI release result: %s", h.out.String())
	}

	if listed := reservationList(t, h); len(listed.Reservations) != 0 {
		t.Fatal("a released reservation remains held")
	}

	h.requireCode(codeReservationNotFound, releaseCommand("Ubuntu-A", id)...)

	if len(a.revokeCalls) != 1 {
		t.Fatal("an old release reached the helper again")
	}
}

func TestControllerReleaseWrongEpoch(t *testing.T) {
	h, a, id := setupReleaseCLI(t)
	before := h.keys.signs

	// A helper restart: the same runtime, another epoch.
	a.info.HelperID = "helper_ffffffffffffffffffffffffffffffff"

	h.requireCode(codeReservationReleaseInvalid, releaseCommand("Ubuntu-A", id)...)

	if len(a.revokeCalls) != 0 || h.keys.signs != before {
		t.Fatal("a foreign helper epoch received authorization")
	}

	if listed := reservationList(t, h); len(listed.Reservations) != 1 {
		t.Fatal("a helper restart released ownership")
	}
}

// The helper retired the generation, but its receipt was lost: the hold stays, and a newly approved
// release confirms the retirement with a new capability.
func TestControllerReleaseLostRevocationReceipt(t *testing.T) {
	h, a, id := setupReleaseCLI(t)

	a.loseRevocationReceipt = true
	h.requireCode(codeLeaseRevocationUnconfirmed, releaseCommand("Ubuntu-A", id)...)

	if a.tunnelGeneration != "" || len(a.revokeCalls) != 1 {
		t.Fatal("incorrect simulated retirement")
	}

	if listed := reservationList(t, h); len(listed.Reservations) != 1 {
		t.Fatal("a lost retirement receipt released ownership")
	}

	firstNonce := a.revokeCalls[0].Claims.Nonce
	a.loseRevocationReceipt = false

	h.mustRun(releaseCommand("Ubuntu-A", id)...)

	if len(a.revokeCalls) != 2 || a.revokeCalls[1].Claims.Nonce == firstNonce {
		t.Fatal("the confirmation reused old authorization")
	}

	if listed := reservationList(t, h); len(listed.Reservations) != 0 {
		t.Fatal("a confirmed retirement was not released")
	}
}

func TestControllerReleaseLostOutput(t *testing.T) {
	h, _, id := setupReleaseCLI(t)

	h.stdout = failingWriter{}
	h.requireCode(labruntime.CodeStateUncertain, releaseCommand("Ubuntu-A", id)...)
	h.stdout = nil

	if listed := reservationList(t, h); len(listed.Reservations) != 0 {
		t.Fatal("a committed release was rolled back")
	}
}

// A lab that is already gone is no obstacle: the helper kept the retirement record.
func TestControllerReleaseAfterCleanup(t *testing.T) {
	for name, cleanup := range map[string][][]string{
		"disconnect": {{"-approve", "-wsl-distro", "Ubuntu-A", "disconnect", "", labNS}},
		"delete and unbind": {
			{"-approve", "-wsl-distro", "Ubuntu-A", "delete-lab", "", labNS},
			{"-approve", "-wsl-distro", "Ubuntu-A", "unbind-profile", ""},
		},
	} {
		t.Run(name, func(t *testing.T) {
			h, a, id := setupReleaseCLI(t)

			for _, args := range cleanup {
				args = slices.Clone(args)
				args[slices.Index(args, "")] = h.profile.ID
				h.mustRun(args...)
			}

			if a.tunnelGeneration != "" {
				t.Fatal("the cleanup left the tunnel")
			}

			h.mustRun(releaseCommand("Ubuntu-A", id)...)

			if listed := reservationList(t, h); len(listed.Reservations) != 0 || len(a.revokeCalls) != 1 {
				t.Fatal("a retired generation of a removed lab was not released")
			}
		})
	}
}

func TestControllerReleaseWrongRuntime(t *testing.T) {
	h, a, id := setupReleaseCLI(t)
	b := h.runtimes["Ubuntu-B"]

	h.mustRun("-approve", "-wsl-distro", "Ubuntu-B", "trust-runtime")

	calls, signs := len(b.calls), h.keys.signs

	h.requireCode(codeReservationReleaseInvalid, releaseCommand("Ubuntu-B", id)...)
	h.requireCode(labruntime.CodeRuntimeUntrusted, releaseCommand("Ubuntu-C", id)...)

	if len(b.calls) != calls || len(a.revokeCalls) != 0 || h.keys.signs != signs {
		t.Fatal("another runtime was contacted or signed for")
	}

	if listed := reservationList(t, h); len(listed.Reservations) != 1 {
		t.Fatal("a refused release lost ownership")
	}
}

func TestControllerReleaseArguments(t *testing.T) {
	h := newHarness(t)

	for _, args := range [][]string{
		{"-approve", "release-egress"},
		{"-approve", "release-egress", "reservation_1"},
		{"-approve", "release-egress", "8.8.4.4"},
		{"-approve", "release-egress", "reservation_0123456789abcdef0123456789abcdef", "extra"},
	} {
		if err := h.run(args...); err == nil || !strings.Contains(err.Error(), "usage") {
			t.Fatalf("invalid arguments accepted: %v: %v", args, err)
		}
	}

	if h.reached != 0 {
		t.Fatal("invalid arguments reached a runtime")
	}
}

// After the retirement, an uncertain write outranks every other cause, and a refusal of the commit
// is not a refusal of the revocation.
func TestReleaseErrorCodes(t *testing.T) {
	for want, err := range map[string]error{
		labruntime.CodeStateUncertain: errors.Join(control.ErrReservationReleaseUnconfirmed,
			control.ErrReservationStateUncertain),
		codeReservationReleaseUnconfirmed: errors.Join(control.ErrReservationReleaseUnconfirmed, control.ErrReservationBusy),
		codeLeaseRevocationUnconfirmed: errors.Join(control.ErrLeaseRevocationUnconfirmed,
			control.ErrReservationReleaseInvalid),
		codeReservationReleaseInvalid: control.ErrReservationReleaseInvalid,
		codeReservationNotFound:       control.ErrReservationNotFound,
		codeReservationOwnerRetired:   control.ErrReservationOwnerRetired,
		codeReservationJournalCorrupt: errors.Join(control.ErrReservationJournalCorrupt, control.ErrReservationOwnerRetired),
	} {
		if got := labruntime.ErrorCode(reservationCommandError(err)); got != want {
			t.Errorf("%v: got %s, want %s", err, got, want)
		}
	}
}

func recoverCommand(distro, id string) []string {
	return []string{"-approve", "-wsl-distro", distro, "recover-egress", id}
}

func TestControllerRecoverEgress(t *testing.T) {
	h, a, id := setupReleaseCLI(t)
	original := a.info.HelperID

	if err := h.run("-wsl-distro", "Ubuntu-A", "recover-egress", id); err == nil ||
		!strings.Contains(err.Error(), "requires -approve") {
		t.Fatal("an unapproved recovery accepted")
	}

	// The original epoch is alive: recovery is refused before anything is signed.
	signs := h.keys.signs
	h.requireCode(codeReservationReleaseInvalid, recoverCommand("Ubuntu-A", id)...)

	if len(a.revokeCalls) != 0 || h.keys.signs != signs {
		t.Fatal("a recovery reached the original helper epoch")
	}

	// A crash and a restart in the same boot: release needs the lost epoch, recovery a reboot.
	a.info.HelperID = "helper_ffffffffffffffffffffffffffffffff"

	h.requireCode(codeReservationReleaseInvalid, releaseCommand("Ubuntu-A", id)...)
	h.requireCode(codeLeaseRevocationUnconfirmed, recoverCommand("Ubuntu-A", id)...)

	if listed := reservationList(t, h); len(listed.Reservations) != 1 || len(a.revokeCalls) != 1 {
		t.Fatal("a same-boot recovery released ownership")
	}

	a.rebootBoots = [2]string{"11111111-2222-4333-8444-555555555555", "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"}
	h.mustRun(recoverCommand("Ubuntu-A", id)...)

	var result reservationReleaseCommandResult
	if err := json.Unmarshal(h.out.Bytes(), &result); err != nil {
		t.Fatal(err)
	}

	lease := result.RevokedLease
	if result.State != "released" || result.Reservation.ID != id || !lease.GenerationRetired ||
		lease.Intent.Operation != control.LabRecoverRetiredGenerationOp || lease.Intent.OriginalHelperID != original ||
		lease.HelperID != a.info.HelperID || lease.OriginalBootID != a.rebootBoots[0] ||
		lease.CurrentBootID != a.rebootBoots[1] || result.ActivationAllowed || result.NetworkReady {
		t.Fatalf("incorrect CLI recovery result: %s", h.out.String())
	}

	if listed := reservationList(t, h); len(listed.Reservations) != 0 {
		t.Fatal("a recovered reservation remains held")
	}

	h.requireCode(codeReservationNotFound, recoverCommand("Ubuntu-A", id)...)

	if len(a.revokeCalls) != 2 {
		t.Fatal("an old recovery reached the helper again")
	}
}

func TestControllerRecoverArguments(t *testing.T) {
	h := newHarness(t)

	for _, args := range [][]string{
		{"-approve", "recover-egress"},
		{"-approve", "recover-egress", "reservation_1"},
		{"-approve", "recover-egress", "reservation_0123456789abcdef0123456789abcdef", "extra"},
	} {
		if err := h.run(args...); err == nil || !strings.Contains(err.Error(), "usage") {
			t.Fatalf("invalid arguments accepted: %v: %v", args, err)
		}
	}

	if h.reached != 0 {
		t.Fatal("invalid arguments reached a runtime")
	}
}
