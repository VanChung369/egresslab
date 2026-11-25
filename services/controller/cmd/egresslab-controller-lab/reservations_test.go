//go:build windows || linux || darwin

package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
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
