//go:build windows || linux || darwin

package control

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"time"
)

const (
	authorityRaceReady  = "authority-race-ready"
	authorityRaceResult = "authority-race-result="
)

func runAuthorityRaceChild(t *testing.T, mode, dir string) {
	t.Helper()

	number, err := strconv.Atoi(os.Getenv(reservationChildNumberEnv))
	if err != nil || number <= 0 {
		t.Fatal("invalid child number")
	}

	signer := newSeedSigner()

	authority, err := OpenReservationAuthority(dir, signer)
	if err != nil {
		t.Fatal(err)
	}

	journal, err := authority.journal()
	if err != nil {
		t.Fatal(err)
	}

	now := reservationTestBase.Add(3 * time.Minute)
	clock := func() time.Time { return now }

	var operation func() error

	switch mode {
	case "authority-reserve":
		admission := testReservationAdmission(t, number, number, number, "8.8.4.4", now.Add(-11*time.Second))

		operation = func() error {
			_, err := reserveDurableEgressJournal(context.Background(), journal, admission, clock)
			return err
		}

	case "authority-release":
		items, err := authority.List()
		if err != nil || len(items) != 1 {
			t.Fatalf("missing original hold: %v", err)
		}

		candidate := testReservationAdmission(t, 1, 1, 1, "8.8.4.4", reservationTestBase)
		admission := releaseAdmissionFor(t, authority.Info(), signer, items[0], candidate, now.Add(-41*time.Second))

		operation = func() error {
			_, err := releaseDurableEgressJournal(context.Background(), journal, admission, clock)
			return err
		}

	default:
		t.Fatal("unknown authority race operation")
	}

	fmt.Println(authorityRaceReady)

	line, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil || line != "go\n" {
		t.Fatal("invalid process barrier")
	}

	err = operation()

	var result string

	switch {
	case err == nil && mode == "authority-reserve":
		result = "granted"
	case err == nil:
		result = "released"
	case errors.Is(err, ErrReservationBusy):
		result = "busy"
	case errors.Is(err, ErrReservationIPCollision):
		result = "collision"
	case errors.Is(err, ErrReservationNotFound):
		result = "not-found"
	default:
		t.Fatalf("unexpected race result: %v", err)
	}

	fmt.Println(authorityRaceResult + result)
}

type authorityRaceRequest struct {
	mode   string
	number int
}

type authorityRaceChild struct {
	cmd    *exec.Cmd
	stdin  io.WriteCloser
	stdout *bufio.Reader
	waited bool
}

type authorityRace struct {
	dir      string
	children []*authorityRaceChild
}

// startAuthorityRace starts every child up to its barrier; finish releases them together and returns
// the results in request order.
func startAuthorityRace(t *testing.T, dir string, requests ...authorityRaceRequest) *authorityRace {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	race := &authorityRace{dir: dir}

	t.Cleanup(func() {
		for _, child := range race.children {
			_ = child.stdin.Close()

			if !child.waited {
				_ = child.cmd.Process.Kill()
				_ = child.cmd.Wait()
			}
		}

		cancel()
	})

	for _, request := range requests {
		cmd := reservationChildCommand(t, ctx, request.mode, dir, request.number)

		stdin, err := cmd.StdinPipe()
		if err != nil {
			t.Fatal(err)
		}

		stdout, err := cmd.StdoutPipe()
		if err != nil {
			_ = stdin.Close()
			t.Fatal(err)
		}

		cmd.Stderr = os.Stderr

		if err := cmd.Start(); err != nil {
			_ = stdin.Close()
			t.Fatal(err)
		}

		child := &authorityRaceChild{cmd: cmd, stdin: stdin, stdout: bufio.NewReader(stdout)}
		race.children = append(race.children, child)

		for {
			line, err := child.stdout.ReadString('\n')
			if err != nil {
				t.Fatalf("child failed before the barrier: %v %s", err, line)
			}

			if strings.TrimSpace(line) == authorityRaceReady {
				break
			}

			t.Log(strings.TrimSpace(line))
		}
	}

	return race
}

func (r *authorityRace) finish(t *testing.T) []string {
	t.Helper()

	for _, child := range r.children {
		if _, err := io.WriteString(child.stdin, "go\n"); err != nil {
			t.Fatal(err)
		}

		_ = child.stdin.Close()
	}

	results := make([]string, 0, len(r.children))

	for _, child := range r.children {
		output, readErr := io.ReadAll(child.stdout)
		waitErr := child.cmd.Wait()
		child.waited = true

		if readErr != nil || waitErr != nil {
			t.Fatalf("child failed: read=%v wait=%v\n%s", readErr, waitErr, output)
		}

		result := ""

		for _, line := range strings.Split(string(output), "\n") {
			line = strings.TrimSpace(line)
			if !strings.HasPrefix(line, authorityRaceResult) {
				continue
			}

			if result != "" {
				t.Fatal("multiple child results")
			}

			result = strings.TrimPrefix(line, authorityRaceResult)
		}

		if result == "" {
			t.Fatalf("missing child result: %s", output)
		}

		results = append(results, result)
	}

	t.Logf("authority race results: %v", results)

	waitForAuthorityUnlock(t, r.dir)

	return results
}

// waitForAuthorityUnlock polls, tests only: Windows may release a closed handle's lock shortly after.
func waitForAuthorityUnlock(t *testing.T, dir string) {
	t.Helper()

	deadline := time.Now().Add(5 * time.Second)

	for {
		_, err := OpenReservationAuthority(dir, newSeedSigner())
		if err == nil {
			return
		}

		if !errors.Is(err, ErrReservationBusy) || !time.Now().Before(deadline) {
			t.Fatalf("authority lock not released: %v", err)
		}

		time.Sleep(20 * time.Millisecond)
	}
}

func runAuthorityRace(t *testing.T, dir string, requests ...authorityRaceRequest) []string {
	t.Helper()

	return startAuthorityRace(t, dir, requests...).finish(t)
}

func TestAuthorityConcurrentReserveProcesses(t *testing.T) {
	dir, authority, _ := newTestAuthority(t)

	results := runAuthorityRace(t, dir,
		authorityRaceRequest{mode: "authority-reserve", number: 1},
		authorityRaceRequest{mode: "authority-reserve", number: 2})

	winner := 0

	for i, result := range results {
		switch result {
		case "granted":
			if winner != 0 {
				t.Fatal("duplicate IP granted")
			}

			winner = i + 1

		case "busy", "collision":
		default:
			t.Fatalf("unexpected outcome: %s", result)
		}
	}

	if winner == 0 {
		t.Fatal("no reservation committed")
	}

	items, err := authority.List()
	if err != nil || len(items) != 1 || items[0].Owner.RuntimeID != fmt.Sprintf("runtime_%032x", winner) ||
		items[0].IPv4.String() != "8.8.4.4" {
		t.Fatalf("incorrect durable ownership: %v", err)
	}
}

func TestAuthorityConcurrentReleaseReserve(t *testing.T) {
	f := newReleaseTestFixture(t)

	results := runAuthorityRace(t, f.dir,
		authorityRaceRequest{mode: "authority-release", number: 1},
		authorityRaceRequest{mode: "authority-reserve", number: 2})

	releaseResult, reserveResult := results[0], results[1]

	if releaseResult != "released" && releaseResult != "busy" {
		t.Fatalf("invalid release outcome: %s", releaseResult)
	}

	switch reserveResult {
	case "granted", "busy", "collision":
	default:
		t.Fatalf("invalid reserve outcome: %s", reserveResult)
	}

	items, err := f.authority.List()
	if err != nil {
		t.Fatal(err)
	}

	if releaseResult != "released" {
		if reserveResult != "collision" {
			t.Fatalf("the reservation holding the lock found no hold: %s", reserveResult)
		}

		if len(items) != 1 || items[0].ID != f.admission.hold.ID {
			t.Fatal("original reservation lost")
		}

		return
	}

	if reserveResult != "granted" {
		if len(items) != 0 {
			t.Fatal("released address remains held")
		}

		return
	}

	if len(items) != 1 || items[0].ID == f.admission.hold.ID ||
		items[0].Owner.RuntimeID != fmt.Sprintf("runtime_%032x", 2) {
		t.Fatal("incorrect ownership transfer")
	}

	if _, err := f.release(); !errors.Is(err, ErrReservationNotFound) {
		t.Fatalf("stale release accepted: %v", err)
	}

	current, err := f.authority.List()
	if err != nil || len(current) != 1 || current[0].ID != items[0].ID {
		t.Fatal("stale release removed the new owner")
	}
}

func TestAuthorityConcurrentReleaseProcesses(t *testing.T) {
	f := newReleaseTestFixture(t)

	results := runAuthorityRace(t, f.dir,
		authorityRaceRequest{mode: "authority-release", number: 1},
		authorityRaceRequest{mode: "authority-release", number: 1})

	released := 0

	for _, result := range results {
		switch result {
		case "released":
			released++
		case "busy", "not-found":
		default:
			t.Fatalf("unexpected release result: %s", result)
		}
	}

	if released != 1 {
		t.Fatalf("expected one release, got %d", released)
	}

	state, err := loadReservationJournalState(f.journal)
	if err != nil {
		t.Fatal(err)
	}

	if len(state.registry.snapshot()) != 0 || len(state.seenIDs) != 1 || len(state.seenOwners) != 1 {
		t.Fatal("incorrect final journal state")
	}
}

func TestAuthorityReleaseThenReserveProcesses(t *testing.T) {
	f := newReleaseTestFixture(t)

	reserver := startAuthorityRace(t, f.dir, authorityRaceRequest{mode: "authority-reserve", number: 2})

	results := runAuthorityRace(t, f.dir, authorityRaceRequest{mode: "authority-release", number: 1})
	if results[0] != "released" {
		t.Fatalf("release refused: %v", results)
	}

	results = reserver.finish(t)
	if results[0] != "granted" {
		t.Fatalf("released address not reusable: %v", results)
	}

	items, err := f.authority.List()
	if err != nil || len(items) != 1 || items[0].ID == f.admission.hold.ID ||
		items[0].Owner.RuntimeID != fmt.Sprintf("runtime_%032x", 2) {
		t.Fatal("incorrect ownership transfer")
	}

	if _, err := f.release(); !errors.Is(err, ErrReservationNotFound) {
		t.Fatalf("stale release accepted: %v", err)
	}

	if current, err := f.authority.List(); err != nil || len(current) != 1 || current[0].ID != items[0].ID {
		t.Fatal("stale release removed the new owner")
	}
}

func runAuthorityHoldChild(t *testing.T, mode, dir string) {
	t.Helper()

	var held io.Closer

	if mode == "marker-hold" {
		marker, _, err := openReservationAuthorityMarker(dir)
		if err != nil {
			t.Fatal(err)
		}

		held = marker
	} else {
		authority, err := OpenReservationAuthority(dir, newSeedSigner())
		if err != nil {
			t.Fatal(err)
		}

		journal, err := authority.journal()
		if err != nil {
			t.Fatal(err)
		}

		handle, err := journal.open()
		if err != nil {
			t.Fatal(err)
		}

		held = handle
	}
	defer held.Close()

	fmt.Println("authority-lock-ready")

	if _, err := io.Copy(io.Discard, os.Stdin); err != nil {
		t.Fatal(err)
	}
}

func TestAuthorityLockedProcessFailsFast(t *testing.T) {
	for mode, ready := range map[string]string{
		"authority-hold": "authority-lock-ready",
		"marker-hold":    "authority-lock-ready",
		"hold":           "journal-lock-ready",
	} {
		t.Run(mode, func(t *testing.T) { testAuthorityLockedProcess(t, mode, ready) })
	}
}

func testAuthorityLockedProcess(t *testing.T, mode, ready string) {
	f := newReleaseTestFixture(t)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	cmd := reservationChildCommand(t, ctx, mode, f.dir, 1)

	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	defer stdin.Close()

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}

	cmd.Stderr = os.Stderr

	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}

	waited := false
	defer func() {
		if !waited {
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
		}
	}()

	reader := bufio.NewReader(stdout)
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			t.Fatalf("child exited without the lock: %v", err)
		}

		if strings.TrimSpace(line) == ready {
			break
		}
	}

	next := testReservationAdmission(t, 2, 2, 2, "8.8.8.8", f.now.Add(-11*time.Second))
	results := make(chan []error, 1)

	go func() {
		_, reserveErr := reserveDurableEgressJournal(context.Background(), f.journal, next, f.clock)
		_, releaseErr := f.release()
		_, listErr := f.authority.List()
		results <- []error{reserveErr, releaseErr, listErr}
	}()

	select {
	case errs := <-results:
		for _, err := range errs {
			if !errors.Is(err, ErrReservationBusy) {
				t.Fatalf("a locked authority was used: %v", errs)
			}
		}
	case <-time.After(10 * time.Second):
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		waited = true

		select {
		case <-results:
		case <-time.After(10 * time.Second):
		}

		t.Fatal("a transaction waited for the lock")
	}

	_ = stdin.Close()
	if err := cmd.Wait(); err != nil {
		t.Fatal(err)
	}
	waited = true

	waitForAuthorityUnlock(t, f.dir)

	if _, err := f.release(); err != nil {
		t.Fatalf("authority unusable after the holder exited: %v", err)
	}
}
