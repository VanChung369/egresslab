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
	reservationChildModeEnv   = "EGRESSLAB_TEST_RESERVATION_CHILD"
	reservationChildDirEnv    = "EGRESSLAB_TEST_RESERVATION_DIR"
	reservationChildNumberEnv = "EGRESSLAB_TEST_RESERVATION_NUMBER"
)

// TestReservationJournalSubprocess is the entry point of the child processes: the test binary
// re-runs itself as a real second OS process. Without the environment it does nothing.
func TestReservationJournalSubprocess(t *testing.T) {
	mode := os.Getenv(reservationChildModeEnv)
	if mode == "" {
		return
	}

	dir := os.Getenv(reservationChildDirEnv)

	switch mode {
	case "hold":
		path, err := reservationJournalPath(dir)
		if err != nil {
			t.Fatal(err)
		}

		file, err := openLockedReservationJournal(path, false)
		if err != nil {
			t.Fatal(err)
		}
		defer file.Close()

		fmt.Println("journal-lock-ready")

		// Hold the lock until the parent closes stdin or kills this process.
		if _, err := io.Copy(io.Discard, os.Stdin); err != nil {
			t.Fatal(err)
		}

	case "reserve":
		number, err := strconv.Atoi(os.Getenv(reservationChildNumberEnv))
		if err != nil || number <= 0 {
			t.Fatal("invalid child owner")
		}

		base := reservationTestBase
		admission := testReservationAdmission(t, number, number, number, "8.8.4.4", base)

		// Start together with the other children: wait for the parent's line (or EOF).
		fmt.Println("reserve-ready")
		_, _ = bufio.NewReader(os.Stdin).ReadString('\n')

		_, err = reserveDurableEgressAt(dir, admission, func() time.Time { return base.Add(11 * time.Second) })

		switch {
		case err == nil:
			fmt.Println("reservation-result=granted")
		case errors.Is(err, ErrReservationBusy):
			fmt.Println("reservation-result=busy")
		case errors.Is(err, ErrReservationIPCollision):
			fmt.Println("reservation-result=collision")
		default:
			t.Fatal(err)
		}

	default:
		t.Fatal("unknown reservation child mode")
	}
}

func reservationChildCommand(t *testing.T, ctx context.Context, mode, dir string, number int) *exec.Cmd {
	t.Helper()

	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}

	cmd := exec.CommandContext(ctx, executable, "-test.run=^TestReservationJournalSubprocess$")
	cmd.Env = append(os.Environ(),
		reservationChildModeEnv+"="+mode,
		reservationChildDirEnv+"="+dir,
		reservationChildNumberEnv+"="+strconv.Itoa(number))

	return cmd
}

func TestReservationJournalProcessLockRecovery(t *testing.T) {
	dir := newTestReservationJournal(t)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	cmd := reservationChildCommand(t, ctx, "hold", dir, 0)

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

	ready := make(chan bool, 1)
	go func() {
		scanner := bufio.NewScanner(stdout)
		found := false

		for scanner.Scan() {
			if !found && scanner.Text() == "journal-lock-ready" {
				found = true
				ready <- true
			}
		}

		if !found {
			ready <- false
		}
	}()

	select {
	case ok := <-ready:
		if !ok {
			t.Fatal("child exited without the lock")
		}
	case <-ctx.Done():
		t.Fatal("child lock timed out")
	}

	if _, err := inspectReservationJournal(dir); !errors.Is(err, ErrReservationBusy) {
		t.Fatalf("cross-process lock bypassed: %v", err)
	}

	base := reservationTestBase
	admission := testReservationAdmission(t, 1, 1, 1, "8.8.4.4", base)
	clock := func() time.Time { return base.Add(11 * time.Second) }

	if _, err := reserveDurableEgressAt(dir, admission, clock); !errors.Is(err, ErrReservationBusy) {
		t.Fatalf("allocation without the exclusive lock: %v", err)
	}

	// Kill only the test's own child; the OS must release its lock.
	if err := cmd.Process.Kill(); err != nil {
		t.Fatal(err)
	}

	_ = cmd.Wait()
	waited = true

	// Bounded polling, tests only: some platforms release the lock shortly after exit.
	deadline := time.Now().Add(5 * time.Second)

	for {
		_, err = inspectReservationJournal(dir)
		if err == nil {
			break
		}

		if !errors.Is(err, ErrReservationBusy) || !time.Now().Before(deadline) {
			t.Fatalf("OS lock not released: %v", err)
		}

		time.Sleep(20 * time.Millisecond)
	}

	if _, err := reserveDurableEgressAt(dir, admission, clock); err != nil {
		t.Fatal("journal unusable after the child exited:", err)
	}
}

func TestReservationJournalConcurrentProcesses(t *testing.T) {
	dir := newTestReservationJournal(t)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	type child struct {
		cmd    *exec.Cmd
		stdin  io.WriteCloser
		ready  chan struct{}
		output chan string
	}

	var children []child

	defer func() {
		for _, c := range children {
			_ = c.cmd.Process.Kill()
			_ = c.cmd.Wait()
		}
	}()

	for _, number := range []int{1, 2} {
		c := child{
			cmd:    reservationChildCommand(t, ctx, "reserve", dir, number),
			ready:  make(chan struct{}),
			output: make(chan string, 1),
		}

		var err error
		if c.stdin, err = c.cmd.StdinPipe(); err != nil {
			t.Fatal(err)
		}

		stdout, err := c.cmd.StdoutPipe()
		if err != nil {
			t.Fatal(err)
		}

		c.cmd.Stderr = os.Stderr

		if err := c.cmd.Start(); err != nil {
			t.Fatal(err)
		}

		children = append(children, c)

		go func() {
			var out strings.Builder

			scanner := bufio.NewScanner(stdout)
			for scanner.Scan() {
				out.WriteString(scanner.Text() + "\n")
				if scanner.Text() == "reserve-ready" {
					close(c.ready)
				}
			}

			c.output <- out.String()
		}()
	}

	// Both children have built their admissions; release them together so the transactions overlap.
	for _, c := range children {
		select {
		case <-c.ready:
		case <-ctx.Done():
			t.Fatal("child not ready")
		}
	}

	for _, c := range children {
		if _, err := io.WriteString(c.stdin, "go\n"); err != nil {
			t.Fatal(err)
		}
		c.stdin.Close()
	}

	granted, refused := 0, 0

	for _, c := range children {
		output := <-c.output
		if err := c.cmd.Wait(); err != nil {
			t.Fatalf("child failed: %v\n%s", err, output)
		}

		switch {
		case strings.Contains(output, "reservation-result=granted"):
			granted++
		case strings.Contains(output, "reservation-result=busy"),
			strings.Contains(output, "reservation-result=collision"):
			refused++
		default:
			t.Fatalf("unexpected child output: %s", output)
		}
	}

	if granted != 1 || refused != 1 {
		t.Fatalf("cross-process uniqueness violated: granted=%d refused=%d", granted, refused)
	}

	// Ownership outlives both children.
	items, err := inspectReservationJournal(dir)
	if err != nil || len(items) != 1 || !items[0].recovered {
		t.Fatalf("child reservation lost: %v", err)
	}

	// A completely new process still sees the address as held.
	output, err := reservationChildCommand(t, ctx, "reserve", dir, 3).CombinedOutput()
	if err != nil || !strings.Contains(string(output), "reservation-result=collision") {
		t.Fatalf("persistent collision not enforced: %v\n%s", err, output)
	}
}
