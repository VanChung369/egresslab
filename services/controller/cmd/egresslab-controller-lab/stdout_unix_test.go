//go:build !windows

package main

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/VanChung369/egresslab/services/controller/internal/labruntime"
)

// A reader that closed stdout must not turn a committed release into a silent SIGPIPE exit.
func TestReleaseReportedOnClosedStdout(t *testing.T) {
	if os.Getenv("EGRESSLAB_CLOSED_STDOUT_TEST") == "1" {
		h, _, id := setupReleaseCLI(t)

		h.stdout = os.Stdout
		err := h.run(releaseCommand("Ubuntu-A", id)...)
		h.stdout = nil

		fmt.Fprintf(os.Stderr, "result %s: %v\n", labruntime.ErrorCode(err), err)
		fmt.Fprintf(os.Stderr, "held %d\n", len(reservationList(t, h).Reservations))

		return
	}

	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}

	// No reader is left: the child's first write to stdout meets a broken pipe.
	reader.Close()

	var stderr bytes.Buffer

	cmd := exec.Command(os.Args[0], "-test.run=^TestReleaseReportedOnClosedStdout$")
	cmd.Env = append(os.Environ(), "EGRESSLAB_CLOSED_STDOUT_TEST=1")
	cmd.Stdout, cmd.Stderr = writer, &stderr

	err = cmd.Run()
	writer.Close()

	if err != nil || !strings.Contains(stderr.String(), "result "+labruntime.CodeStateUncertain+": ") ||
		!strings.Contains(stderr.String(), "release committed") || !strings.Contains(stderr.String(), "held 0") {
		t.Fatalf("closed stdout: %v\n%s", err, stderr.String())
	}
}
