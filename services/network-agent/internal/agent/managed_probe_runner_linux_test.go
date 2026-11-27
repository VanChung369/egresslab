//go:build linux

package agent

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

func TestVerifyProbeBinary(t *testing.T) {
	userFile := filepath.Join(t.TempDir(), "egresslab-probe")
	if err := os.WriteFile(userFile, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}

	for name, path := range map[string]string{
		"relative":    "egresslab-probe",
		"missing":     "/nonexistent/egresslab-probe",
		"directory":   "/usr/bin",
		"user-owned":  userFile,
		"in temp dir": filepath.Join(os.TempDir(), "egresslab-probe"),
	} {
		if os.Geteuid() == 0 && name == "user-owned" {
			continue
		}

		if err := verifyProbeBinary(path); !errors.Is(err, ErrManagedProbeUnavailable) {
			t.Errorf("%s accepted: %v", name, err)
		}
	}

	info, err := os.Lstat("/usr/bin/true")
	if err != nil || !info.Mode().IsRegular() || info.Sys().(*syscall.Stat_t).Uid != 0 {
		t.Skip("no root-owned /usr/bin/true to check the accepting path")
	}

	if err := verifyProbeBinary("/usr/bin/true"); err != nil {
		t.Fatalf("root-owned system binary refused: %v", err)
	}
}

func TestManagedProbeFailureReason(t *testing.T) {
	for stderr, want := range map[string]string{
		"HTTPS probe failed\n":                      "HTTPS_REQUEST_FAILED",
		"HTTPS probe got no answer\n":               "HTTPS_NO_ANSWER",
		"HTTPS probe source unavailable\n":          "HTTPS_SOURCE_UNAVAILABLE",
		"HTTPS probe reply incomplete\n":            "HTTPS_REPLY_INCOMPLETE",
		"HTTPS probe TLS failed\n":                  "HTTPS_TLS_FAILED",
		"HTTPS probe unexpected status\n":           "HTTPS_UNEXPECTED_STATUS",
		"HTTPS probe invalid response\n":            "HTTPS_INVALID_RESPONSE",
		"probe must not run as root\n":              "WORKER_PRIVILEGE_CHECK_FAILED",
		"probe must have no supplementary groups\n": "WORKER_PRIVILEGE_CHECK_FAILED",
		"unexpected probe privileges\n":             "WORKER_PRIVILEGE_CHECK_FAILED",
		"incomplete probe privilege information\n":  "WORKER_PRIVILEGE_CHECK_FAILED",
		"cannot inspect probe privileges\n":         "WORKER_STATUS_UNAVAILABLE",
		"invalid probe arguments\n":                 "WORKER_INVALID_REQUEST",
		"unknown probe source\n":                    "WORKER_INVALID_REQUEST",
		"invalid probe destination\n":               "WORKER_INVALID_REQUEST",
		"":                                          "WORKER_EXECUTION_FAILED",
		"secret token=abc\n":                        "WORKER_EXECUTION_FAILED",
	} {
		if got := managedProbeFailureReason(stderr); got != want {
			t.Fatalf("%q: got %s, want %s", stderr, got, want)
		}
	}
}

func TestManagedProbeWorkerError(t *testing.T) {
	silent := managedProbeWorkerError("HTTPS probe got no answer\n")
	if !errors.Is(silent, ErrManagedProbeFailed) || !errors.Is(silent, ErrManagedProbeNoAnswer) ||
		!strings.Contains(silent.Error(), "HTTPS_NO_ANSWER") {
		t.Fatalf("worker without an answer: %v", silent)
	}

	for _, stderr := range []string{"HTTPS probe failed\n", "", "unknown probe source\n", "HTTPS probe TLS failed\n",
		"HTTPS probe source unavailable: 503\n"} {
		if err := managedProbeWorkerError(stderr); !errors.Is(err, ErrManagedProbeFailed) ||
			errors.Is(err, ErrManagedProbeNoAnswer) {
			t.Fatalf("%q: %v", stderr, err)
		}
	}
}

// Every reason the worker reports reaches the helper as the same reason, with the same consequence.
func TestManagedProbeReasonsRoundTrip(t *testing.T) {
	for reason, known := range managedProbeReasons {
		line := ManagedProbeFailureLine(probeSourceFailure(reason, errors.New("source detail")))
		if line != known.line || strings.Contains(line, "source detail") {
			t.Fatalf("%s: worker line %q", reason, line)
		}

		err := managedProbeWorkerError(line + "\n")
		if managedProbeReasonOf(err) != reason || errors.Is(err, ErrManagedProbeNoAnswer) != known.noAnswer ||
			!errors.Is(err, ErrManagedProbeFailed) || !strings.Contains(err.Error(), reason) {
			t.Fatalf("%s: helper error %v", reason, err)
		}
	}
}
