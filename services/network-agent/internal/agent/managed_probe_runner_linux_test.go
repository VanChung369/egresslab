//go:build linux

package agent

import (
	"errors"
	"os"
	"path/filepath"
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
