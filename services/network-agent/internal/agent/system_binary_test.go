package agent

import (
	"os"
	"path/filepath"
	"testing"
)

func TestFindExecutableSkipsUnusableCandidates(t *testing.T) {
	notExecutable := t.TempDir()
	directory := t.TempDir()
	valid := t.TempDir()

	if err := os.WriteFile(filepath.Join(notExecutable, "ip"), []byte("#!/bin/sh\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	if err := os.Mkdir(filepath.Join(directory, "ip"), 0o755); err != nil {
		t.Fatal(err)
	}

	if err := os.WriteFile(filepath.Join(valid, "ip"), []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}

	got, err := findExecutable("ip", []string{notExecutable, directory, valid})
	if err != nil {
		t.Fatal(err)
	}

	if got != filepath.Join(valid, "ip") {
		t.Fatalf("unexpected executable: %s", got)
	}

	if _, err := findExecutable("ip", []string{notExecutable, directory}); err == nil {
		t.Fatal("unusable candidates were accepted")
	}
}
