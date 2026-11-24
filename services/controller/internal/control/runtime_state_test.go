package control

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const (
	testRuntimeA = "runtime_000000000000000000000000000000aa"
	testRuntimeB = "runtime_000000000000000000000000000000bb"
)

func trusted(id, provider, target string) TrustedRuntime {
	return TrustedRuntime{ID: id, Provider: provider, Target: target, PublicKeySHA256: strings.Repeat("ab", 32), TrustedAt: time.Unix(1, 0)}
}

func TestRuntimeStateRoundTrip(t *testing.T) {
	dir := t.TempDir()

	state, err := LoadRuntimeState(dir)
	if err != nil || len(state.Runtimes) != 0 {
		t.Fatalf("empty state: %v", err)
	}

	if err := state.Trust(trusted(testRuntimeA, "wsl", "Ubuntu-22.04")); err != nil {
		t.Fatal(err)
	}

	if err := state.SetBinding(RuntimeBinding{ProfileID: "profile_0123456789abcdef", RuntimeID: testRuntimeA,
		Namespace: "egresslab-lab-0123456789abcdef", HelperEpoch: "helper_0123456789abcdef0123456789abcdef", UpdatedAt: time.Unix(2, 0)}); err != nil {
		t.Fatal(err)
	}

	if err := state.Save(); err != nil {
		t.Fatal(err)
	}

	loaded, err := LoadRuntimeState(dir)
	if err != nil {
		t.Fatal(err)
	}

	if b, ok := loaded.Binding("profile_0123456789abcdef"); !ok || b.RuntimeID != testRuntimeA || b.Namespace == "" {
		t.Fatalf("binding: %+v", b)
	}

	// Trusting again after a controller key replacement pins the new key and keeps the bindings.
	again := trusted(testRuntimeA, "wsl", "Ubuntu-22.04")
	again.PublicKeySHA256, again.TrustedAt = strings.Repeat("cd", 32), time.Unix(3, 0)

	if err := loaded.Trust(again); err != nil || len(loaded.Runtimes) != 1 || len(loaded.Bindings) != 1 {
		t.Fatalf("trust again: %v %+v", err, loaded)
	}

	if rt, _ := loaded.RuntimeFor("wsl", "Ubuntu-22.04"); rt.PublicKeySHA256 != again.PublicKeySHA256 || !rt.TrustedAt.Equal(again.TrustedAt) {
		t.Fatalf("new key not pinned: %+v", rt)
	}

	if err := loaded.Untrust(testRuntimeA); err != nil || len(loaded.Bindings) != 0 {
		t.Fatalf("untrust: %v %+v", err, loaded.Bindings)
	}
}

func TestRuntimeStateRefusesConflicts(t *testing.T) {
	state, _ := LoadRuntimeState(t.TempDir())

	if err := state.Trust(trusted(testRuntimeA, "wsl", "")); err == nil {
		t.Error("WSL runtime without a named distribution trusted")
	}

	if err := state.Trust(trusted(testRuntimeA, "native", "x")); err == nil {
		t.Error("native runtime with a target trusted")
	}

	state, _ = LoadRuntimeState(t.TempDir())
	if err := state.Trust(trusted(testRuntimeA, "wsl", "Ubuntu-22.04")); err != nil {
		t.Fatal(err)
	}

	if err := state.Trust(trusted(testRuntimeB, "wsl", "Ubuntu-22.04")); err == nil {
		t.Error("second runtime trusted for the same target")
	}

	if err := state.Trust(trusted(testRuntimeA, "lima", "egresslab")); err == nil {
		t.Error("one runtime trusted under two targets")
	}

	if err := state.SetBinding(RuntimeBinding{ProfileID: "profile_0123456789abcdef", RuntimeID: testRuntimeB, UpdatedAt: time.Unix(1, 0)}); err == nil {
		t.Error("binding to an untrusted runtime accepted")
	}

	if err := state.SetBinding(RuntimeBinding{ProfileID: "profile_0123456789abcdef", RuntimeID: testRuntimeA,
		Namespace: "egresslab-lab-0123456789abcdef", UpdatedAt: time.Unix(1, 0)}); err == nil {
		t.Error("namespace without a helper epoch accepted")
	}
}

func TestRuntimeStateRejectsBadFiles(t *testing.T) {
	for name, content := range map[string]string{
		"unknown field":    `{"version":1,"runtimes":[],"bindings":[],"admin":true}`,
		"bad version":      `{"version":2,"runtimes":[],"bindings":[]}`,
		"trailing data":    `{"version":1,"runtimes":[],"bindings":[]}{}`,
		"dangling binding": `{"version":1,"runtimes":[],"bindings":[{"profile_id":"profile_0123456789abcdef","runtime_id":"` + testRuntimeA + `","updated_at":"2026-01-01T00:00:00Z"}]}`,
	} {
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, RuntimeStateFile), []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}

		if _, err := LoadRuntimeState(dir); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}
