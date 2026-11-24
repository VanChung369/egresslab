package control

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"time"
)

// RuntimeStateFile sits next to state.json. It is owned by the lab CLI, not by the HTTP
// controller, and is decoded as strictly as state.json.
const RuntimeStateFile = "runtimes.json"

var runtimeTargetPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$`)

// TrustedRuntime is a Linux runtime the operator provisioned: its ID is what the helper reports,
// pinned to the provider and target it was reached through.
type TrustedRuntime struct {
	ID              string    `json:"id"`
	Provider        string    `json:"provider"`
	Target          string    `json:"target,omitempty"`
	PublicKeySHA256 string    `json:"public_key_sha256"`
	TrustedAt       time.Time `json:"trusted_at"`
}

// RuntimeBinding ties a profile to one runtime for good. Namespace and HelperEpoch describe the
// current lab and are valid only while that helper process runs.
type RuntimeBinding struct {
	ProfileID   string    `json:"profile_id"`
	RuntimeID   string    `json:"runtime_id"`
	Namespace   string    `json:"namespace,omitempty"`
	HelperEpoch string    `json:"helper_epoch,omitempty"`
	UpdatedAt   time.Time `json:"updated_at"`
}

type RuntimeState struct {
	path     string
	Runtimes []TrustedRuntime `json:"runtimes"`
	Bindings []RuntimeBinding `json:"bindings"`
}

type runtimeSnapshot struct {
	Version  int              `json:"version"`
	Runtimes []TrustedRuntime `json:"runtimes"`
	Bindings []RuntimeBinding `json:"bindings"`
}

func LoadRuntimeState(dataDir string) (*RuntimeState, error) {
	path := filepath.Join(dataDir, RuntimeStateFile)
	state := &RuntimeState{path: path, Runtimes: []TrustedRuntime{}, Bindings: []RuntimeBinding{}}

	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return state, nil
	}
	if err != nil {
		return nil, err
	}

	var snap runtimeSnapshot
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()

	if err := decoder.Decode(&snap); err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}

	var extra json.RawMessage
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("read %s: %w: trailing data", path, ErrInvalidState)
	}

	if snap.Version != 1 {
		return nil, fmt.Errorf("read %s: unsupported version %d", path, snap.Version)
	}

	if snap.Runtimes != nil {
		state.Runtimes = snap.Runtimes
	}

	if snap.Bindings != nil {
		state.Bindings = snap.Bindings
	}

	if err := state.validate(); err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}

	return state, nil
}

func (s *RuntimeState) validate() error {
	ids := map[string]bool{}
	targets := map[string]bool{}

	for i, rt := range s.Runtimes {
		where := fmt.Sprintf("runtimes[%d]", i)
		key := rt.Provider + "\x00" + rt.Target

		switch {
		case !ValidRuntimeID(rt.ID) || ids[rt.ID]:
			return invalidState(where, "malformed or duplicate id")
		case !validRuntimeTarget(rt.Provider, rt.Target) || targets[key]:
			return invalidState(where, "invalid or duplicate provider target")
		case !labFingerprintPattern.MatchString(rt.PublicKeySHA256) || rt.TrustedAt.IsZero():
			return invalidState(where, "missing key fingerprint or trust time")
		}

		ids[rt.ID] = true
		targets[key] = true
	}

	profiles := map[string]bool{}
	namespaces := map[string]bool{}

	for i, b := range s.Bindings {
		where := fmt.Sprintf("bindings[%d]", i)

		switch {
		case !ValidProfileID(b.ProfileID) || profiles[b.ProfileID]:
			return invalidState(where, "malformed or duplicate profile")
		case !ids[b.RuntimeID]:
			return invalidState(where, "unknown runtime")
		case (b.Namespace == "") != (b.HelperEpoch == ""):
			return invalidState(where, "namespace and helper epoch go together")
		case b.Namespace != "" && (!ValidLabNamespace(b.Namespace) || !labHelperIDPattern.MatchString(b.HelperEpoch) || namespaces[b.Namespace]):
			return invalidState(where, "invalid lab record")
		case b.UpdatedAt.IsZero():
			return invalidState(where, "missing updated_at")
		}

		profiles[b.ProfileID] = true
		if b.Namespace != "" {
			namespaces[b.Namespace] = true
		}
	}

	return nil
}

// validRuntimeTarget: a WSL distribution must be named; "the default distribution" can change.
func validRuntimeTarget(provider, target string) bool {
	switch provider {
	case "wsl", "lima":
		return runtimeTargetPattern.MatchString(target)
	case "native":
		return target == ""
	default:
		return false
	}
}

func (s *RuntimeState) RuntimeFor(provider, target string) (TrustedRuntime, bool) {
	for _, rt := range s.Runtimes {
		if rt.Provider == provider && rt.Target == target {
			return rt, true
		}
	}

	return TrustedRuntime{}, false
}

func (s *RuntimeState) Binding(profileID string) (RuntimeBinding, bool) {
	for _, b := range s.Bindings {
		if b.ProfileID == profileID {
			return b, true
		}
	}

	return RuntimeBinding{}, false
}

// Trust adds rt. The same runtime trusted again through the same target keeps its bindings; only a
// new public-key fingerprint (after a controller key replacement) is pinned.
func (s *RuntimeState) Trust(rt TrustedRuntime) error {
	for i, existing := range s.Runtimes {
		sameTarget := existing.Provider == rt.Provider && existing.Target == rt.Target

		switch {
		case existing.ID == rt.ID && sameTarget:
			if existing.PublicKeySHA256 != rt.PublicKeySHA256 {
				s.Runtimes[i].PublicKeySHA256, s.Runtimes[i].TrustedAt = rt.PublicKeySHA256, rt.TrustedAt
			}

			return s.validate()
		case existing.ID == rt.ID:
			return fmt.Errorf("runtime %s is already trusted as %s %s", rt.ID, existing.Provider, existing.Target)
		case sameTarget:
			return fmt.Errorf("%s %s is trusted as runtime %s; untrust it first", rt.Provider, rt.Target, existing.ID)
		}
	}

	s.Runtimes = append(s.Runtimes, rt)

	return s.validate()
}

// Untrust removes a runtime and every profile binding to it. Labs inside that runtime are not
// touched; the helper deletes them at shutdown, or egresslab-lab-recover after a crash.
func (s *RuntimeState) Untrust(id string) error {
	kept := s.Runtimes[:0:0]
	for _, rt := range s.Runtimes {
		if rt.ID != id {
			kept = append(kept, rt)
		}
	}

	if len(kept) == len(s.Runtimes) {
		return fmt.Errorf("runtime %s is not trusted", id)
	}

	bindings := s.Bindings[:0:0]
	for _, b := range s.Bindings {
		if b.RuntimeID != id {
			bindings = append(bindings, b)
		}
	}

	s.Runtimes, s.Bindings = kept, bindings

	return nil
}

func (s *RuntimeState) SetBinding(b RuntimeBinding) error {
	for i, existing := range s.Bindings {
		if existing.ProfileID == b.ProfileID {
			s.Bindings[i] = b
			return s.validate()
		}
	}

	s.Bindings = append(s.Bindings, b)

	return s.validate()
}

func (s *RuntimeState) RemoveBinding(profileID string) {
	kept := s.Bindings[:0:0]
	for _, b := range s.Bindings {
		if b.ProfileID != profileID {
			kept = append(kept, b)
		}
	}

	s.Bindings = kept
}

// Save writes atomically. Concurrent lab CLI runs are not coordinated.
func (s *RuntimeState) Save() error {
	if err := s.validate(); err != nil {
		return err
	}

	if err := os.MkdirAll(filepath.Dir(s.path), 0o700); err != nil {
		return err
	}

	contents, err := json.MarshalIndent(runtimeSnapshot{Version: 1, Runtimes: s.Runtimes, Bindings: s.Bindings}, "", "  ")
	if err != nil {
		return err
	}

	tmp, err := os.CreateTemp(filepath.Dir(s.path), ".runtimes-*.tmp")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())

	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}

	if _, err := tmp.Write(contents); err != nil {
		tmp.Close()
		return err
	}

	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}

	if err := tmp.Close(); err != nil {
		return err
	}

	if err := os.Rename(tmp.Name(), s.path); err != nil {
		return err
	}

	return syncDir(filepath.Dir(s.path))
}
