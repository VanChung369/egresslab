package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/VanChung369/egresslab/services/controller/internal/control"
	"github.com/VanChung369/egresslab/services/controller/internal/keystore"
	"github.com/VanChung369/egresslab/services/controller/internal/labruntime"
)

const (
	runtimeA = "runtime_000000000000000000000000000000aa"
	runtimeB = "runtime_000000000000000000000000000000bb"
	epoch1   = "helper_00000000000000000000000000000001"
	epoch2   = "helper_00000000000000000000000000000002"
	labNS    = "egresslab-lab-0123456789abcdef"
)

type memoryKeys struct {
	private ed25519.PrivateKey
	signs   int
}

func (k *memoryKeys) Initialize() error {
	if k.private != nil {
		return keystore.ErrKeyExists
	}

	_, k.private, _ = ed25519.GenerateKey(rand.Reader)

	return nil
}

func (k *memoryKeys) PublicKey() (ed25519.PublicKey, error) {
	if k.private == nil {
		return nil, keystore.ErrNoKey
	}

	return k.private.Public().(ed25519.PublicKey), nil
}

func (k *memoryKeys) Sign(message []byte) ([]byte, error) {
	k.signs++
	return ed25519.Sign(k.private, message), nil
}

// fakeRuntime is one Linux runtime: its helper's identity and lab registry.
type fakeRuntime struct {
	kind, target string
	info         control.LabHelperInfo
	labs         map[string]string // profile -> namespace
	namespace    string            // CreateLab's namespace; empty: labNS
	createErr    error
	created      []control.LabCapability
	calls        []string
	afterChange  func() // runs after a successful CreateLab or DeleteLab

	stage            control.LabStageInfo
	tunnelProfile    string
	tunnelGeneration string
	tunnelCalls      []control.LabCapability
	tunnelErr        error

	probeCalls []control.LabCapability
	probeErr   error
	probeStale bool

	multiProbeCalls []control.LabCapability
	multiProbeErr   error
	multiPolicyErr  error
	multiPolicyEdit func(*control.LabMultiProbePolicy)
	multiProbeEdit  func(*control.LabMultiProbeInfo)
	multiTargetEdit func(*control.LabMultiProbeTarget)

	lastMultiProbe *control.LabMultiProbeInfo
	candidateCalls []control.LabCapability
	candidateErr   error

	lastCandidate *control.LabCandidateInfo
	prepareCalls  []control.LabCapability
	prepareErr    error
}

func (f *fakeRuntime) HelperInfo(context.Context) (control.LabHelperInfo, error) {
	f.calls = append(f.calls, "HelperInfo")
	return f.info, nil
}

func (f *fakeRuntime) ListLabs(context.Context) ([]control.LabInfo, error) {
	f.calls = append(f.calls, "ListLabs")

	var labs []control.LabInfo
	for profile, ns := range f.labs {
		labs = append(labs, control.LabInfo{ProfileID: profile, Namespace: ns, State: f.stateOf(profile)})
	}

	return labs, nil
}

func (f *fakeRuntime) CreateLab(_ context.Context, profileID string, c control.LabCapability) (control.LabInfo, error) {
	f.calls = append(f.calls, "CreateLab")
	f.created = append(f.created, c)

	if f.createErr != nil {
		return control.LabInfo{}, f.createErr
	}

	ns := labNS
	if f.namespace != "" {
		ns = f.namespace
	}

	f.labs[profileID] = ns

	if f.afterChange != nil {
		f.afterChange()
	}

	return control.LabInfo{ProfileID: profileID, Namespace: ns, State: control.LabSealed}, nil
}

func (f *fakeRuntime) lab(op, p, n, state string) (control.LabInfo, error) {
	f.calls = append(f.calls, op)

	if f.labs[p] != n {
		return control.LabInfo{}, labruntime.Errorf(labruntime.CodeLabNotFound, "no lab for this profile")
	}

	if state == control.LabDeleted {
		delete(f.labs, p)

		if f.tunnelProfile == p {
			f.tunnelProfile, f.tunnelGeneration = "", ""
		}

		if f.afterChange != nil {
			f.afterChange()
		}
	}

	return control.LabInfo{ProfileID: p, Namespace: n, State: state}, nil
}

func (f *fakeRuntime) stateOf(profileID string) string {
	if f.tunnelProfile == profileID {
		return control.LabTunnelConfigured
	}

	return control.LabSealed
}

func (f *fakeRuntime) VerifyLab(_ context.Context, p, n string) (control.LabInfo, error) {
	return f.lab("VerifyLab", p, n, f.stateOf(p))
}

func (f *fakeRuntime) StageInfo(_ context.Context, profileID string) (control.LabStageInfo, error) {
	f.calls = append(f.calls, "StageInfo")

	if f.stage.ProfileID != profileID {
		return control.LabStageInfo{}, labruntime.Errorf(labruntime.CodeStageNotFound, "no WireGuard stage")
	}

	return f.stage, nil
}

func (f *fakeRuntime) ConnectTunnel(_ context.Context, profileID, namespace, stageID string, c control.LabCapability) (control.LabInfo, error) {
	f.calls = append(f.calls, "ConnectTunnel")
	f.tunnelCalls = append(f.tunnelCalls, c)

	if f.tunnelErr != nil {
		return control.LabInfo{}, f.tunnelErr
	}

	if f.labs[profileID] != namespace || f.stage.ProfileID != profileID || f.stage.StageID != stageID || !f.stage.Compatible {
		return control.LabInfo{}, labruntime.Errorf(labruntime.CodeOwnershipMismatch, "invalid tunnel binding")
	}

	if f.tunnelProfile != "" {
		return control.LabInfo{}, labruntime.Errorf(labruntime.CodeLabBusy, "tunnel slot held")
	}

	f.tunnelProfile = profileID
	f.tunnelGeneration = fmt.Sprintf("tunnelgen_%032x", len(f.tunnelCalls))

	return control.LabInfo{ProfileID: profileID, Namespace: namespace, State: control.LabTunnelConfigured}, nil
}

func (f *fakeRuntime) Disconnect(_ context.Context, p, n string) (control.LabInfo, error) {
	lab, err := f.lab("Disconnect", p, n, control.LabSealed)
	if err == nil && f.tunnelProfile == p {
		f.tunnelProfile, f.tunnelGeneration = "", ""
	}

	return lab, err
}

func (f *fakeRuntime) DeleteLab(_ context.Context, p, n string) (control.LabInfo, error) {
	return f.lab("DeleteLab", p, n, control.LabDeleted)
}

func (f *fakeRuntime) Name() string                          { return f.kind + ":" + f.target }
func (f *fakeRuntime) Kind() string                          { return f.kind }
func (f *fakeRuntime) Target() string                        { return f.target }
func (f *fakeRuntime) Detect(context.Context) error          { return nil }
func (f *fakeRuntime) Start(context.Context) error           { return labruntime.ErrNotImplemented }
func (f *fakeRuntime) Stop(context.Context) error            { return labruntime.ErrNotImplemented }
func (f *fakeRuntime) Transport() labruntime.HelperTransport { return f }
func (f *fakeRuntime) Status(context.Context) (labruntime.Status, error) {
	return labruntime.Status{Provider: f.Name(), Reachable: true}, nil
}
func (f *fakeRuntime) Capabilities(context.Context) (labruntime.Capabilities, error) {
	return labruntime.Capabilities{Provider: f.Name(), AuthorizationConfigured: true, LabLifecycle: true}, nil
}

type harness struct {
	t        *testing.T
	dir      string
	keys     *memoryKeys
	runtimes map[string]*fakeRuntime // "-wsl-distro" value -> runtime
	reached  int
	out      bytes.Buffer
	profile  control.RoutingProfile
	now      func() time.Time // nil: a fixed time
	stdout   io.Writer        // nil: out
}

func newHarness(t *testing.T) *harness {
	t.Helper()

	dir := t.TempDir()
	t.Setenv("EGRESSLAB_DATA_DIR", dir)

	store, err := control.NewStore(filepath.Join(dir, "state.json"))
	if err != nil {
		t.Fatal(err)
	}

	profile, err := store.CreateProfile("Lab profile")
	if err != nil {
		t.Fatal(err)
	}

	h := &harness{t: t, dir: dir, keys: &memoryKeys{}, profile: profile, runtimes: map[string]*fakeRuntime{}}
	if err := h.keys.Initialize(); err != nil {
		t.Fatal(err)
	}

	h.runtimes["Ubuntu-A"] = h.newRuntime("Ubuntu-A", runtimeA)
	h.runtimes["Ubuntu-B"] = h.newRuntime("Ubuntu-B", runtimeB)

	return h
}

func (h *harness) newRuntime(target, id string) *fakeRuntime {
	public, _ := h.keys.PublicKey()

	return &fakeRuntime{kind: "wsl", target: target, labs: map[string]string{}, info: control.LabHelperInfo{
		AuthorizationConfigured: true, HelperID: epoch1, PublicKeySHA256: control.LabPublicKeySHA256(public), RuntimeID: id,
	}}
}

func (h *harness) run(args ...string) error {
	h.out.Reset()

	return run(args, deps{
		openKeys: func(string) (keystore.KeyStore, error) { return h.keys, nil },
		newRuntime: func(_ string, opts labruntime.Options) (labruntime.RuntimeProvider, error) {
			h.reached++
			if rt, ok := h.runtimes[opts.WSLDistro]; ok {
				return rt, nil
			}
			return &fakeRuntime{kind: "wsl", target: opts.WSLDistro, labs: map[string]string{}}, nil
		},
		now: func() time.Time {
			if h.now != nil {
				return h.now()
			}
			return time.Unix(1795500000, 0)
		},
		stdout: h.writer(),
		// Never the real per-user authority.
		reservationRoot: func() (string, error) { return h.dir, nil },
	})
}

func (h *harness) writer() io.Writer {
	if h.stdout != nil {
		return h.stdout
	}

	return &h.out
}

func (h *harness) mustRun(args ...string) {
	h.t.Helper()

	if err := h.run(args...); err != nil {
		h.t.Fatalf("%q: %v", args, err)
	}
}

func (h *harness) requireCode(code string, args ...string) {
	h.t.Helper()

	if err := h.run(args...); labruntime.ErrorCode(err) != code {
		h.t.Fatalf("%q: got %v, want %s", args, err, code)
	}
}

func (h *harness) binding() (control.RuntimeBinding, bool) {
	h.t.Helper()

	state, err := control.LoadRuntimeState(h.dir)
	if err != nil {
		h.t.Fatal(err)
	}

	return state.Binding(h.profile.ID)
}

func TestMutationsNeedApproval(t *testing.T) {
	h := newHarness(t)

	for _, args := range [][]string{
		{"create-lab", h.profile.ID},
		{"delete-lab", h.profile.ID, labNS},
		{"trust-runtime"},
		{"untrust-runtime", runtimeA},
		{"unbind-profile", h.profile.ID},
	} {
		if err := h.run(append([]string{"-wsl-distro", "Ubuntu-A"}, args...)...); err == nil ||
			!strings.Contains(err.Error(), "requires -approve") {
			t.Fatalf("%q: %v", args, err)
		}
	}

	if h.reached != 0 {
		t.Fatal("runtime reached without approval")
	}
}

func TestTrustRuntime(t *testing.T) {
	h := newHarness(t)

	h.requireCode(labruntime.CodeInvalidRequest, "-approve", "trust-runtime")

	otherKey := h.newRuntime("Other-key", "runtime_000000000000000000000000000000cc")
	otherKey.info.PublicKeySHA256 = hex.EncodeToString(make([]byte, 32))
	h.runtimes["Other-key"] = otherKey
	h.requireCode(labruntime.CodeRuntimeUntrusted, "-approve", "-wsl-distro", "Other-key", "trust-runtime")

	noID := h.newRuntime("No-id", "")
	h.runtimes["No-id"] = noID
	h.requireCode(labruntime.CodeRuntimeUntrusted, "-approve", "-wsl-distro", "No-id", "trust-runtime")

	h.mustRun("-approve", "-wsl-distro", "Ubuntu-A", "trust-runtime")
	h.mustRun("-approve", "-wsl-distro", "Ubuntu-A", "trust-runtime")

	state, _ := control.LoadRuntimeState(h.dir)
	if rt, ok := state.RuntimeFor("wsl", "Ubuntu-A"); !ok || rt.ID != runtimeA || len(state.Runtimes) != 1 {
		t.Fatalf("trusted runtimes: %+v", state.Runtimes)
	}

	// The distribution now answers as another installation.
	h.runtimes["Ubuntu-A"].info.RuntimeID = runtimeB
	h.requireCode(labruntime.CodeRuntimeUntrusted, "-approve", "-wsl-distro", "Ubuntu-A", "trust-runtime")
}

func TestCreateLabNeedsTrustedRuntime(t *testing.T) {
	h := newHarness(t)

	h.requireCode(labruntime.CodeRuntimeUntrusted, "-approve", "-wsl-distro", "Ubuntu-A", "create-lab", h.profile.ID)
	h.requireCode(labruntime.CodeRuntimeUntrusted, "-approve", "create-lab", h.profile.ID)

	h.mustRun("-approve", "-wsl-distro", "Ubuntu-A", "trust-runtime")
	h.runtimes["Ubuntu-A"].info.RuntimeID = runtimeB
	h.requireCode(labruntime.CodeRuntimeUntrusted, "-approve", "-wsl-distro", "Ubuntu-A", "create-lab", h.profile.ID)

	if len(h.runtimes["Ubuntu-A"].created) != 0 {
		t.Fatal("CreateLab sent to an untrusted runtime")
	}
}

func TestCreateLabRecordsBinding(t *testing.T) {
	h := newHarness(t)
	a := h.runtimes["Ubuntu-A"]
	h.mustRun("-approve", "-wsl-distro", "Ubuntu-A", "trust-runtime")
	h.mustRun("-approve", "-wsl-distro", "Ubuntu-A", "create-lab", h.profile.ID)

	b, ok := h.binding()
	if !ok || b.RuntimeID != runtimeA || b.Namespace != labNS || b.HelperEpoch != epoch1 {
		t.Fatalf("binding: %+v", b)
	}

	capability := a.created[0]
	raw, _ := json.Marshal(capability.Claims)
	signature, _ := base64.RawURLEncoding.DecodeString(capability.Signature)
	public, _ := h.keys.PublicKey()

	if capability.Claims.HelperID != epoch1 ||
		!ed25519.Verify(public, append([]byte("egresslab/helper-capability/v1\x00"), raw...), signature) {
		t.Fatal("capability does not verify for the current epoch")
	}

	h.requireCode(labruntime.CodeLabExists, "-approve", "-wsl-distro", "Ubuntu-A", "create-lab", h.profile.ID)

	// After a helper restart the old record is stale (a normal stop deleted the lab): creation
	// goes ahead, and the helper's recovery gate covers a crash.
	a.info.HelperID = epoch2
	delete(a.labs, h.profile.ID)
	h.mustRun("-approve", "-wsl-distro", "Ubuntu-A", "create-lab", h.profile.ID)

	if b, _ := h.binding(); b.HelperEpoch != epoch2 || len(a.created) != 2 {
		t.Fatalf("after restart: %+v", b)
	}
}

func TestRecordSaveFailureIsReported(t *testing.T) {
	h := newHarness(t)
	a := h.runtimes["Ubuntu-A"]
	h.mustRun("-approve", "-wsl-distro", "Ubuntu-A", "trust-runtime")

	// A directory in place of runtimes.json makes the save after the helper call fail.
	path := filepath.Join(h.dir, control.RuntimeStateFile)
	var saved []byte

	a.afterChange = func() {
		var err error
		if saved, err = os.ReadFile(path); err != nil {
			t.Fatal(err)
		}

		if err := errors.Join(os.Remove(path), os.MkdirAll(filepath.Join(path, "blocked"), 0o700)); err != nil {
			t.Fatal(err)
		}
	}

	restore := func() {
		if err := errors.Join(os.RemoveAll(path), os.WriteFile(path, saved, 0o600)); err != nil {
			t.Fatal(err)
		}
	}

	err := h.run("-approve", "-wsl-distro", "Ubuntu-A", "create-lab", h.profile.ID)
	if err == nil || !strings.Contains(err.Error(), "record was not saved") {
		t.Fatalf("create-lab: %v", err)
	}

	restore()

	err = h.run("-approve", "-wsl-distro", "Ubuntu-A", "delete-lab", h.profile.ID, labNS)
	if err == nil || !strings.Contains(err.Error(), "record was not saved") {
		t.Fatalf("delete-lab: %v", err)
	}

	restore()
}

func TestProfileStaysOnItsRuntime(t *testing.T) {
	h := newHarness(t)
	h.mustRun("-approve", "-wsl-distro", "Ubuntu-A", "trust-runtime")
	h.mustRun("-approve", "-wsl-distro", "Ubuntu-B", "trust-runtime")
	h.mustRun("-approve", "-wsl-distro", "Ubuntu-A", "create-lab", h.profile.ID)

	h.requireCode(labruntime.CodeOwnershipMismatch, "-approve", "-wsl-distro", "Ubuntu-B", "create-lab", h.profile.ID)
	h.requireCode(labruntime.CodeOwnershipMismatch, "-approve", "-wsl-distro", "Ubuntu-B", "delete-lab", h.profile.ID, labNS)
	h.requireCode(labruntime.CodeOwnershipMismatch, "-approve", "-wsl-distro", "Ubuntu-B", "unbind-profile", h.profile.ID)

	if len(h.runtimes["Ubuntu-B"].created) != 0 {
		t.Fatal("profile used on a second runtime")
	}

	h.requireCode(labruntime.CodeOwnershipMismatch, "-wsl-distro", "Ubuntu-A", "verify-lab", h.profile.ID, "egresslab-lab-ffffffffffffffff")
}

func TestUncertainCreateCanBeCleanedUp(t *testing.T) {
	h := newHarness(t)
	a := h.runtimes["Ubuntu-A"]
	h.mustRun("-approve", "-wsl-distro", "Ubuntu-A", "trust-runtime")

	// The helper created the lab, but the answer was lost.
	a.createErr = labruntime.Errorf(labruntime.CodeRuntimeUnavailable, "wsl: connection reset")
	a.labs[h.profile.ID] = labNS

	h.requireCode(labruntime.CodeStateUncertain, "-approve", "-wsl-distro", "Ubuntu-A", "create-lab", h.profile.ID)

	if b, ok := h.binding(); !ok || b.RuntimeID != runtimeA || b.Namespace != "" {
		t.Fatalf("binding after an uncertain create: %+v %t", b, ok)
	}

	// verify-lab recovers the record from the helper's registry; delete-lab needs no record.
	h.mustRun("-wsl-distro", "Ubuntu-A", "verify-lab", h.profile.ID, labNS)
	if b, _ := h.binding(); b.Namespace != labNS || b.HelperEpoch != epoch1 {
		t.Fatalf("record not recovered: %+v", b)
	}

	h.mustRun("-approve", "-wsl-distro", "Ubuntu-A", "delete-lab", h.profile.ID, labNS)
	if b, _ := h.binding(); b.Namespace != "" || b.RuntimeID != runtimeA {
		t.Fatalf("after delete: %+v", b)
	}

	// A definite refusal keeps the helper's code.
	a.createErr = labruntime.Errorf(labruntime.CodeRecoveryRequired, "leftover lab resources")
	h.requireCode(labruntime.CodeRecoveryRequired, "-approve", "-wsl-distro", "Ubuntu-A", "create-lab", h.profile.ID)
}

func TestUnbindAndUntrust(t *testing.T) {
	h := newHarness(t)
	h.mustRun("-approve", "-wsl-distro", "Ubuntu-A", "trust-runtime")
	h.mustRun("-approve", "-wsl-distro", "Ubuntu-A", "create-lab", h.profile.ID)

	h.requireCode(labruntime.CodeLabExists, "-approve", "-wsl-distro", "Ubuntu-A", "unbind-profile", h.profile.ID)

	h.mustRun("-approve", "-wsl-distro", "Ubuntu-A", "delete-lab", h.profile.ID, labNS)
	h.mustRun("-approve", "-wsl-distro", "Ubuntu-A", "unbind-profile", h.profile.ID)

	if _, ok := h.binding(); ok {
		t.Fatal("binding kept after unbind")
	}

	// Untrust removes a runtime and its bindings, but not the labs inside it.
	h.mustRun("-approve", "-wsl-distro", "Ubuntu-A", "create-lab", h.profile.ID)
	h.mustRun("-approve", "untrust-runtime", runtimeA)

	if _, ok := h.binding(); ok {
		t.Fatal("binding kept after untrust")
	}

	h.requireCode(labruntime.CodeInvalidRequest, "-approve", "untrust-runtime", runtimeA)

	// Trusted again, the unbound lab is still deletable: the helper's registry decides.
	h.mustRun("-approve", "-wsl-distro", "Ubuntu-A", "trust-runtime")
	h.mustRun("-approve", "-wsl-distro", "Ubuntu-A", "delete-lab", h.profile.ID, labNS)

	if _, ok := h.binding(); ok {
		t.Fatal("delete-lab bound an unbound profile")
	}

	h.requireCode(labruntime.CodeLabNotFound, "-approve", "-wsl-distro", "Ubuntu-A", "delete-lab", h.profile.ID, labNS)
}

func TestCreateLabRefusals(t *testing.T) {
	h := newHarness(t)
	a := h.runtimes["Ubuntu-A"]
	h.mustRun("-approve", "-wsl-distro", "Ubuntu-A", "trust-runtime")

	a.info.PublicKeySHA256 = hex.EncodeToString(make([]byte, 32))
	h.requireCode(labruntime.CodeRuntimeUntrusted, "-approve", "-wsl-distro", "Ubuntu-A", "create-lab", h.profile.ID)

	if err := h.run("-approve", "-wsl-distro", "Ubuntu-A", "create-lab", "profile_ffffffffffffffff"); err == nil ||
		!strings.Contains(err.Error(), "profile not found") {
		t.Fatalf("unknown profile: %v", err)
	}

	if len(a.created) != 0 {
		t.Fatal("CreateLab sent despite refusal")
	}
}

func TestKeyCommands(t *testing.T) {
	h := newHarness(t)
	h.keys.private = nil

	if err := h.run("public-key"); !errors.Is(err, keystore.ErrNoKey) {
		t.Fatalf("public key before init: %v", err)
	}

	h.mustRun("init-key")

	public, _ := h.keys.PublicKey()
	if strings.TrimSpace(h.out.String()) != hex.EncodeToString(public) {
		t.Fatalf("printed %q", h.out.String())
	}

	if err := h.run("init-key"); !errors.Is(err, keystore.ErrKeyExists) {
		t.Fatalf("second init: %v", err)
	}

	h.mustRun("runtimes")

	if h.reached != 0 {
		t.Fatal("key commands reached the runtime")
	}
}

func TestBadArguments(t *testing.T) {
	h := newHarness(t)

	for _, args := range [][]string{
		nil,
		{"helper-info", "extra"},
		{"-approve", "create-lab", "profile_x"},
		{"verify-lab", "profile_0123456789abcdef", "../default"},
		{"-approve", "untrust-runtime", "runtime_x"},
		{"connect-tunnel"},
		{"-approve", "connect-tunnel", "profile_0123456789abcdef", "egresslab-lab-0123456789abcdef"},
		{"-approve", "connect-tunnel", "profile_0123456789abcdef", "egresslab-lab-0123456789abcdef", "wgstage_x"},
		{"-approve", "disconnect", "profile_0123456789abcdef", "egresslab-lab-x"},
		{"stage-info"},
		{"stage-info", "profile_x"},
		{"-runtime"},
	} {
		if err := h.run(args...); err == nil {
			t.Errorf("%q accepted", args)
		}
	}

	if h.reached != 0 {
		t.Fatal("invalid arguments reached the runtime")
	}
}
