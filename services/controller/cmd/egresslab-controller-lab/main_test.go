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
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/VanChung369/egresslab/services/controller/internal/control"
	"github.com/VanChung369/egresslab/services/controller/internal/keystore"
	"github.com/VanChung369/egresslab/services/controller/internal/labruntime"
)

type memoryKeys struct{ private ed25519.PrivateKey }

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
	return ed25519.Sign(k.private, message), nil
}

type fakeTransport struct {
	info    control.LabHelperInfo
	created []control.LabCapability
	calls   []string
}

func (f *fakeTransport) HelperInfo(context.Context) (control.LabHelperInfo, error) {
	f.calls = append(f.calls, "HelperInfo")
	return f.info, nil
}

func (f *fakeTransport) ListLabs(context.Context) ([]control.LabInfo, error) {
	f.calls = append(f.calls, "ListLabs")
	return nil, nil
}

func (f *fakeTransport) CreateLab(_ context.Context, profileID string, c control.LabCapability) (control.LabInfo, error) {
	f.calls = append(f.calls, "CreateLab")
	f.created = append(f.created, c)
	return control.LabInfo{ProfileID: profileID, Namespace: "egresslab-lab-0123456789abcdef", State: control.LabSealed}, nil
}

func (f *fakeTransport) VerifyLab(_ context.Context, p, n string) (control.LabInfo, error) {
	f.calls = append(f.calls, "VerifyLab")
	return control.LabInfo{ProfileID: p, Namespace: n, State: control.LabSealed}, nil
}

func (f *fakeTransport) DeleteLab(_ context.Context, p, n string) (control.LabInfo, error) {
	f.calls = append(f.calls, "DeleteLab")
	return control.LabInfo{ProfileID: p, Namespace: n, State: control.LabDeleted}, nil
}

type fakeProvider struct{ transport *fakeTransport }

func (fakeProvider) Name() string                            { return "fake" }
func (fakeProvider) Detect(context.Context) error            { return nil }
func (fakeProvider) Start(context.Context) error             { return labruntime.ErrNotImplemented }
func (fakeProvider) Stop(context.Context) error              { return labruntime.ErrNotImplemented }
func (p fakeProvider) Transport() labruntime.HelperTransport { return p.transport }
func (fakeProvider) Status(context.Context) (labruntime.Status, error) {
	return labruntime.Status{Provider: "fake", Reachable: true}, nil
}
func (fakeProvider) Capabilities(context.Context) (labruntime.Capabilities, error) {
	return labruntime.Capabilities{Provider: "fake", AuthorizationConfigured: true, LabLifecycle: true}, nil
}

type harness struct {
	keys      *memoryKeys
	transport *fakeTransport
	runtimes  int
	out       bytes.Buffer
	profile   control.RoutingProfile
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

	h := &harness{keys: &memoryKeys{}, transport: &fakeTransport{}, profile: profile}
	if err := h.keys.Initialize(); err != nil {
		t.Fatal(err)
	}

	public, _ := h.keys.PublicKey()
	h.transport.info = control.LabHelperInfo{
		AuthorizationConfigured: true,
		HelperID:                "helper_0123456789abcdef0123456789abcdef",
		PublicKeySHA256:         control.LabPublicKeySHA256(public),
	}

	return h
}

func (h *harness) run(args ...string) error {
	h.out.Reset()

	return run(args, deps{
		openKeys: func(string) (keystore.KeyStore, error) { return h.keys, nil },
		newRuntime: func(string, labruntime.Options) (labruntime.RuntimeProvider, error) {
			h.runtimes++
			return fakeProvider{h.transport}, nil
		},
		now:    func() time.Time { return time.Unix(1795500000, 0) },
		stdout: &h.out,
	})
}

func TestMutationsNeedApproval(t *testing.T) {
	h := newHarness(t)

	for _, args := range [][]string{
		{"create-lab", h.profile.ID},
		{"delete-lab", h.profile.ID, "egresslab-lab-0123456789abcdef"},
	} {
		if err := h.run(args...); err == nil || !strings.Contains(err.Error(), "requires -approve") {
			t.Fatalf("%q: %v", args, err)
		}
	}

	if h.runtimes != 0 || len(h.transport.calls) != 0 {
		t.Fatal("runtime reached without approval")
	}
}

func TestCreateLabSignsForCurrentHelper(t *testing.T) {
	h := newHarness(t)

	if err := h.run("-approve", "create-lab", h.profile.ID); err != nil {
		t.Fatal(err)
	}

	if strings.Join(h.transport.calls, ",") != "HelperInfo,CreateLab" || len(h.transport.created) != 1 {
		t.Fatalf("calls: %v", h.transport.calls)
	}

	capability := h.transport.created[0]
	if capability.Claims.HelperID != h.transport.info.HelperID || capability.Claims.Intent.ProfileID != h.profile.ID {
		t.Fatalf("claims: %+v", capability.Claims)
	}

	raw, _ := json.Marshal(capability.Claims)
	signature, _ := base64.RawURLEncoding.DecodeString(capability.Signature)
	public, _ := h.keys.PublicKey()

	if !ed25519.Verify(public, append([]byte("egresslab/helper-capability/v1\x00"), raw...), signature) {
		t.Fatal("capability does not verify with the controller key")
	}

	var lab control.LabInfo
	if err := json.Unmarshal(h.out.Bytes(), &lab); err != nil || lab.State != control.LabSealed {
		t.Fatalf("output: %s %v", h.out.String(), err)
	}
}

func TestCreateLabRefusals(t *testing.T) {
	h := newHarness(t)

	h.transport.info.PublicKeySHA256 = hex.EncodeToString(make([]byte, 32))
	if err := h.run("-approve", "create-lab", h.profile.ID); err == nil || !strings.Contains(err.Error(), "fingerprint mismatch") {
		t.Fatalf("untrusted helper: %v", err)
	}

	if err := h.run("-approve", "create-lab", "profile_ffffffffffffffff"); err == nil ||
		!strings.Contains(err.Error(), "profile not found") {
		t.Fatalf("unknown profile: %v", err)
	}

	if strings.Join(h.transport.calls, ",") != "HelperInfo" {
		t.Fatalf("CreateLab sent despite refusal: %v", h.transport.calls)
	}
}

func TestKeyCommands(t *testing.T) {
	h := newHarness(t)
	h.keys.private = nil

	if err := h.run("public-key"); !errors.Is(err, keystore.ErrNoKey) {
		t.Fatalf("public key before init: %v", err)
	}

	if err := h.run("init-key"); err != nil {
		t.Fatal(err)
	}

	printed := strings.TrimSpace(h.out.String())
	public, _ := h.keys.PublicKey()

	if printed != hex.EncodeToString(public) {
		t.Fatalf("printed %q", printed)
	}

	if err := h.run("init-key"); !errors.Is(err, keystore.ErrKeyExists) {
		t.Fatalf("second init: %v", err)
	}

	if h.runtimes != 0 {
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
		{"connect-tunnel"},
		{"-runtime"},
	} {
		if err := h.run(args...); err == nil {
			t.Errorf("%q accepted", args)
		}
	}

	if h.runtimes != 0 {
		t.Fatal("invalid arguments reached the runtime")
	}
}
