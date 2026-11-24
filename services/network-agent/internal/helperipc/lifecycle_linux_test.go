//go:build linux

package helperipc

import (
	"context"
	"net"
	"os"
	"testing"
	"time"

	"github.com/VanChung369/egresslab/services/network-agent/internal/helperauth"
)

func serveLifecycleTest(t *testing.T, v *helperauth.Verifier, labs *LabLifecycle) string {
	t.Helper()
	requireUnprivileged(t)

	return serveWith(t, func(ctx context.Context, listener *net.UnixListener) error {
		return ServeLifecycle(ctx, listener, uint32(os.Getuid()), nil, v, labs)
	})
}

func TestLabLifecycleIPC(t *testing.T) {
	labs, backend, v, mint := newLifecycleFixture(t)
	socket := serveLifecycleTest(t, v, labs)
	ctx := context.Background()
	req := mint(lifecycleProfile)

	created, err := CreateSealedLab(ctx, socket, lifecycleProfile, *req.Capability)
	if err != nil || created.Lab == nil || created.Lab.State != LabSealed || created.NetworkReady {
		t.Fatalf("create lab: %+v %v", created, err)
	}

	lab := created.Lab

	verified, err := VerifySealedLab(ctx, socket, lab.ProfileID, lab.Namespace)
	if err != nil || verified.Lab == nil || verified.Lab.State != LabSealed || verified.NetworkReady {
		t.Fatalf("verify lab: %+v %v", verified, err)
	}

	deleted, err := DeleteSealedLab(ctx, socket, lab.ProfileID, lab.Namespace)
	if err != nil || deleted.Lab == nil || deleted.Lab.State != LabDeleted || deleted.NetworkReady {
		t.Fatalf("delete lab: %+v %v", deleted, err)
	}

	if _, err := CreateSealedLab(ctx, socket, lifecycleProfile, *req.Capability); err == nil ||
		err.Error() != "authorization denied" {
		t.Fatalf("replay over IPC: %v", err)
	}

	labs.mu.Lock()
	defer labs.mu.Unlock()

	if backend.created != 1 || backend.deleted != 1 || len(labs.labs) != 0 {
		t.Fatal("unexpected backend operations")
	}
}

func TestLabLifecycleIPCRefusals(t *testing.T) {
	labs, backend, v, mint := newLifecycleFixture(t)
	socket := serveLifecycleTest(t, v, labs)
	ctx := context.Background()

	created, err := CreateSealedLab(ctx, socket, lifecycleProfile, *mint(lifecycleProfile).Capability)
	if err != nil {
		t.Fatal(err)
	}

	lab := *created.Lab
	token := mint("profile_ffffffffffffffff").Capability

	// Tunnel and probe stay disabled even when lab operations are enabled.
	for _, op := range []string{helperauth.OpConnectTunnel, helperauth.OpPermitProbe, "RecoverClean"} {
		intent := testIntent()
		intent.Operation = op
		resp := rawRequest(t, socket, Request{Version: Version, Operation: op, Intent: &intent, Capability: token})

		if resp.OK || resp.Error != "operation not enabled" || resp.Lab != nil {
			t.Fatalf("%s: %+v", op, resp)
		}
	}

	signedDelete := existingLabRequest(OpDeleteLab, lab)
	signedDelete.Capability = token

	unsigned := mint("profile_ffffffffffffffff")
	unsigned.Capability = nil

	foreign := existingLabRequest(OpVerifyLab, lab)
	foreign.Intent.ProfileID = "profile_ffffffffffffffff"

	for name, tt := range map[string]struct {
		req  Request
		want string
	}{
		"DeleteLab with a capability": {signedDelete, "authorization denied"},
		"CreateLab without one":       {unsigned, "authorization denied"},
		"foreign profile":             {foreign, "lab operation failed"},
	} {
		if resp := rawRequest(t, socket, tt.req); resp.OK || resp.Error != tt.want || resp.Lab != nil {
			t.Fatalf("%s: %+v", name, resp)
		}
	}

	// None of the refusals consumed the capability.
	if _, err := CreateSealedLab(ctx, socket, "profile_ffffffffffffffff", *token); err != nil {
		t.Fatal(err)
	}

	labs.mu.Lock()
	defer labs.mu.Unlock()

	if backend.created != 2 || backend.deleted != 0 || backend.verified != 0 {
		t.Fatalf("refused requests reached the backend: %+v", backend)
	}
}

func TestServeLifecycleRequiresAuthorization(t *testing.T) {
	err := ServeLifecycle(context.Background(), nil, 1000, nil, nil, NewLabLifecycle(&fakeLifecycleBackend{}))
	if err == nil || err.Error() != "lab lifecycle requires authorization" {
		t.Fatalf("lifecycle without a verifier: %v", err)
	}
}

type blockingCreateBackend struct {
	fakeLifecycleBackend
	started chan context.Context
	release chan struct{}
}

func (b *blockingCreateBackend) Create(ctx context.Context) (string, error) {
	b.started <- ctx
	<-b.release

	return b.fakeLifecycleBackend.Create(ctx)
}

func TestShutdownDoesNotInterruptLabOperation(t *testing.T) {
	backend := &blockingCreateBackend{started: make(chan context.Context), release: make(chan struct{})}
	labs := NewLabLifecycle(backend)
	v, mint := lifecycleSigner(t)

	ctx, shutdown := context.WithCancel(context.Background())
	result := make(chan Response, 1)
	req := mint(lifecycleProfile)

	go func() { result <- respond(ctx, req, nil, v, labs) }()

	opCtx := <-backend.started
	shutdown()

	if opCtx.Err() != nil {
		t.Fatal("shutdown cancelled a running kernel operation")
	}

	if _, ok := opCtx.Deadline(); !ok {
		t.Fatal("lab operation has no deadline")
	}

	close(backend.release)

	if resp := <-result; !resp.OK || resp.Lab == nil || resp.Lab.State != LabSealed {
		t.Fatalf("interrupted operation: %+v", resp)
	}

	if resp := respond(ctx, mint("profile_ffffffffffffffff"), nil, v, labs); resp.OK ||
		resp.Error != "helper is shutting down" {
		t.Fatalf("operation during shutdown: %+v", resp)
	}

	if backend.created != 1 {
		t.Fatal("backend called during shutdown")
	}
}

func TestClientRejectsBadLabMetadata(t *testing.T) {
	socket := fakeHelper(t, func(req Request) Response {
		return Response{Version: Version, Operation: req.Operation, OK: true,
			Lab: &LabInfo{ProfileID: "profile_ffffffffffffffff", Namespace: "egresslab-lab-0123456789abcdef", State: LabSealed}}
	})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if _, err := VerifySealedLab(ctx, socket, lifecycleProfile, "egresslab-lab-0123456789abcdef"); err == nil ||
		err.Error() != "invalid lab lifecycle response" {
		t.Fatalf("other profile accepted: %v", err)
	}

	if _, err := Call(ctx, socket, OpPing); err == nil || err.Error() != "invalid lab lifecycle response" {
		t.Fatalf("lab metadata on Ping accepted: %v", err)
	}
}
