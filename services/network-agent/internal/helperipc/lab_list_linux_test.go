//go:build linux

package helperipc

import (
	"context"
	"net"
	"os"
	"testing"
)

func TestListLabsLifecycle(t *testing.T) {
	labs, backend, verifier, mint := newLifecycleFixture(t)
	socket := serveLifecycleTest(t, verifier, labs)
	ctx := context.Background()

	empty, err := Call(ctx, socket, OpListLabs)
	if err != nil || len(empty.Labs) != 0 {
		t.Fatalf("expected empty registry: %+v %v", empty, err)
	}

	created, err := CreateSealedLab(ctx, socket, lifecycleProfile, *mint(lifecycleProfile).Capability)
	if err != nil {
		t.Fatal(err)
	}

	listed, err := Call(ctx, socket, OpListLabs)
	if err != nil || len(listed.Labs) != 1 || listed.Labs[0] != *created.Lab || listed.NetworkReady {
		t.Fatalf("unexpected registry: %+v %v", listed, err)
	}

	// A faulted lab stays listed until it is deleted.
	labs.mu.Lock()
	backend.verifyErr = os.ErrDeadlineExceeded
	labs.mu.Unlock()

	if _, err := VerifySealedLab(ctx, socket, created.Lab.ProfileID, created.Lab.Namespace); err == nil {
		t.Fatal("verification failure not reported")
	}

	listed, err = Call(ctx, socket, OpListLabs)
	if err != nil || len(listed.Labs) != 1 || listed.Labs[0].State != LabFaulted {
		t.Fatalf("faulted lab: %+v %v", listed, err)
	}

	if _, err := DeleteSealedLab(ctx, socket, created.Lab.ProfileID, created.Lab.Namespace); err != nil {
		t.Fatal(err)
	}

	listed, err = Call(ctx, socket, OpListLabs)
	if err != nil || len(listed.Labs) != 0 {
		t.Fatalf("deleted lab remains in registry: %+v %v", listed, err)
	}
}

func TestListLabsRefusals(t *testing.T) {
	labs, _, verifier, mint := newLifecycleFixture(t)
	socket := serveLifecycleTest(t, verifier, labs)

	withAuth := mint(lifecycleProfile)
	withAuth.Operation = OpListLabs
	if resp := rawRequest(t, socket, withAuth); resp.OK || resp.Error != "unexpected authorization fields" {
		t.Fatalf("ListLabs with authorization fields: %+v", resp)
	}

	labs.mu.Lock()
	resp := rawRequest(t, socket, Request{Version: Version, Operation: OpListLabs})
	labs.mu.Unlock()

	if resp.OK || resp.Error != "lab registry unavailable" || resp.Labs != nil {
		t.Fatalf("ListLabs while busy: %+v", resp)
	}

	disabled := serveAuthorizedTest(t, verifier)
	if resp := rawRequest(t, disabled, Request{Version: Version, Operation: OpListLabs}); resp.OK ||
		resp.Error != "operation not enabled" {
		t.Fatalf("ListLabs without lifecycle: %+v", resp)
	}
}

func TestProductionPeerMustBeRoot(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/peer.sock"

	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	go func() {
		if conn, err := listener.Accept(); err == nil {
			conn.Close()
		}
	}()

	conn, err := net.Dial("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	err = verifyProductionPeer(conn)

	if os.Getuid() == 0 {
		if err != nil {
			t.Fatalf("root server refused: %v", err)
		}
	} else if err == nil || err.Error() != "unexpected helper UID" {
		t.Fatalf("non-root server accepted: %v", err)
	}
}
