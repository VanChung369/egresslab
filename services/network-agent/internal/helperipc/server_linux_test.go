//go:build linux

package helperipc

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// serveTest runs Serve for allowedUID; see serveWith.
func serveTest(t *testing.T, allowedUID uint32, scan RecoveryScanner) string {
	t.Helper()

	return serveWith(t, func(ctx context.Context, listener *net.UnixListener) error {
		return Serve(ctx, listener, allowedUID, scan)
	})
}

// serveWith runs serve on a socket in a short temporary directory (Unix socket paths are limited
// to about 108 bytes, which t.TempDir can exceed) and stops it when the test ends.
func serveWith(t *testing.T, serve func(context.Context, *net.UnixListener) error) string {
	t.Helper()

	dir, err := os.MkdirTemp("", "elipc-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })

	path := filepath.Join(dir, "helper.sock")

	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)

	go func() { done <- serve(ctx, listener) }()

	t.Cleanup(func() {
		cancel()

		select {
		case err := <-done:
			if err != nil {
				t.Error(err)
			}
		case <-time.After(2 * time.Second):
			t.Error("server shutdown timed out")
		}
	})

	return path
}

func requireUnprivileged(t *testing.T) {
	t.Helper()

	if os.Getuid() == 0 {
		t.Skip("integration test requires an unprivileged user")
	}
}

// rawExchange sends payload as one frame without Call's client-side checks.
func rawExchange(t *testing.T, socket string, payload []byte) Response {
	t.Helper()

	conn, err := net.Dial("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	if err := conn.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}

	frame := []byte{byte(len(payload) >> 24), byte(len(payload) >> 16), byte(len(payload) >> 8), byte(len(payload))}
	if _, err := conn.Write(append(frame, payload...)); err != nil {
		t.Fatal(err)
	}

	var resp Response
	if err := ReadFrame(conn, &resp); err != nil {
		t.Fatal(err)
	}

	return resp
}

func TestPeerIdentityAndReadOnlyOperations(t *testing.T) {
	requireUnprivileged(t)

	var calls atomic.Int32

	socket := serveTest(t, uint32(os.Getuid()), func(context.Context) ([]RecoveryItem, error) {
		calls.Add(1)
		return []RecoveryItem{{Kind: "namespace", Name: "egresslab-lab-0123456789abcdef", State: "orphan"}}, nil
	})

	ctx := context.Background()

	ping, err := Call(ctx, socket, OpPing)
	if err != nil || !ping.OK || ping.NetworkReady || len(ping.Items) != 0 {
		t.Fatalf("ping %+v %v", ping, err)
	}

	scan, err := Call(ctx, socket, OpRecoverScan)
	if err != nil || len(scan.Items) != 1 || scan.Items[0].State != "orphan" {
		t.Fatalf("scan %+v %v", scan, err)
	}

	if calls.Load() != 1 {
		t.Fatal("scanner invocation mismatch")
	}

	// Send mutations directly; Call refuses them on the client side too.
	for _, op := range []string{"CreateLab", "ConnectTunnel", "PermitProbe", "PermitMultiProbeV1", "RecoverClean"} {
		denied := rawExchange(t, socket, []byte(`{"version":1,"operation":"`+op+`"}`))

		if denied.OK || denied.Error != "operation not enabled" || denied.Operation != op || denied.NetworkReady {
			t.Fatalf("%s accepted: %+v", op, denied)
		}
	}

	if calls.Load() != 1 {
		t.Fatal("a refused operation reached the scanner")
	}
}

func TestPeerRejection(t *testing.T) {
	// Runs as root too: allowedUID is never the caller's UID.
	socket := serveTest(t, uint32(os.Getuid()+1), func(context.Context) ([]RecoveryItem, error) {
		t.Error("scanner called for denied peer")
		return nil, nil
	})

	if _, err := Call(context.Background(), socket, OpPing); err == nil {
		t.Fatal("wrong UID accepted")
	}

	if _, err := Call(context.Background(), socket, OpRecoverScan); err == nil {
		t.Fatal("wrong UID accepted")
	}
}

func TestServeRejectsRootClientUID(t *testing.T) {
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: "@egresslab-test-" + t.Name(), Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	if err := Serve(context.Background(), listener, 0, nil); err == nil {
		t.Fatal("UID 0 accepted as the agent UID")
	}
}

func TestScannerFailureDoesNotEscape(t *testing.T) {
	requireUnprivileged(t)

	socket := serveTest(t, uint32(os.Getuid()), func(context.Context) ([]RecoveryItem, error) {
		return nil, errors.New("internal path /secret")
	})

	_, err := Call(context.Background(), socket, OpRecoverScan)
	if err == nil || err.Error() != "recovery scan failed" {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestMalformedRequestsAreRefusedWithoutEcho(t *testing.T) {
	requireUnprivileged(t)

	socket := serveTest(t, uint32(os.Getuid()), func(context.Context) ([]RecoveryItem, error) {
		t.Error("scanner called for a malformed request")
		return nil, nil
	})

	tests := []struct {
		name, payload, wantErr string
	}{
		{"unknown field", `{"version":1,"operation":"RecoverScan","command":"rm -rf /"}`, "invalid request frame"},
		{"trailing content", `{"version":1,"operation":"RecoverScan"}{}`, "invalid request frame"},
		{"wrong version", `{"version":2,"operation":"RecoverScan"}`, "unsupported protocol version"},
		{"long operation", `{"version":1,"operation":"` + strings.Repeat("A", 4000) + `"}`, "operation not enabled"},
		{"shell-like operation", `{"version":1,"operation":"ip netns add x"}`, "operation not enabled"},
		{"digit-first operation", `{"version":1,"operation":"1PermitProbe"}`, "operation not enabled"},
		{"punctuated operation", `{"version":1,"operation":"PermitProbe-V1"}`, "operation not enabled"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp := rawExchange(t, socket, []byte(tt.payload))

			if resp.OK || resp.Error != tt.wantErr || resp.NetworkReady || len(resp.Items) != 0 {
				t.Fatalf("got %+v", resp)
			}

			if tt.name != "wrong version" && resp.Operation != "" {
				t.Fatalf("echoed operation %q", resp.Operation)
			}
		})
	}
}

func TestOversizedScanResults(t *testing.T) {
	requireUnprivileged(t)

	t.Run("too many items", func(t *testing.T) {
		socket := serveTest(t, uint32(os.Getuid()), func(context.Context) ([]RecoveryItem, error) {
			return make([]RecoveryItem, maxRecoveryItems+1), nil
		})

		if _, err := Call(context.Background(), socket, OpRecoverScan); err == nil ||
			err.Error() != "recovery scan failed" {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("frame too large", func(t *testing.T) {
		socket := serveTest(t, uint32(os.Getuid()), func(context.Context) ([]RecoveryItem, error) {
			items := make([]RecoveryItem, maxRecoveryItems)
			for i := range items {
				items[i] = RecoveryItem{Kind: "namespace", Detail: strings.Repeat("d", 1024)}
			}
			return items, nil
		})

		if _, err := Call(context.Background(), socket, OpRecoverScan); err == nil ||
			err.Error() != "response too large" {
			t.Fatalf("unexpected error: %v", err)
		}
	})
}
