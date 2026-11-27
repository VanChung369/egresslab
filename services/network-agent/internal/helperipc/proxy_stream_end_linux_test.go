package helperipc

import (
	"context"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestProxyStreamEndReason(t *testing.T) {
	for _, tt := range []struct {
		result proxyRelayResult
		want   string
	}{
		{proxyRelayResult{cause: "download: connection reset"}, "download: connection reset"},
		{proxyRelayResult{stopped: context.DeadlineExceeded}, "lifetime reached"},
		{proxyRelayResult{stopped: context.Canceled}, "streams closed"},
		{proxyRelayResult{}, "closed by both sides"},
	} {
		if got := proxyStreamEndReason(tt.result); got != tt.want {
			t.Errorf("%+v: got %q, want %q", tt.result, got, tt.want)
		}
	}
}

// relayEnds are the four ends of one relayed stream: the IPC client and the destination, and the
// helper's sockets to each.
type relayEnds struct {
	peer, client    *net.UnixConn
	target, destiny *net.TCPConn
}

func newRelayEnds(t *testing.T) relayEnds {
	t.Helper()

	tcp, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer tcp.Close()

	target, err := net.DialTCP("tcp4", nil, tcp.Addr().(*net.TCPAddr))
	if err != nil {
		t.Fatal(err)
	}

	destination, err := tcp.AcceptTCP()
	if err != nil {
		t.Fatal(err)
	}

	dir, err := os.MkdirTemp("", "egl")
	if err != nil {
		t.Fatal(err)
	}

	unix, err := net.ListenUnix("unix", &net.UnixAddr{Name: filepath.Join(dir, "s"), Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close()

	peer, err := net.DialUnix("unix", nil, unix.Addr().(*net.UnixAddr))
	if err != nil {
		t.Fatal(err)
	}

	client, err := unix.AcceptUnix()
	if err != nil {
		t.Fatal(err)
	}

	e := relayEnds{peer: peer, client: client, target: target, destiny: destination}

	t.Cleanup(func() {
		_ = peer.Close()
		_ = client.Close()
		_ = target.Close()
		_ = destination.Close()
		_ = os.RemoveAll(dir)
	})

	return e
}

// The relay reports the first cause that ended a stream; without one, whether both sides closed or
// its context ended from outside.
func TestRelayProxyEndCause(t *testing.T) {
	for _, tt := range []struct {
		mode string
		want string
	}{
		{mode: "both sides closed", want: "closed by both sides"},
		{mode: "destination reset", want: "download: connection reset"},
		{mode: "client gone", want: "client gone"},
		{mode: "context ended", want: "streams closed"},
	} {
		t.Run(tt.mode, func(t *testing.T) {
			e := newRelayEnds(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			results := make(chan proxyRelayResult, 1)
			go func() { results <- relayProxy(ctx, cancel, e.client, e.target) }()

			if _, err := e.peer.Write([]byte("ping")); err != nil {
				t.Fatal(err)
			}

			buf := make([]byte, 4)
			if _, err := io.ReadFull(e.destiny, buf); err != nil {
				t.Fatal(err)
			}

			if _, err := e.destiny.Write([]byte("pong!")); err != nil {
				t.Fatal(err)
			}

			if _, err := io.ReadFull(e.peer, make([]byte, 5)); err != nil {
				t.Fatal(err)
			}

			switch tt.mode {
			case "both sides closed":
				_ = e.peer.CloseWrite()
				_, _ = io.Copy(io.Discard, e.destiny)
				_ = e.destiny.Close()
			case "destination reset":
				_ = e.destiny.SetLinger(0)
				_ = e.destiny.Close()
			case "client gone":
				// The destination neither sends nor closes.
				_ = e.peer.Close()
			case "context ended":
				cancel()
			}

			select {
			case r := <-results:
				if got := proxyStreamEndReason(r); got != tt.want || r.up != 4 || r.down != 5 {
					t.Fatalf("reason %q, up %d, down %d", got, r.up, r.down)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("relay did not end")
			}

			if !errors.Is(ctx.Err(), context.Canceled) {
				t.Fatal("relay left its context running")
			}
		})
	}
}
