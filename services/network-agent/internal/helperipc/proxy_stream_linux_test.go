//go:build linux

package helperipc

import (
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/VanChung369/egresslab/services/network-agent/internal/helperauth"
)

var testProxyDestination = netip.MustParseAddrPort("93.184.216.34:443")

// proxyEcho is the destination: a loopback echo server that records its connections.
type proxyEcho struct {
	addr  string
	mu    sync.Mutex
	conns []net.Conn
}

func newProxyEcho(t *testing.T) *proxyEcho {
	t.Helper()

	l, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })

	e := &proxyEcho{addr: l.Addr().String()}

	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}

			e.mu.Lock()
			e.conns = append(e.conns, c)
			e.mu.Unlock()

			go func() {
				defer c.Close()
				_, _ = io.Copy(c, c)
			}()
		}
	}()

	return e
}

type proxyDialRecorder struct {
	mu          sync.Mutex
	calls       int
	namespace   string
	destination netip.AddrPort
	err         error
}

func (r *proxyDialRecorder) dialer(echo *proxyEcho) ProxyDialer {
	return func(ctx context.Context, namespace string, destination netip.AddrPort) (*net.TCPConn, error) {
		r.mu.Lock()
		r.calls++
		r.namespace, r.destination = namespace, destination
		err := r.err
		r.mu.Unlock()

		if err != nil {
			return nil, err
		}

		c, err := net.Dial("tcp4", echo.addr)
		if err != nil {
			return nil, err
		}

		return c.(*net.TCPConn), nil
	}
}

type proxyFixture struct {
	f       *tunnelFixture
	windows *fakeTrafficWindowBackend
	prep    Request
	lease   PreparedLeaseInfo
	dials   *proxyDialRecorder
	socket  string
}

func newProxyFixture(t *testing.T, enabled bool) *proxyFixture {
	t.Helper()
	requireUnprivileged(t)

	f, windows, prep, lease := newTrafficWindowFixture(t)
	echo := newProxyEcho(t)
	dials := &proxyDialRecorder{}

	opts := ServerOptions{Verifier: f.verifier, Labs: f.labs, RuntimeID: multiProbeTestRuntimeID}
	if enabled {
		opts.ProxyUID, opts.ProxyDial = 1001, dials.dialer(echo)
	}

	socket := serveWith(t, func(ctx context.Context, listener *net.UnixListener) error {
		return ServeWith(ctx, listener, uint32(os.Getuid()), opts)
	})

	return &proxyFixture{f: f, windows: windows, prep: prep, lease: lease, dials: dials, socket: socket}
}

func (p *proxyFixture) capability(t *testing.T, destination netip.AddrPort) helperauth.SignedCapability {
	t.Helper()

	binding, err := prepareLeaseIntent(p.lease.CandidateInfo, p.lease.AuthorityID, p.lease.ReservationID)
	if err != nil {
		t.Fatal(err)
	}

	intent, err := helperauth.NewOpenProxyStreamIntent(binding, destination)
	if err != nil {
		t.Fatal(err)
	}

	return *p.f.mint(intent).Capability
}

func (p *proxyFixture) open(t *testing.T, capability helperauth.SignedCapability) (*net.UnixConn, ProxyStreamAck, error) {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	return OpenProxyStream(ctx, p.socket, capability)
}

func echoOnce(t *testing.T, conn net.Conn, msg string) {
	t.Helper()

	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	defer conn.SetDeadline(time.Time{})

	if _, err := conn.Write([]byte(msg)); err != nil {
		t.Fatal(err)
	}

	got := make([]byte, len(msg))
	if _, err := io.ReadFull(conn, got); err != nil || string(got) != msg {
		t.Fatalf("echo %q: %q %v", msg, got, err)
	}
}

func TestProxyStreamIPC(t *testing.T) {
	p := newProxyFixture(t, true)
	capability := p.capability(t, testProxyDestination)

	conn, ack, err := p.open(t, capability)
	if err != nil || !ack.OK || ack.BoundIPv4 != "127.0.0.1" {
		t.Fatalf("stream refused: %+v %v", ack, err)
	}
	defer conn.Close()

	echoOnce(t, conn, "ping")

	// The socket outlives one window; the next windows carry it on.
	time.Sleep(2500 * time.Millisecond)
	echoOnce(t, conn, "after another window")

	p.dials.mu.Lock()
	calls, namespace, destination := p.dials.calls, p.dials.namespace, p.dials.destination
	p.dials.mu.Unlock()

	if calls != 1 || namespace != p.lease.Namespace || destination != testProxyDestination {
		t.Fatalf("unexpected dial: %d %s %v", calls, namespace, destination)
	}

	if _, _, err := p.open(t, capability); ErrorCode(err) != CodeAuthorizationDenied {
		t.Fatalf("replayed stream capability accepted: %v", err)
	}

	// Neither the refused replay nor a refused release interrupted the stream.
	forged := revokeRequest(t, p.f, p.prep)
	forged.Capability.Signature = capability.Signature

	if _, err := runRevokeLease(p.f, forged); err == nil {
		t.Fatal("forged release accepted")
	}

	echoOnce(t, conn, "still open")
}

// A request whose client left before its first window never dials.
func TestProxyStreamAbandonedRequest(t *testing.T) {
	p := newProxyFixture(t, true)

	// The monitor is due, so no window opens for now.
	p.f.labs.mu.Lock()
	lease := p.f.labs.preparedLease
	checkedAt := lease.monitor.checkedAt
	lease.monitor.checkedAt = checkedAt.Add(-egressMonitorInterval)
	p.f.labs.mu.Unlock()

	conn, err := net.Dial("unix", p.socket)
	if err != nil {
		t.Fatal(err)
	}

	capability := p.capability(t, testProxyDestination)
	intent := capability.Claims.Intent

	if err := WriteFrame(conn, Request{Version: Version, Operation: intent.Operation, Intent: &intent,
		Capability: &capability}); err != nil {
		t.Fatal(err)
	}

	time.Sleep(500 * time.Millisecond)
	_ = conn.Close()
	time.Sleep(500 * time.Millisecond)

	p.f.labs.mu.Lock()
	lease.monitor.checkedAt = checkedAt
	p.f.labs.mu.Unlock()

	time.Sleep(time.Second)

	p.dials.mu.Lock()
	calls := p.dials.calls
	p.dials.mu.Unlock()

	p.f.labs.mu.Lock()
	defer p.f.labs.mu.Unlock()

	if calls != 0 || p.f.labs.proxyStream != nil {
		t.Fatalf("an abandoned request dialed (%d) or kept its stream", calls)
	}
}

func TestProxyStreamRefusals(t *testing.T) {
	for _, mode := range []string{"expired health", "other destination signed", "dial failed", "disabled"} {
		t.Run(mode, func(t *testing.T) {
			p := newProxyFixture(t, mode != "disabled")
			capability := p.capability(t, testProxyDestination)
			want := CodeAuthorizationDenied

			switch mode {
			case "expired health":
				p.f.labs.mu.Lock()
				p.f.labs.preparedLease.monitor.expiresAt = time.Now().Add(-time.Second)
				p.f.labs.mu.Unlock()
			case "other destination signed":
				other := p.capability(t, netip.MustParseAddrPort("93.184.216.35:443"))
				capability.Signature = other.Signature
			case "dial failed":
				p.dials.err = errors.New("managed proxy dial failed: DESTINATION_REFUSED")
				want = CodeRuntimeUnavailable
			case "disabled":
				want = CodeOperationDisabled
			}

			conn, ack, err := p.open(t, capability)
			if conn != nil || ack.OK || ErrorCode(err) != want {
				t.Fatalf("unexpected result: %+v %v", ack, err)
			}

			// A refused stream never faults the tunnel.
			p.f.labs.mu.Lock()
			defer p.f.labs.mu.Unlock()

			if p.f.labs.labs[p.f.lab.ProfileID].State != LabTunnelConfigured || p.f.labs.proxyStream != nil {
				t.Fatal("refused stream changed the lab")
			}

			if mode != "expired health" && p.f.labs.preparedLease == nil {
				t.Fatal("refused stream dropped the prepared lease")
			}
		})
	}
}

// A release preempts the stream and closes it before the generation retires.
func TestProxyStreamClosedByRelease(t *testing.T) {
	p := newProxyFixture(t, true)

	conn, _, err := p.open(t, p.capability(t, testProxyDestination))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	echoOnce(t, conn, "ping")

	if _, err := runRevokeLease(p.f, revokeRequest(t, p.f, p.prep)); err != nil {
		t.Fatalf("release refused while a stream ran: %v", err)
	}

	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))

	if _, err := conn.Read(make([]byte, 1)); err == nil {
		t.Fatal("stream outlived the release")
	}

	p.f.labs.mu.Lock()
	defer p.f.labs.mu.Unlock()

	if p.f.labs.proxyStream != nil || p.f.labs.proxyActive.Load() != nil || p.f.labs.preparedLease != nil {
		t.Fatal("stream state outlived the release")
	}
}

// One stream per helper: a new authorized stream replaces the earlier one.
func TestProxyStreamReplaced(t *testing.T) {
	p := newProxyFixture(t, true)

	first, _, err := p.open(t, p.capability(t, testProxyDestination))
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()

	echoOnce(t, first, "first")

	second, _, err := p.open(t, p.capability(t, testProxyDestination))
	if err != nil {
		t.Fatalf("second stream refused: %v", err)
	}
	defer second.Close()

	echoOnce(t, second, "second")

	_ = first.SetReadDeadline(time.Now().Add(5 * time.Second))

	if _, err := first.Read(make([]byte, 1)); err == nil {
		t.Fatal("replaced stream still open")
	}
}

// An authorized stream waits out a short monitor check instead of answering LAB_BUSY.
func TestProxyStreamWaitsForMonitor(t *testing.T) {
	p := newProxyFixture(t, true)
	capability := p.capability(t, testProxyDestination)

	p.f.labs.mu.Lock()

	go func() {
		time.Sleep(time.Second)
		p.f.labs.mu.Unlock()
	}()

	conn, _, err := p.open(t, capability)
	if err != nil {
		t.Fatalf("stream refused while the lifecycle was briefly busy: %v", err)
	}
	defer conn.Close()

	echoOnce(t, conn, "ping")
}
