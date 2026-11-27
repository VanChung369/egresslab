//go:build linux

package helperipc

import (
	"context"
	"errors"
	"fmt"
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
	hang        bool   // never answers before its context ends
	target      string // instead of the echo server
}

func (r *proxyDialRecorder) dialer(echo *proxyEcho) ProxyDialer {
	return func(ctx context.Context, namespace string, destination netip.AddrPort) (*net.TCPConn, error) {
		r.mu.Lock()
		r.calls++
		r.namespace, r.destination = namespace, destination
		err, hang, addr := r.err, r.hang, r.target
		r.mu.Unlock()

		if addr == "" {
			addr = echo.addr
		}

		if hang {
			<-ctx.Done()
			return nil, ctx.Err()
		}

		if err != nil {
			return nil, err
		}

		c, err := net.Dial("tcp4", addr)
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

	// The fake windows last 2 s.
	budget, reserve := proxyDialBudget, proxyDialReserve
	proxyDialBudget, proxyDialReserve = 600*time.Millisecond, 300*time.Millisecond
	t.Cleanup(func() { proxyDialBudget, proxyDialReserve = budget, reserve })

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

// waitPlaneGone waits for the keeper to retire with its last stream or request.
func (p *proxyFixture) waitPlaneGone(t *testing.T) {
	t.Helper()

	deadline := time.Now().Add(5 * time.Second)

	for p.f.labs.proxyPlane.Load() != nil {
		if time.Now().After(deadline) {
			t.Fatal("the stream keeper outlived its streams")
		}

		time.Sleep(20 * time.Millisecond)
	}
}

func (p *proxyFixture) windowsOpened() int {
	p.f.labs.mu.Lock()
	defer p.f.labs.mu.Unlock()

	return p.windows.opened
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
	p.waitPlaneGone(t)

	p.dials.mu.Lock()
	defer p.dials.mu.Unlock()

	if p.dials.calls != 0 {
		t.Fatalf("an abandoned request dialed (%d)", p.dials.calls)
	}
}

func TestProxyStreamRefusals(t *testing.T) {
	for _, mode := range []string{"expired health", "other destination signed", "dial failed", "dial hangs", "disabled"} {
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
			case "dial hangs":
				// It must give up before the window's deadline: a window run past it faults the tunnel.
				p.dials.hang = true
				want = CodeRuntimeUnavailable
			case "disabled":
				want = CodeOperationDisabled
			}

			conn, ack, err := p.open(t, capability)
			if conn != nil || ack.OK || ErrorCode(err) != want {
				t.Fatalf("unexpected result: %+v %v", ack, err)
			}

			// A refused stream never faults the tunnel.
			p.waitPlaneGone(t)

			p.f.labs.mu.Lock()
			defer p.f.labs.mu.Unlock()

			if p.f.labs.labs.peek(p.f.lab.ProfileID).State != LabTunnelConfigured {
				t.Fatal("refused stream changed the lab")
			}

			if mode != "expired health" && p.f.labs.preparedLease == nil {
				t.Fatal("refused stream dropped the prepared lease")
			}
		})
	}
}

// A release preempts every stream and closes them before the generation retires.
func TestProxyStreamClosedByRelease(t *testing.T) {
	p := newProxyFixture(t, true)

	var conns []*net.UnixConn

	for range maxProxyStreams {
		conn, _, err := p.open(t, p.capability(t, testProxyDestination))
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()

		echoOnce(t, conn, "ping")
		conns = append(conns, conn)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	if _, err := callRequest(ctx, p.socket, revokeRequest(t, p.f, p.prep)); err != nil {
		t.Fatalf("release refused while every stream slot was taken: %v", err)
	}

	for _, conn := range conns {
		_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))

		if _, err := conn.Read(make([]byte, 1)); err == nil {
			t.Fatal("a stream outlived the release")
		}
	}

	p.f.labs.mu.Lock()
	defer p.f.labs.mu.Unlock()

	if p.f.labs.proxyPlane.Load() != nil || p.f.labs.preparedLease != nil {
		t.Fatal("stream state outlived the release")
	}

	// Interrupting the window was no failure of the tunnel.
	if state := p.f.labs.labs.peek(p.f.lab.ProfileID).State; state != LabSealed {
		t.Fatalf("release left the lab %s", state)
	}
}

// Streams of one reservation share the windows; the last one to end ends them.
func TestProxyStreamsShareWindows(t *testing.T) {
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
	echoOnce(t, first, "first again")

	// The registry answers inside each window, while the keeper holds the lifecycle lock.
	var listMu sync.Mutex
	var lists []error

	p.f.labs.mu.Lock()
	p.windows.inWindow = func() {
		listed, err := Call(context.Background(), p.socket, OpListLabs)
		if err == nil && (len(listed.Labs) != 1 || listed.Labs[0].State != LabTunnelConfigured) {
			err = fmt.Errorf("unexpected registry: %+v", listed.Labs)
		}

		listMu.Lock()
		lists = append(lists, err)
		listMu.Unlock()
	}
	p.f.labs.mu.Unlock()

	// Both cross the next windows.
	time.Sleep(2500 * time.Millisecond)

	listMu.Lock()
	if len(lists) == 0 {
		t.Error("no window opened")
	}

	for _, err := range lists {
		if err != nil {
			t.Errorf("ListLabs in a window: %v", err)
		}
	}
	listMu.Unlock()

	echoOnce(t, first, "later")
	echoOnce(t, second, "later")

	_ = first.Close()
	echoOnce(t, second, "alone")
	_ = second.Close()

	p.waitPlaneGone(t)

	opened := p.windowsOpened()
	time.Sleep(time.Second)

	if p.windowsOpened() != opened {
		t.Fatal("windows outlived the last stream")
	}

	p.dials.mu.Lock()
	defer p.dials.mu.Unlock()

	if p.dials.calls != 2 {
		t.Fatalf("unexpected dials: %d", p.dials.calls)
	}
}

// Two first requests at once: the one that does not start the keeper joins its plane instead of
// waiting for the lock, which the keeper's windows hold longer than that wait.
func TestProxyStreamFirstRequestsJoin(t *testing.T) {
	p := newProxyFixture(t, true)
	p.windows.window = 8 * time.Second

	first, second := p.capability(t, testProxyDestination), p.capability(t, testProxyDestination)

	p.f.labs.mu.Lock()

	type opened struct {
		conn *net.UnixConn
		err  error
	}

	results := make(chan opened, 2)

	for _, capability := range []helperauth.SignedCapability{first, second} {
		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()

			conn, _, err := OpenProxyStream(ctx, p.socket, capability)
			results <- opened{conn, err}
		}()
	}

	time.Sleep(500 * time.Millisecond)
	p.f.labs.mu.Unlock()

	started := time.Now()

	for range 2 {
		o := <-results
		if o.err != nil {
			t.Fatalf("a first request refused: %v", o.err)
		}
		defer o.conn.Close()

		echoOnce(t, o.conn, "ping")
	}

	if time.Since(started) > 4*time.Second {
		t.Fatalf("a first request waited %v", time.Since(started))
	}
}

// silentServer reads until its client half-closes, then neither sends nor closes.
func silentServer(t *testing.T) string {
	t.Helper()

	l, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}

	stop := make(chan struct{})
	t.Cleanup(func() { close(stop); _ = l.Close() })

	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}

			go func() {
				defer c.Close()
				_, _ = io.Copy(io.Discard, c)
				<-stop
			}()
		}
	}()

	return l.Addr().String()
}

func (p *proxyFixture) waitStreams(t *testing.T, want int32) {
	t.Helper()

	deadline := time.Now().Add(5 * time.Second)

	for p.f.labs.proxyCount.Load() != want {
		if time.Now().After(deadline) {
			t.Fatalf("%d streams, want %d", p.f.labs.proxyCount.Load(), want)
		}

		time.Sleep(20 * time.Millisecond)
	}
}

// A half-closed client keeps its download; a client that is gone frees its slot, though the
// destination neither sends nor closes.
func TestProxyStreamPeerHangup(t *testing.T) {
	p := newProxyFixture(t, true)
	p.dials.target = silentServer(t)

	conn, _, err := p.open(t, p.capability(t, testProxyDestination))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	if err := conn.CloseWrite(); err != nil {
		t.Fatal(err)
	}

	time.Sleep(time.Second)

	if n := p.f.labs.proxyCount.Load(); n != 1 {
		t.Fatalf("a half-close ended the stream: %d", n)
	}

	_ = conn.Close()
	p.waitStreams(t, 0)
}

// deafServer accepts and then neither reads nor sends.
func deafServer(t *testing.T) string {
	t.Helper()

	l, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}

	stop := make(chan struct{})
	t.Cleanup(func() { close(stop); _ = l.Close() })

	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}

			go func() {
				defer c.Close()
				<-stop
			}()
		}
	}()

	return l.Addr().String()
}

// A client that leaves while its upload is stuck on a destination that no longer reads still frees
// its slot.
func TestProxyStreamHangupDuringUpload(t *testing.T) {
	p := newProxyFixture(t, true)
	p.dials.target = deafServer(t)

	conn, _, err := p.open(t, p.capability(t, testProxyDestination))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	go func() {
		chunk := make([]byte, 64*1024)

		for range 512 {
			if _, err := conn.Write(chunk); err != nil {
				return
			}
		}
	}()

	time.Sleep(time.Second)
	_ = conn.Close()

	p.waitStreams(t, 0)
}

// While an authorized release waits for the lock, a new request is refused at once instead of
// competing for the lock and starting a plane whose window would outlast the release's wait.
func TestProxyStreamRefusedWhileReleaseWaits(t *testing.T) {
	p := newProxyFixture(t, true)
	p.windows.window = 8 * time.Second

	conn, _, err := p.open(t, p.capability(t, testProxyDestination))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	next := p.capability(t, testProxyDestination)
	plane := p.f.labs.proxyPlane.Load()

	// Between two windows, as a monitor check would.
	p.f.labs.mu.Lock()

	locked := make(chan bool, 1)
	go func() { locked <- p.f.labs.lockPreemptingProxyStreams(context.Background(), true) }()

	select {
	case <-plane.ctx.Done():
	case <-time.After(5 * time.Second):
		t.Fatal("the release did not cancel the streams")
	}

	started := time.Now()

	if _, _, err := p.open(t, next); ErrorCode(err) != CodeLabBusy || time.Since(started) > time.Second {
		t.Fatalf("a request competed with the release: %v after %v", err, time.Since(started))
	}

	p.f.labs.mu.Unlock()

	if !<-locked {
		t.Fatal("the release did not get the lock")
	}

	p.f.labs.mu.Unlock()
}

// A plane that ended starts no dial, even before its cancellation reached the dial's context.
func TestProxyDialAfterPlaneEnded(t *testing.T) {
	plane := newProxyPlane(context.Background(), "profile", "reservation")
	plane.cancel()

	dialed := false
	dial := func(context.Context, string, netip.AddrPort) (*net.TCPConn, error) {
		dialed = true
		return nil, errors.New("dialed")
	}

	r := &proxyRequest{ctx: context.Background(), req: Request{Intent: &helperauth.Intent{}},
		result: make(chan proxyAdmission, 1)}

	if a := dialProxyStream(context.Background(), time.Now().Add(time.Second), plane, r, testProxyDestination,
		dial); a.err == nil || dialed {
		t.Fatal("an ended plane dialed")
	}
}

// A waiting request learns why the window failed, not an authorization refusal.
func TestProxyStreamWindowFailure(t *testing.T) {
	p := newProxyFixture(t, true)
	p.windows.err = errors.New("gate failed")

	if _, _, err := p.open(t, p.capability(t, testProxyDestination)); ErrorCode(err) != CodeLabFaulted {
		t.Fatalf("unexpected result: %v", err)
	}
}

// Over the limit a request is refused before its capability is consumed.
func TestProxyStreamLimit(t *testing.T) {
	p := newProxyFixture(t, true)

	var conns []*net.UnixConn

	for i := range maxProxyStreams {
		conn, _, err := p.open(t, p.capability(t, testProxyDestination))
		if err != nil {
			t.Fatalf("stream %d refused: %v", i, err)
		}
		defer conn.Close()

		echoOnce(t, conn, "ping")
		conns = append(conns, conn)
	}

	over := p.capability(t, testProxyDestination)

	if _, _, err := p.open(t, over); ErrorCode(err) != CodeLabBusy {
		t.Fatalf("stream over the limit: %v", err)
	}

	_ = conns[0].Close()

	deadline := time.Now().Add(5 * time.Second)

	for p.f.labs.proxyCount.Load() >= maxProxyStreams {
		if time.Now().After(deadline) {
			t.Fatal("an ended stream still counts")
		}

		time.Sleep(20 * time.Millisecond)
	}

	conn, _, err := p.open(t, over)
	if err != nil {
		t.Fatalf("the refused capability was consumed: %v", err)
	}
	defer conn.Close()

	echoOnce(t, conn, "again")
	echoOnce(t, conns[1], "still open")
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
