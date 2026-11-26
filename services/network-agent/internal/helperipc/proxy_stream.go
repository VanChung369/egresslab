package helperipc

import (
	"context"
	"net"
	"net/netip"
	"slices"
	"sync"
	"time"

	"github.com/VanChung369/egresslab/services/network-agent/internal/helperauth"
)

const (
	// proxyStreamLifetime bounds one stream; it is not the lifetime of any traffic permission.
	proxyStreamLifetime = 30 * time.Minute

	// proxyPreemptWait bounds how long a release waits for the streams to leave their traffic
	// window, and a first stream for a short monitor check.
	proxyPreemptWait = 5 * time.Second

	// maxProxyStreams counts admitted and waiting streams together. Each keeps one server connection
	// for its lifetime, so the rest of maxConnections stays free for a release.
	maxProxyStreams = 8
)

// ProxyStreamAck answers an OpenProxyStreamV1 request on the same connection, before any stream
// byte. After a successful ack the connection carries only raw TCP bytes.
type ProxyStreamAck struct {
	Version   int    `json:"version"`
	Operation string `json:"operation"`
	OK        bool   `json:"ok"`
	Code      string `json:"code,omitempty"`

	BoundIPv4 string `json:"bound_ipv4,omitempty"`
	BoundPort uint16 `json:"bound_port,omitempty"`
}

func (a *ProxyStreamAck) valid() bool {
	if a == nil || a.Version != Version || a.Operation != helperauth.OpOpenProxyStream {
		return false
	}

	if !a.OK {
		return knownCodes[a.Code] && a.BoundIPv4 == "" && a.BoundPort == 0
	}

	ip, err := netip.ParseAddr(a.BoundIPv4)

	return a.Code == "" && err == nil && ip.Is4() && ip.String() == a.BoundIPv4 && a.BoundPort != 0
}

// proxyStreamState is one admitted stream: the client connection and the handed-off TCP socket. It
// ends with its context.
type proxyStreamState struct {
	ctx    context.Context
	cancel context.CancelFunc

	client *net.UnixConn
	target *net.TCPConn
}

func (s *proxyStreamState) close() {
	s.cancel()
	_ = s.client.Close()
	_ = s.target.Close()
}

// proxyRequest is a checked stream request, its capability not yet consumed, waiting for a window.
type proxyRequest struct {
	ctx    context.Context // ends when its client leaves
	req    Request
	conn   *net.UnixConn
	result chan proxyAdmission

	taken bool // under the plane's mu
}

type proxyAdmission struct {
	stream *proxyStreamState
	err    error
}

// proxyPlane carries every stream of the prepared reservation through one chain of traffic windows.
// Its keeper holds the windows while any stream or request remains and admits and dials new
// requests inside them; streams only relay.
type proxyPlane struct {
	profileID     string
	reservationID string

	// Windows open on parent, the server's context: ending the plane never fails a window.
	parent context.Context
	ctx    context.Context
	cancel context.CancelFunc

	changed chan struct{}

	mu       sync.Mutex
	closing  bool
	err      error // why the keeper stopped
	queue    []*proxyRequest
	inflight int
	streams  map[*proxyStreamState]struct{}
}

func newProxyPlane(parent context.Context, profileID, reservationID string) *proxyPlane {
	ctx, cancel := context.WithCancel(parent)

	return &proxyPlane{
		profileID:     profileID,
		reservationID: reservationID,
		parent:        parent,
		ctx:           ctx,
		cancel:        cancel,
		changed:       make(chan struct{}, 1),
		streams:       make(map[*proxyStreamState]struct{}),
	}
}

func (p *proxyPlane) notify() {
	select {
	case p.changed <- struct{}{}:
	default:
	}
}

// submit queues r unless the plane is ending.
func (p *proxyPlane) submit(r *proxyRequest) bool {
	p.mu.Lock()

	if p.closing || p.ctx.Err() != nil {
		p.mu.Unlock()
		return false
	}

	p.queue = append(p.queue, r)
	p.mu.Unlock()

	p.notify()

	return true
}

// next claims the oldest waiting request for the keeper.
func (p *proxyPlane) next() *proxyRequest {
	p.mu.Lock()
	defer p.mu.Unlock()

	if len(p.queue) == 0 {
		return nil
	}

	r := p.queue[0]
	p.queue = slices.Delete(p.queue, 0, 1)
	r.taken = true
	p.inflight++

	return r
}

// withdraw gives r up unless the keeper has claimed it; a claimed request always gets its result.
func (p *proxyPlane) withdraw(r *proxyRequest) bool {
	p.mu.Lock()

	if r.taken {
		p.mu.Unlock()
		return false
	}

	p.queue = slices.DeleteFunc(p.queue, func(q *proxyRequest) bool { return q == r })
	p.mu.Unlock()

	p.notify()

	return true
}

func (p *proxyPlane) finish(r *proxyRequest, a proxyAdmission) {
	p.mu.Lock()
	p.inflight--
	p.mu.Unlock()

	r.result <- a
	p.notify()
}

// add registers an admitted stream; false once the plane is ending or its client has left.
func (p *proxyPlane) add(r *proxyRequest, s *proxyStreamState) bool {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.closing || p.ctx.Err() != nil || r.ctx.Err() != nil {
		return false
	}

	p.streams[s] = struct{}{}

	return true
}

func (p *proxyPlane) remove(s *proxyStreamState) {
	p.mu.Lock()
	delete(p.streams, s)
	p.mu.Unlock()

	p.notify()
}

func (p *proxyPlane) idleLocked() bool {
	return len(p.streams) == 0 && p.inflight == 0 && len(p.queue) == 0
}

func (p *proxyPlane) idle() bool {
	p.mu.Lock()
	defer p.mu.Unlock()

	return p.idleLocked()
}

// retireIfIdle ends the plane when nothing is left; nothing can be queued on it afterwards.
func (p *proxyPlane) retireIfIdle() bool {
	p.mu.Lock()
	defer p.mu.Unlock()

	if !p.idleLocked() {
		return false
	}

	p.closing = true

	return true
}

// close ends every stream; waiting requests see the plane's context end.
func (p *proxyPlane) close(err error) {
	p.mu.Lock()
	p.closing = true

	if p.err == nil {
		p.err = err
	}

	streams := p.streams
	p.streams = make(map[*proxyStreamState]struct{})
	p.mu.Unlock()

	p.cancel()

	for s := range streams {
		s.close()
	}
}

func (p *proxyPlane) failure() error {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.err == nil {
		return errLabBusy
	}

	return p.err
}

// closeProxyStreamsLocked closes every stream before anything retires its generation. The caller
// holds l.mu.
func (l *LabLifecycle) closeProxyStreamsLocked() {
	if plane := l.proxyPlane.Swap(nil); plane != nil {
		plane.close(errLabAuthorization)
	}
}

// lockPreemptingProxyStreams takes the lifecycle lock for a release. The streams' keeper holds the
// lock through its chained traffic windows almost all the time, so an already authorized release
// (its capability checked, not yet consumed) cancels the plane first; it also waits out a monitor
// check. The wait is bounded; anything else keeps refusing with LAB_BUSY.
func (l *LabLifecycle) lockPreemptingProxyStreams(ctx context.Context, authorized bool) bool {
	if l.mu.TryLock() {
		return true
	}

	if !authorized {
		return false
	}

	if plane := l.proxyPlane.Load(); plane != nil {
		plane.cancel()
	}

	return l.lockWithin(ctx, proxyPreemptWait)
}

// lockWithin waits up to wait for the lifecycle lock without preempting anything.
func (l *LabLifecycle) lockWithin(ctx context.Context, wait time.Duration) bool {
	if l.mu.TryLock() {
		return true
	}

	deadline := time.NewTimer(wait)
	defer deadline.Stop()

	tick := time.NewTicker(20 * time.Millisecond)
	defer tick.Stop()

	for {
		select {
		case <-ctx.Done():
			return false
		case <-deadline.C:
			return false
		case <-tick.C:
		}

		if l.mu.TryLock() {
			return true
		}
	}
}
