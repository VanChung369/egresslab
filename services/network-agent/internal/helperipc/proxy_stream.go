package helperipc

import (
	"context"
	"net"
	"net/netip"
	"time"

	"github.com/VanChung369/egresslab/services/network-agent/internal/helperauth"
)

const (
	// proxyStreamLifetime bounds one stream; it is not the lifetime of any traffic permission.
	proxyStreamLifetime = 30 * time.Minute

	// proxyPreemptWait bounds how long a teardown or a new stream waits for a running stream to
	// leave its traffic window.
	proxyPreemptWait = 5 * time.Second
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

// proxyStreamState is the one proxy stream of this helper: the client connection and, once dialed,
// the handed-off TCP socket. It ends with its context.
type proxyStreamState struct {
	profileID     string
	reservationID string

	ctx    context.Context
	cancel context.CancelFunc

	client *net.UnixConn
	target *net.TCPConn
}

// closeLocked: the caller holds the lifecycle lock.
func (s *proxyStreamState) closeLocked() {
	s.cancel()
	_ = s.client.Close()

	if s.target != nil {
		_ = s.target.Close()
	}
}

// closeProxyStreamLocked closes the stream before anything retires its generation. The caller holds
// l.mu.
func (l *LabLifecycle) closeProxyStreamLocked() {
	if l.proxyStream == nil {
		return
	}

	l.proxyStream.closeLocked()
	l.proxyActive.Store(nil)
	l.proxyStream = nil
}

// lockPreemptingProxyStream takes the lifecycle lock for a release or a new stream. A running stream
// holds the lock through its chained traffic windows almost all the time, so an already authorized
// request (its capability checked, not yet consumed) cancels it first; it also waits out a monitor
// check. The wait is bounded; anything else keeps refusing with LAB_BUSY.
func (l *LabLifecycle) lockPreemptingProxyStream(ctx context.Context, authorized bool) bool {
	if l.mu.TryLock() {
		return true
	}

	if !authorized {
		return false
	}

	if stream := l.proxyActive.Load(); stream != nil {
		stream.cancel()
	}

	deadline := time.NewTimer(proxyPreemptWait)
	defer deadline.Stop()

	tick := time.NewTicker(20 * time.Millisecond)
	defer tick.Stop()

	for {
		if l.mu.TryLock() {
			return true
		}

		select {
		case <-ctx.Done():
			return false
		case <-deadline.C:
			return false
		case <-tick.C:
		}
	}
}
