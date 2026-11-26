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
	"time"

	"github.com/VanChung369/egresslab/services/network-agent/internal/helperauth"
)

const (
	// proxyFirstWindowWait bounds how long a new stream waits for a traffic window and its dial.
	proxyFirstWindowWait = 45 * time.Second

	// proxyWindowHold caps one window, so a due monitor check never waits long.
	proxyWindowHold = 6 * time.Second

	proxyWindowRetry = 250 * time.Millisecond
)

// A window admits a new dial only while proxyDialBudget of it is left (the agent's 4 s dial timeout
// and proxyDialReserve); later requests wait for the next window. Every dial ends proxyDialReserve
// before the window's deadline, so its worker's cleanup never runs the window past it. Variables
// for tests.
var (
	proxyDialBudget  = 6 * time.Second
	proxyDialReserve = 2 * time.Second
)

// ProxyDialer opens one TCP connection inside namespace as the proxy user (agent.ProxyDialer).
type ProxyDialer func(ctx context.Context, namespace string, destination netip.AddrPort) (*net.TCPConn, error)

// proxyKeeper is what the keeper needs from the server; it never comes from a request.
type proxyKeeper struct {
	verifier  *helperauth.Verifier
	runtimeID string
	uid       uint32
	dial      ProxyDialer
}

// checkProxyRequest validates the request and its signature without consuming it.
func checkProxyRequest(req Request, v *helperauth.Verifier) error {
	if req.Version != Version || req.Operation != helperauth.OpOpenProxyStream || req.Intent == nil ||
		req.Capability == nil || v == nil || !helperauth.ValidOpenProxyStreamIntent(*req.Intent) {
		return errLabInvalid
	}

	if _, ok := req.Intent.ProxyDestination(); !ok {
		return errLabInvalid
	}

	if v.Check(*req.Capability, *req.Intent) != nil {
		return errLabAuthorization
	}

	return nil
}

// authorizeProxyRequestLocked binds the signed request to the prepared lease of this helper epoch,
// the plane's reservation and fresh monitoring health, and consumes the capability. The caller holds
// l.mu, inside a traffic window.
func (l *LabLifecycle) authorizeProxyRequestLocked(req Request, k proxyKeeper, reservationID string) (netip.AddrPort, error) {
	v := k.verifier
	destination, _ := req.Intent.ProxyDestination()
	p := l.preparedLease

	if l.closed || l.blockCreation || p == nil || p.info.ReservationID != reservationID || !p.monitor.fresh(time.Now()) {
		return netip.AddrPort{}, errLabAuthorization
	}

	lab, exists := l.labs[p.info.ProfileID]
	if !exists || lab.Namespace != p.info.Namespace || lab.State != LabTunnelConfigured ||
		l.tunnelProfile != p.info.ProfileID {
		return netip.AddrPort{}, errLabUncertain
	}

	helperID, fingerprint := v.Identity()
	if p.info.HelperID != helperID || p.info.RuntimeID != k.runtimeID || p.info.PublicKeySHA256 != fingerprint {
		return netip.AddrPort{}, errLabAuthorization
	}

	binding, err := prepareLeaseIntent(p.info.CandidateInfo, p.info.AuthorityID, p.info.ReservationID)
	if err != nil {
		return netip.AddrPort{}, errLabAuthorization
	}

	expected, err := helperauth.NewOpenProxyStreamIntent(binding, destination)
	if err != nil || *req.Intent != expected {
		return netip.AddrPort{}, errLabAuthorization
	}

	nonce := req.Capability.Claims.Nonce
	if nonce == p.info.EvidenceNonce || nonce == p.info.ReservationNonce || nonce == p.info.PreparationNonce {
		return netip.AddrPort{}, errLabAuthorization
	}

	if err := v.VerifyAndConsume(*req.Capability, expected); err != nil {
		return netip.AddrPort{}, errLabAuthorization
	}

	return destination, nil
}

// joinProxyPlane queues r on the plane of its reservation, starting the plane and its keeper when
// there is none. A running keeper holds the lock, so joining it never takes the lock; without one,
// the lock is held at most by a short operation such as a monitor check, or by a keeper that another
// first request just started.
func (l *LabLifecycle) joinProxyPlane(ctx context.Context, r *proxyRequest, k proxyKeeper) (*proxyPlane, error) {
	reservationID := r.req.Intent.ReservationID
	deadline := time.Now().Add(proxyPreemptWait)

	for {
		if plane := l.proxyPlane.Load(); plane != nil && plane.reservationID == reservationID && plane.submit(r) {
			return plane, nil
		}

		if l.mu.TryLock() {
			break
		}

		if !time.Now().Before(deadline) {
			return nil, errLabBusy
		}

		timer := time.NewTimer(20 * time.Millisecond)

		select {
		case <-ctx.Done():
			timer.Stop()
			return nil, errLabBusy
		case <-timer.C:
		}
	}

	plane, created, err := l.joinProxyPlaneLocked(ctx, r)
	l.mu.Unlock()

	// Started after the unlock, so its first window does not find the lock taken.
	if created {
		go l.runProxyPlane(plane, k)
	}

	return plane, err
}

func (l *LabLifecycle) joinProxyPlaneLocked(ctx context.Context, r *proxyRequest) (*proxyPlane, bool, error) {
	reservationID := r.req.Intent.ReservationID
	p := l.preparedLease

	if l.closed || l.blockCreation || p == nil || p.info.ReservationID != reservationID || !p.monitor.fresh(time.Now()) {
		return nil, false, errLabAuthorization
	}

	if plane := l.proxyPlane.Load(); plane != nil {
		if plane.reservationID == reservationID && plane.submit(r) {
			return plane, false, nil
		}

		// Ending, or left from another reservation.
		plane.close(errLabAuthorization)
	}

	plane := newProxyPlane(ctx, p.info.ProfileID, reservationID)
	if !plane.submit(r) {
		return nil, false, errLabBusy
	}

	l.proxyPlane.Store(plane)

	return plane, true, nil
}

// runProxyPlane chains traffic windows while the plane has streams or requests. A window that the
// monitor or another operation refuses is tried again; any other failure ends every stream.
func (l *LabLifecycle) runProxyPlane(plane *proxyPlane, k proxyKeeper) {
	var failure error

	defer func() {
		plane.close(failure)
		l.proxyPlane.CompareAndSwap(plane, nil)
	}()

	for plane.ctx.Err() == nil && !plane.retireIfIdle() {
		err := l.WithPreparedTrafficWindow(plane.parent, plane.reservationID, k.uid, func(windowCtx context.Context) error {
			return l.holdProxyWindowLocked(windowCtx, plane, k)
		})

		if err != nil && !errors.Is(err, errLabBusy) {
			failure = err
			return
		}

		if plane.retireIfIdle() {
			return
		}

		timer := time.NewTimer(proxyWindowRetry)

		select {
		case <-plane.ctx.Done():
			timer.Stop()
		case <-timer.C:
		}
	}
}

// holdProxyWindowLocked keeps one window open for the plane's streams, admitting and dialing new
// requests while enough of it is left. It returns at the hold, or early when the plane ends or has
// nothing left, and only after every dial it started has finished: no dial outlives its window, and
// a dial admitted late may keep the window past the hold, never past its deadline. It never returns a
// stream's own failure, which would fault the tunnel.
func (l *LabLifecycle) holdProxyWindowLocked(windowCtx context.Context, plane *proxyPlane, k proxyKeeper) error {
	deadline, ok := windowCtx.Deadline()
	if !ok {
		return errLabUncertain
	}

	holdUntil := deadline.Add(-time.Second)
	if limit := time.Now().Add(proxyWindowHold); holdUntil.After(limit) {
		holdUntil = limit
	}

	acceptUntil := deadline.Add(-proxyDialBudget)
	if acceptUntil.After(holdUntil) {
		acceptUntil = holdUntil
	}

	dialUntil := deadline.Add(-proxyDialReserve)

	var dials sync.WaitGroup
	defer dials.Wait()

	hold := time.NewTimer(time.Until(holdUntil))
	defer hold.Stop()

	for {
		for time.Now().Before(acceptUntil) {
			r := plane.next()
			if r == nil {
				break
			}

			if r.ctx.Err() != nil {
				plane.finish(r, proxyAdmission{err: errLabBusy})
				continue
			}

			destination, err := l.authorizeProxyRequestLocked(r.req, k, plane.reservationID)
			if err != nil {
				plane.finish(r, proxyAdmission{err: err})
				continue
			}

			dials.Add(1)

			go func() {
				defer dials.Done()
				plane.finish(r, dialProxyStream(windowCtx, dialUntil, plane, r, destination, k.dial))
			}()
		}

		select {
		case <-plane.ctx.Done():
			return nil
		case <-hold.C:
			return nil
		case <-plane.changed:
			if plane.idle() {
				return nil
			}
		}
	}
}

func dialProxyStream(windowCtx context.Context, dialUntil time.Time, plane *proxyPlane, r *proxyRequest,
	destination netip.AddrPort, dial ProxyDialer) proxyAdmission {
	dialCtx, cancelDial := context.WithDeadline(windowCtx, dialUntil)
	stopRequest := context.AfterFunc(r.ctx, cancelDial)
	stopPlane := context.AfterFunc(plane.ctx, cancelDial)
	target, err := dial(dialCtx, r.req.Intent.Namespace, destination)
	stopRequest()
	stopPlane()
	cancelDial()

	// A refused destination is the client's answer, not a fault of the tunnel.
	if err != nil {
		logDetached("proxy stream: %v", err)
		return proxyAdmission{err: errLabUnavailable}
	}

	streamCtx, cancel := context.WithTimeout(plane.ctx, proxyStreamLifetime)
	stream := &proxyStreamState{ctx: streamCtx, cancel: cancel, client: r.conn, target: target}

	if !plane.add(r, stream) {
		cancel()
		_ = target.Close()

		return proxyAdmission{err: errLabBusy}
	}

	return proxyAdmission{stream: stream}
}

// serveProxyStream admits one stream through the plane of the prepared reservation, then relays it.
// The socket outlives every window; its traffic pauses while the gate is closed (during a monitor
// check). It never dials again.
func (l *LabLifecycle) serveProxyStream(
	ctx context.Context,
	conn *net.UnixConn,
	req Request,
	v *helperauth.Verifier,
	runtimeID string,
	proxyUID uint32,
	dial ProxyDialer,
) {
	reply := func(ok bool, code string, bound netip.AddrPort) error {
		ack := ProxyStreamAck{Version: Version, Operation: helperauth.OpOpenProxyStream, OK: ok, Code: code}
		if ok {
			ack.BoundIPv4 = bound.Addr().String()
			ack.BoundPort = bound.Port()
		}

		_ = conn.SetWriteDeadline(time.Now().Add(time.Second))
		err := WriteFrame(conn, ack)
		_ = conn.SetWriteDeadline(time.Time{})

		return err
	}

	// Refused before anything is consumed.
	if l.proxyCount.Add(1) > maxProxyStreams {
		l.proxyCount.Add(-1)
		_ = reply(false, CodeLabBusy, netip.AddrPort{})

		return
	}
	defer l.proxyCount.Add(-1)

	if err := checkProxyRequest(req, v); err != nil {
		_ = reply(false, labCode(err), netip.AddrPort{})
		return
	}

	// The request was read under the ordinary deadline; the stream owns its lifetime from here.
	_ = conn.SetDeadline(time.Time{})

	requestCtx, cancelRequest := context.WithCancel(ctx)
	defer cancelRequest()

	// Before the ack the client sends nothing: a read that returns means it left, and an abandoned
	// request must not dial.
	watching := make(chan struct{})

	go func() {
		defer close(watching)

		if _, err := conn.Read(make([]byte, 1)); !errors.Is(err, os.ErrDeadlineExceeded) {
			cancelRequest()
		}
	}()

	stopWatching := func() {
		_ = conn.SetReadDeadline(time.Now())
		<-watching
		_ = conn.SetReadDeadline(time.Time{})
	}

	r := &proxyRequest{ctx: requestCtx, req: req, conn: conn, result: make(chan proxyAdmission, 1)}

	plane, err := l.joinProxyPlane(ctx, r, proxyKeeper{verifier: v, runtimeID: runtimeID, uid: proxyUID, dial: dial})
	if err != nil {
		stopWatching()
		_ = reply(false, labCode(err), netip.AddrPort{})

		return
	}

	admission := waitProxyAdmission(plane, r)
	stopWatching()

	if admission.err != nil {
		_ = reply(false, labCode(admission.err), netip.AddrPort{})
		return
	}

	stream := admission.stream

	defer func() {
		stream.close()
		plane.remove(stream)
	}()

	local, ok := stream.target.LocalAddr().(*net.TCPAddr)
	if requestCtx.Err() != nil || !ok || reply(true, "", local.AddrPort()) != nil {
		return
	}

	relayProxy(stream.ctx, stream.cancel, conn, stream.target)
}

// waitProxyAdmission waits for the keeper's answer. A request the keeper has not taken is withdrawn
// when it times out, its client leaves or the plane ends; a taken one is always answered, within its
// window.
func waitProxyAdmission(plane *proxyPlane, r *proxyRequest) proxyAdmission {
	timer := time.NewTimer(proxyFirstWindowWait)
	defer timer.Stop()

	var gaveUp error

	select {
	case a := <-r.result:
		return a
	case <-timer.C:
		gaveUp = errLabBusy
	case <-r.ctx.Done():
		gaveUp = errLabBusy
	case <-plane.ctx.Done():
		gaveUp = plane.failure()
	}

	if plane.withdraw(r) {
		return proxyAdmission{err: gaveUp}
	}

	return <-r.result
}

// relayProxy copies both directions and propagates half-closes; the stream ends when both are done
// or on the first error.
func relayProxy(ctx context.Context, cancel context.CancelFunc, client *net.UnixConn, target *net.TCPConn) {
	defer cancel()

	stop := context.AfterFunc(ctx, func() {
		_ = client.Close()
		_ = target.Close()
	})
	defer stop()

	done := make(chan struct{}, 2)

	go func() {
		defer func() { done <- struct{}{} }()

		if _, err := io.Copy(target, client); err != nil {
			cancel()
			return
		}

		_ = target.CloseWrite()
	}()

	go func() {
		defer func() { done <- struct{}{} }()

		if _, err := io.Copy(client, target); err != nil {
			cancel()
			return
		}

		_ = client.CloseWrite()
	}()

	<-done
	<-done
}
