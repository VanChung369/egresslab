//go:build linux

package helperipc

import (
	"context"
	"errors"
	"io"
	"log"
	"net"
	"net/netip"
	"os"
	"time"

	"github.com/VanChung369/egresslab/services/network-agent/internal/helperauth"
)

const (
	// proxyFirstWindowWait bounds how long a new stream waits for its first traffic window.
	proxyFirstWindowWait = 45 * time.Second

	// proxyWindowHold caps one window, so a due monitor check never waits long.
	proxyWindowHold = 6 * time.Second

	proxyWindowRetry = 250 * time.Millisecond
)

// ProxyDialer opens one TCP connection inside namespace as the proxy user (agent.ProxyDialer).
type ProxyDialer func(ctx context.Context, namespace string, destination netip.AddrPort) (*net.TCPConn, error)

// authorizeProxyStream binds the signed request to the prepared lease of this helper epoch and its
// fresh monitoring health, consumes the capability, and replaces any earlier stream.
func (l *LabLifecycle) authorizeProxyStream(
	ctx context.Context,
	req Request,
	v *helperauth.Verifier,
	conn *net.UnixConn,
	runtimeID string,
) (*proxyStreamState, netip.AddrPort, error) {
	if req.Version != Version || req.Operation != helperauth.OpOpenProxyStream || req.Intent == nil ||
		req.Capability == nil || v == nil || !helperauth.ValidOpenProxyStreamIntent(*req.Intent) {
		return nil, netip.AddrPort{}, errLabInvalid
	}

	destination, ok := req.Intent.ProxyDestination()
	if !ok {
		return nil, netip.AddrPort{}, errLabInvalid
	}

	// Only a request that is already authorized may interrupt the running stream.
	if v.Check(*req.Capability, *req.Intent) != nil {
		return nil, netip.AddrPort{}, errLabAuthorization
	}

	if !l.lockPreemptingProxyStream(ctx, true) {
		return nil, netip.AddrPort{}, errLabBusy
	}
	defer l.mu.Unlock()

	p := l.preparedLease

	if l.closed || l.blockCreation || p == nil || !p.monitor.fresh(time.Now()) {
		return nil, netip.AddrPort{}, errLabAuthorization
	}

	lab, exists := l.labs[p.info.ProfileID]
	if !exists || lab.Namespace != p.info.Namespace || lab.State != LabTunnelConfigured ||
		l.tunnelProfile != p.info.ProfileID {
		return nil, netip.AddrPort{}, errLabUncertain
	}

	helperID, fingerprint := v.Identity()
	if p.info.HelperID != helperID || p.info.RuntimeID != runtimeID || p.info.PublicKeySHA256 != fingerprint {
		return nil, netip.AddrPort{}, errLabAuthorization
	}

	binding, err := prepareLeaseIntent(p.info.CandidateInfo, p.info.AuthorityID, p.info.ReservationID)
	if err != nil {
		return nil, netip.AddrPort{}, errLabAuthorization
	}

	expected, err := helperauth.NewOpenProxyStreamIntent(binding, destination)
	if err != nil || *req.Intent != expected {
		return nil, netip.AddrPort{}, errLabAuthorization
	}

	nonce := req.Capability.Claims.Nonce
	if nonce == p.info.EvidenceNonce || nonce == p.info.ReservationNonce || nonce == p.info.PreparationNonce {
		return nil, netip.AddrPort{}, errLabAuthorization
	}

	if err := v.VerifyAndConsume(*req.Capability, expected); err != nil {
		return nil, netip.AddrPort{}, errLabAuthorization
	}

	// One stream per helper: a new authorized stream replaces a stale one.
	l.closeProxyStreamLocked()

	streamCtx, cancel := context.WithTimeout(ctx, proxyStreamLifetime)

	stream := &proxyStreamState{
		profileID:     p.info.ProfileID,
		reservationID: p.info.ReservationID,
		ctx:           streamCtx,
		cancel:        cancel,
		client:        conn,
	}

	l.proxyStream = stream
	l.proxyActive.Store(stream)

	return stream, destination, nil
}

// serveProxyStream dials once inside a traffic window, then keeps reopening windows while the stream
// lives: the socket outlives every window, and its traffic pauses while the gate is closed (during a
// monitor check). It never dials again and never opens a window past the stream.
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

	stream, destination, err := l.authorizeProxyStream(ctx, req, v, conn, runtimeID)
	if err != nil {
		_ = reply(false, labCode(err), netip.AddrPort{})
		return
	}

	defer func() {
		l.mu.Lock()
		defer l.mu.Unlock()

		if l.proxyStream == stream {
			l.closeProxyStreamLocked()
		} else {
			stream.closeLocked()
		}
	}()

	// The request was read under the ordinary deadline; the stream owns its lifetime from here.
	_ = conn.SetDeadline(time.Time{})

	stop := context.AfterFunc(stream.ctx, func() { _ = conn.Close() })
	defer stop()

	// Before the ack the client sends nothing: a read that returns means it left, and an abandoned
	// request must not dial.
	watching := make(chan struct{})

	go func() {
		defer close(watching)

		if _, err := conn.Read(make([]byte, 1)); !errors.Is(err, os.ErrDeadlineExceeded) {
			stream.cancel()
		}
	}()

	stopWatching := func() {
		_ = conn.SetReadDeadline(time.Now())
		<-watching
		_ = conn.SetReadDeadline(time.Time{})
	}

	openUntil := time.Now().Add(proxyFirstWindowWait)
	opened := false
	failure := ""

	for stream.ctx.Err() == nil {
		if !opened && !time.Now().Before(openUntil) {
			failure = CodeLabBusy
			break
		}

		var dialErr error

		err := l.WithPreparedTrafficWindow(ctx, stream.reservationID, proxyUID, func(windowCtx context.Context) error {
			if stream.ctx.Err() != nil || l.proxyStream != stream {
				return nil
			}

			if !opened {
				dialCtx, cancelDial := context.WithCancel(windowCtx)
				stopDial := context.AfterFunc(stream.ctx, cancelDial)
				target, err := dial(dialCtx, req.Intent.Namespace, destination)
				stopDial()
				cancelDial()

				if err != nil {
					dialErr = err
					return nil
				}

				stopWatching()

				if stream.ctx.Err() != nil {
					_ = target.Close()
					return nil
				}

				stream.target = target

				local, ok := target.LocalAddr().(*net.TCPAddr)
				if !ok || reply(true, "", local.AddrPort()) != nil {
					dialErr = errLabUncertain
					return nil
				}

				opened = true

				go relayProxy(stream.ctx, stream.cancel, conn, target)
			}

			deadline, ok := windowCtx.Deadline()
			if !ok {
				return errLabUncertain
			}

			hold := time.Until(deadline) - time.Second
			if hold > proxyWindowHold {
				hold = proxyWindowHold
			}

			if hold <= 0 {
				return nil
			}

			timer := time.NewTimer(hold)
			defer timer.Stop()

			select {
			case <-stream.ctx.Done():
			case <-timer.C:
			}

			return nil
		})

		// A refused destination is the client's answer, not a fault of the tunnel.
		if dialErr != nil {
			log.Printf("proxy stream: %v", dialErr)

			if !opened {
				failure = CodeRuntimeUnavailable
			}

			break
		}

		if err != nil && !errors.Is(err, errLabBusy) {
			if !opened {
				failure = labCode(err)
			}

			break
		}

		timer := time.NewTimer(proxyWindowRetry)

		select {
		case <-stream.ctx.Done():
			timer.Stop()
		case <-timer.C:
		}
	}

	if !opened {
		if failure == "" {
			failure = CodeLabBusy
		}

		_ = reply(false, failure, netip.AddrPort{})
	}
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
