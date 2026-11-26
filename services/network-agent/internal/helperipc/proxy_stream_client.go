package helperipc

import (
	"context"
	"errors"
	"net"
	"time"

	"github.com/VanChung369/egresslab/services/network-agent/internal/helperauth"
)

// proxyStreamHandshake covers the helper's wait for a first traffic window and the dial.
const proxyStreamHandshake = 60 * time.Second

// OpenProxyStream sends one signed stream request and returns the connection once the helper
// acknowledged it; from then on the connection carries only raw TCP bytes. A refusal is returned
// with its ack and a closed connection.
func OpenProxyStream(
	ctx context.Context,
	socketPath string,
	capability helperauth.SignedCapability,
) (*net.UnixConn, ProxyStreamAck, error) {
	intent := capability.Claims.Intent
	if !helperauth.ValidOpenProxyStreamIntent(intent) {
		return nil, ProxyStreamAck{}, &Error{Code: CodeInvalidRequest, Message: "invalid proxy stream capability"}
	}

	dialer := net.Dialer{Timeout: 3 * time.Second}

	raw, err := dialer.DialContext(ctx, "unix", socketPath)
	if err != nil {
		return nil, ProxyStreamAck{}, &Error{Code: CodeRuntimeUnavailable, Message: "helper unreachable: " + err.Error()}
	}

	conn, ok := raw.(*net.UnixConn)
	if !ok {
		_ = raw.Close()
		return nil, ProxyStreamAck{}, errors.New("expected Unix socket")
	}

	success := false
	defer func() {
		if !success {
			_ = conn.Close()
		}
	}()

	if socketPath == SocketPath {
		if err := verifyProductionPeer(conn); err != nil {
			return nil, ProxyStreamAck{}, &Error{Code: CodeRuntimeUnavailable, Message: err.Error()}
		}
	}

	deadline := time.Now().Add(proxyStreamHandshake)
	if end, ok := ctx.Deadline(); ok && end.Before(deadline) {
		deadline = end
	}

	if err := conn.SetDeadline(deadline); err != nil {
		return nil, ProxyStreamAck{}, err
	}

	req := Request{Version: Version, Operation: intent.Operation, Intent: &intent, Capability: &capability}
	if err := WriteFrame(conn, req); err != nil {
		return nil, ProxyStreamAck{}, err
	}

	// ReadFrame reads exactly one frame, so no stream byte is consumed with it.
	var ack ProxyStreamAck
	if err := ReadFrame(conn, &ack); err != nil {
		return nil, ProxyStreamAck{}, &Error{Code: CodeRuntimeUnavailable, Message: "no proxy stream acknowledgement"}
	}

	if !ack.valid() {
		return nil, ProxyStreamAck{}, errors.New("invalid proxy stream acknowledgement")
	}

	if !ack.OK {
		return nil, ack, &Error{Code: ack.Code, Message: "proxy stream refused"}
	}

	if err := conn.SetDeadline(time.Time{}); err != nil {
		return nil, ProxyStreamAck{}, err
	}

	success = true

	return conn, ack, nil
}
