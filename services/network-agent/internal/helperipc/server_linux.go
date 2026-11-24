//go:build linux

package helperipc

import (
	"context"
	"errors"
	"fmt"
	"net"
	"regexp"
	"sync"
	"syscall"
	"time"
)

const (
	maxConnections   = 16
	maxRecoveryItems = 128
	requestTimeout   = 5 * time.Second
	scanTimeout      = 3 * time.Second
)

// Only short, plain operation names are echoed back to the client.
var echoableOperation = regexp.MustCompile(`^[A-Za-z]{1,32}$`)

type RecoveryScanner func(context.Context) ([]RecoveryItem, error)

// Serve answers local, single-request connections until ctx is cancelled.
//
// The caller owns socket creation and permissions. A peer whose SO_PEERCRED UID is not
// allowedUID is closed before anything is read from it. No network-changing operation exists.
func Serve(ctx context.Context, listener *net.UnixListener, allowedUID uint32, scan RecoveryScanner) error {
	if listener == nil || allowedUID == 0 {
		return errors.New("invalid helper listener or client UID")
	}

	done := make(chan struct{})
	defer close(done)
	defer listener.Close()

	go func() {
		select {
		case <-ctx.Done():
			listener.Close()
		case <-done:
		}
	}()

	slots := make(chan struct{}, maxConnections)

	var workers sync.WaitGroup
	defer workers.Wait()

	for {
		conn, err := listener.AcceptUnix()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return fmt.Errorf("accept helper IPC: %w", err)
		}

		select {
		case slots <- struct{}{}:
			workers.Add(1)

			go func() {
				defer workers.Done()
				defer func() { <-slots }()

				handle(ctx, conn, allowedUID, scan)
			}()

		default:
			conn.Close()
		}
	}
}

func peerUID(conn *net.UnixConn) (uint32, error) {
	raw, err := conn.SyscallConn()
	if err != nil {
		return 0, err
	}

	var uid uint32
	var optErr error

	if err := raw.Control(func(fd uintptr) {
		var cred *syscall.Ucred

		cred, optErr = syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
		if optErr == nil {
			uid = cred.Uid
		}
	}); err != nil {
		return 0, err
	}

	return uid, optErr
}

func handle(ctx context.Context, conn *net.UnixConn, allowedUID uint32, scan RecoveryScanner) {
	defer conn.Close()

	// Authenticate the peer before reading or parsing anything from the socket.
	// Unauthorized peers get no response.
	uid, err := peerUID(conn)
	if err != nil || uid != allowedUID {
		return
	}

	if err := conn.SetDeadline(time.Now().Add(requestTimeout)); err != nil {
		return
	}

	var req Request
	if err := ReadFrame(conn, &req); err != nil {
		// Do not echo anything from a frame that failed to parse.
		_ = WriteFrame(conn, Response{Version: Version, Error: "invalid request frame"})
		return
	}

	resp := respond(ctx, req, scan)

	if err := WriteFrame(conn, resp); errors.Is(err, ErrInvalidFrame) {
		_ = WriteFrame(conn, Response{
			Version:   Version,
			Operation: resp.Operation,
			Error:     "response too large",
		})
	}
}

func respond(ctx context.Context, req Request, scan RecoveryScanner) Response {
	resp := Response{Version: Version, NetworkReady: false}

	if echoableOperation.MatchString(req.Operation) {
		resp.Operation = req.Operation
	}

	if req.Version != Version {
		resp.Error = "unsupported protocol version"
		return resp
	}

	switch req.Operation {
	case OpPing:
		resp.OK = true

	case OpRecoverScan:
		if scan == nil {
			resp.Error = "recovery scanner unavailable"
			return resp
		}

		scanCtx, cancel := context.WithTimeout(ctx, scanTimeout)
		items, err := scan(scanCtx)
		cancel()

		// Scanner errors stay on the helper side; they can name internal paths.
		if err != nil || len(items) > maxRecoveryItems {
			resp.Error = "recovery scan failed"
			return resp
		}

		resp.OK = true
		resp.Items = items

	default:
		// All network mutations are disabled until capability authorization exists.
		resp.Error = "operation not enabled"
	}

	return resp
}
