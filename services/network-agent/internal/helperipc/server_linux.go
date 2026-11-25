//go:build linux

package helperipc

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"regexp"
	"sort"
	"sync"
	"syscall"
	"time"

	"github.com/VanChung369/egresslab/services/network-agent/internal/helperauth"
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

// ServerOptions selects what the helper answers. A nil Verifier disables authorization, a nil
// Labs the lab lifecycle, a nil ReadStage the managed vault.
type ServerOptions struct {
	Scan      RecoveryScanner
	Verifier  *helperauth.Verifier
	Labs      *LabLifecycle
	RuntimeID string
	ReadStage StageReader
}

// Serve answers local, single-request connections until ctx is cancelled, without
// authorization: AuthorizeCheck answers "authorization unavailable".
//
// The caller owns socket creation and permissions. A peer whose SO_PEERCRED UID is not
// allowedUID is closed before anything is read from it. Serve dispatches no network change.
func Serve(ctx context.Context, listener *net.UnixListener, allowedUID uint32, scan RecoveryScanner) error {
	return ServeWith(ctx, listener, allowedUID, ServerOptions{Scan: scan})
}

// ServeAuthorized is Serve plus the AuthorizeCheck dry-run when v is not nil.
func ServeAuthorized(ctx context.Context, listener *net.UnixListener, allowedUID uint32, scan RecoveryScanner, v *helperauth.Verifier) error {
	return ServeWith(ctx, listener, allowedUID, ServerOptions{Scan: scan, Verifier: v})
}

// ServeLifecycle adds CreateLab, VerifyLab, DeleteLab and ListLabs when labs is not nil.
func ServeLifecycle(
	ctx context.Context,
	listener *net.UnixListener,
	allowedUID uint32,
	scan RecoveryScanner,
	v *helperauth.Verifier,
	labs *LabLifecycle,
) error {
	return ServeWith(ctx, listener, allowedUID, ServerOptions{Scan: scan, Verifier: v, Labs: labs})
}

// ServeWith returns after all workers finish; the caller then runs Labs.Close.
func ServeWith(ctx context.Context, listener *net.UnixListener, allowedUID uint32, opts ServerOptions) error {
	if opts.Labs != nil && opts.Verifier == nil {
		return errors.New("lab lifecycle requires authorization")
	}

	if opts.ReadStage != nil && (opts.Labs == nil || opts.Verifier == nil) {
		return errors.New("managed vault requires authorized lab lifecycle")
	}

	if opts.RuntimeID != "" && !ValidRuntimeID(opts.RuntimeID) {
		return errors.New("invalid runtime ID")
	}

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

				handle(ctx, conn, allowedUID, opts)
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

func handle(ctx context.Context, conn *net.UnixConn, allowedUID uint32, opts ServerOptions) {
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
		_ = WriteFrame(conn, Response{Version: Version, Code: CodeInvalidRequest, Error: "invalid request frame"})
		return
	}

	if duration := operationResponseTimeout(req.Operation); duration > 0 {
		if err := conn.SetWriteDeadline(time.Now().Add(duration)); err != nil {
			return
		}
	}

	resp := respond(ctx, req, opts)

	if err := WriteFrame(conn, resp); errors.Is(err, ErrInvalidFrame) {
		_ = WriteFrame(conn, Response{
			Version:   Version,
			Operation: resp.Operation,
			Code:      CodeInternal,
			Error:     "response too large",
		})
	}
}

func respond(ctx context.Context, req Request, opts ServerOptions) Response {
	resp := Response{Version: Version, NetworkReady: false}

	if echoableOperation.MatchString(req.Operation) {
		resp.Operation = req.Operation
	}

	refuse := func(code, message string) Response {
		resp.Code, resp.Error = code, message
		return resp
	}

	if req.Version != Version {
		return refuse(CodeInvalidRequest, "unsupported protocol version")
	}

	hasAuthFields := req.Intent != nil || req.Capability != nil
	v, labs := opts.Verifier, opts.Labs

	switch req.Operation {
	case OpPing, OpRecoverScan, OpHelperInfo, OpListLabs:
		if hasAuthFields {
			return refuse(CodeInvalidRequest, "unexpected authorization fields")
		}
	}

	switch req.Operation {
	case OpPing:
		resp.OK = true

	case OpRecoverScan:
		if opts.Scan == nil {
			return refuse(CodeOperationDisabled, "recovery scanner unavailable")
		}

		scanCtx, cancel := context.WithTimeout(ctx, scanTimeout)
		items, err := opts.Scan(scanCtx)
		cancel()

		// Scanner errors stay on the helper side; they can name internal paths.
		if err != nil || len(items) > maxRecoveryItems {
			return refuse(CodeInternal, "recovery scan failed")
		}

		resp.OK = true
		resp.Items = items

	case OpHelperInfo:
		// Identity handles a nil verifier: an unconfigured helper still answers.
		helperID, fingerprint := v.Identity()

		resp.Info = &HelperInfo{
			AuthorizationConfigured: v != nil,
			HelperID:                helperID,
			PublicKeySHA256:         fingerprint,
			RuntimeID:               opts.RuntimeID,
		}
		resp.OK = true

	case OpAuthorizeCheck:
		if v == nil || req.Intent == nil || req.Capability == nil {
			return refuse(CodeOperationDisabled, "authorization unavailable")
		}

		// Do not tell the client whether the signature, binding, expiry or nonce failed.
		if err := v.VerifyAndConsume(*req.Capability, *req.Intent); err != nil {
			return refuse(CodeAuthorizationDenied, "authorization denied")
		}

		// Dry-run only: nothing is executed for an accepted capability.
		resp.OK = true

	case OpStageInfo:
		if req.Capability != nil || !validStageIntent(req.Intent) {
			return refuse(CodeInvalidRequest, "invalid stage request")
		}

		if opts.ReadStage == nil {
			return refuse(CodeOperationDisabled, "managed vault not enabled")
		}

		stage, err := opts.ReadStage(req.Intent.ProfileID)
		if errors.Is(err, ErrStageNotFound) {
			return refuse(CodeStageNotFound, "WireGuard stage not found")
		}

		if err != nil || !validStageInfo(&stage, req.Intent.ProfileID) {
			log.Printf("stage info: %v", err)
			return refuse(CodeInternal, "stage metadata unavailable")
		}

		resp.OK = true
		resp.Stage = &stage

	case OpListLabs:
		if labs == nil {
			return refuse(CodeOperationDisabled, "operation not enabled")
		}

		items, err := labs.snapshot()
		if err != nil {
			return refuse(labCode(err), "lab registry unavailable")
		}

		resp.OK = true
		resp.Labs = items

	case helperauth.OpPermitProbe:
		if labs == nil || labs.probes == nil {
			return refuse(CodeOperationDisabled, "operation not enabled")
		}

		if ctx.Err() != nil {
			return refuse(CodeRuntimeUnavailable, "helper is shutting down")
		}

		// Like the lifecycle operations, shutdown waits for a running probe and its cleanup.
		probeCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), lifecycleTimeout)
		info, err := labs.executeProbe(probeCtx, req, v)
		cancel()

		if err != nil {
			code := labCode(err)
			if code != CodeAuthorizationDenied {
				log.Printf("managed probe: %s: %v", code, err)
			}

			return refuse(code, labMessages[code])
		}

		resp.OK = true
		resp.Probe = &info

	case helperauth.OpCreateLab, OpVerifyLab, OpDeleteLab, helperauth.OpConnectTunnel, OpDisconnect:
		if labs == nil || (isTunnelOp(req.Operation) && labs.tunnels == nil) {
			return refuse(CodeOperationDisabled, "operation not enabled")
		}

		if ctx.Err() != nil {
			return refuse(CodeRuntimeUnavailable, "helper is shutting down")
		}

		// Shutdown must not kill a kernel command halfway (after "ip netns add" but before
		// ownership is recorded); the server waits for the operation instead.
		labCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), lifecycleTimeout)
		lab, err := labs.execute(labCtx, req, v)
		cancel()

		if err != nil {
			code := labCode(err)
			if code != CodeAuthorizationDenied {
				log.Printf("lab lifecycle %s: %s: %v", req.Operation, code, err)
			}

			return refuse(code, labMessages[code])
		}

		resp.OK = true
		resp.Lab = &lab

	default:
		// Unknown operations stay disabled, with or without a valid capability.
		return refuse(CodeOperationDisabled, "operation not enabled")
	}

	return resp
}

func (l *LabLifecycle) snapshot() ([]LabInfo, error) {
	if l == nil {
		return nil, errLabUnavailable
	}

	if !l.mu.TryLock() {
		return nil, errLabBusy
	}
	defer l.mu.Unlock()

	if l.closed {
		return nil, errLabUnavailable
	}

	items := make([]LabInfo, 0, len(l.labs))
	for _, lab := range l.labs {
		items = append(items, lab)
	}

	sort.Slice(items, func(i, j int) bool { return items[i].ProfileID < items[j].ProfileID })

	return items, nil
}

func isTunnelOp(op string) bool {
	return op == helperauth.OpConnectTunnel || op == OpDisconnect
}
