// Package helperipc is the local protocol between the unprivileged network agent and the
// privileged network helper.
//
// Each connection carries one request and one response. A frame is a 4-byte big-endian length
// followed by at most MaxFrameBytes of JSON. Only read-only operations and the AuthorizeCheck
// dry-run exist; every network mutation is refused (docs/PRIVILEGED-HELPER.md).
package helperipc

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"time"

	"github.com/VanChung369/egresslab/services/network-agent/internal/helperauth"
)

const (
	Version       = 1
	MaxFrameBytes = 64 * 1024
	OpPing        = "Ping"
	OpRecoverScan = "RecoverScan"
	SocketPath    = "/run/egresslab/helper.sock"

	// OpAuthorizeCheck verifies and consumes a capability. It is a dry-run: it changes nothing in
	// the kernel and does not authorize a later operation.
	OpAuthorizeCheck = "AuthorizeCheck"
)

type Request struct {
	Version    int                          `json:"version"`
	Operation  string                       `json:"operation"`
	Intent     *helperauth.Intent           `json:"intent,omitempty"`
	Capability *helperauth.SignedCapability `json:"capability,omitempty"`
}

type RecoveryItem struct {
	Kind   string `json:"kind"`
	Name   string `json:"name"`
	State  string `json:"state"`
	Detail string `json:"detail,omitempty"`
}

type Response struct {
	Version      int            `json:"version"`
	Operation    string         `json:"operation"`
	OK           bool           `json:"ok"`
	NetworkReady bool           `json:"network_ready"`
	Error        string         `json:"error,omitempty"`
	Items        []RecoveryItem `json:"items,omitempty"`
}

var ErrInvalidFrame = errors.New("invalid helper IPC frame")

// ReadFrame reads one length-prefixed JSON document into dest.
// Empty or oversized frames, unknown fields and trailing content are rejected.
func ReadFrame(r io.Reader, dest any) error {
	var header [4]byte
	if _, err := io.ReadFull(r, header[:]); err != nil {
		return fmt.Errorf("%w: header: %w", ErrInvalidFrame, err)
	}

	size := binary.BigEndian.Uint32(header[:])
	if size == 0 || size > MaxFrameBytes {
		return fmt.Errorf("%w: size %d", ErrInvalidFrame, size)
	}

	payload := make([]byte, size)
	if _, err := io.ReadFull(r, payload); err != nil {
		return fmt.Errorf("%w: body: %w", ErrInvalidFrame, err)
	}

	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()

	if err := decoder.Decode(dest); err != nil {
		return fmt.Errorf("%w: JSON: %w", ErrInvalidFrame, err)
	}

	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return fmt.Errorf("%w: trailing content", ErrInvalidFrame)
	}

	return nil
}

// WriteFrame writes value as one length-prefixed JSON document.
func WriteFrame(w io.Writer, value any) error {
	payload, err := json.Marshal(value)
	if err != nil {
		return err
	}

	if len(payload) == 0 || len(payload) > MaxFrameBytes {
		return fmt.Errorf("%w: size %d", ErrInvalidFrame, len(payload))
	}

	frame := make([]byte, 4, 4+len(payload))
	binary.BigEndian.PutUint32(frame, uint32(len(payload)))
	frame = append(frame, payload...)

	_, err = w.Write(frame)
	return err
}

// Call sends one read-only operation to the helper. It never retries.
func Call(ctx context.Context, socketPath string, op string) (Response, error) {
	if op != OpPing && op != OpRecoverScan {
		return Response{}, errors.New("operation is not available to the helper client")
	}

	return callRequest(ctx, socketPath, Request{Version: Version, Operation: op})
}

// CheckCapability asks the helper to verify capability against intent. Success consumes the
// nonce but creates no namespace, configures no tunnel and enables no network access.
func CheckCapability(
	ctx context.Context,
	socketPath string,
	intent helperauth.Intent,
	capability helperauth.SignedCapability,
) (Response, error) {
	return callRequest(ctx, socketPath, Request{
		Version:    Version,
		Operation:  OpAuthorizeCheck,
		Intent:     &intent,
		Capability: &capability,
	})
}

func callRequest(ctx context.Context, socketPath string, req Request) (Response, error) {
	dialer := net.Dialer{Timeout: 3 * time.Second}

	conn, err := dialer.DialContext(ctx, "unix", socketPath)
	if err != nil {
		return Response{}, err
	}
	defer conn.Close()

	deadline := time.Now().Add(5 * time.Second)
	if end, ok := ctx.Deadline(); ok && end.Before(deadline) {
		deadline = end
	}

	if err := conn.SetDeadline(deadline); err != nil {
		return Response{}, err
	}

	if err := WriteFrame(conn, req); err != nil {
		return Response{}, err
	}

	var resp Response
	if err := ReadFrame(conn, &resp); err != nil {
		return Response{}, err
	}

	if resp.Version != Version ||
		resp.Operation != req.Operation ||
		resp.NetworkReady ||
		(resp.OK && resp.Error != "") ||
		(len(resp.Items) != 0 && req.Operation != OpRecoverScan) {
		return Response{}, errors.New("helper returned an invalid response")
	}

	if !resp.OK {
		if resp.Error == "" {
			return Response{}, errors.New("helper denied request")
		}
		return Response{}, errors.New(resp.Error)
	}

	return resp, nil
}
