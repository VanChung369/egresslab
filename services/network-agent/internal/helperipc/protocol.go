// Package helperipc is the local protocol between the unprivileged network agent and the
// privileged network helper.
//
// Each connection carries one request and one response. A frame is a 4-byte big-endian length
// followed by at most MaxFrameBytes of JSON. Besides read-only operations and the AuthorizeCheck
// dry-run, a helper started with the lab lifecycle enabled creates (with a signed capability),
// verifies and deletes sealed lab namespaces. Tunnel, probe and multi-source probe operations are
// refused unless the helper was started with them enabled (docs/PRIVILEGED-HELPER.md).
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
	Version      int             `json:"version"`
	Operation    string          `json:"operation"`
	OK           bool            `json:"ok"`
	NetworkReady bool            `json:"network_ready"`
	Code         string          `json:"code,omitempty"`
	Error        string          `json:"error,omitempty"`
	Items        []RecoveryItem  `json:"items,omitempty"`
	Info         *HelperInfo     `json:"helper_info,omitempty"`
	Lab          *LabInfo        `json:"lab,omitempty"`
	Labs         []LabInfo       `json:"labs,omitempty"`
	Stage        *StageInfo      `json:"stage,omitempty"`
	Probe        *ProbeInfo      `json:"probe,omitempty"`
	MultiProbe   *MultiProbeInfo `json:"multi_probe,omitempty"`

	MultiProbePolicy *MultiProbePolicyInfo `json:"multi_probe_policy,omitempty"`
	MultiProbeTarget *MultiProbeTargetInfo `json:"multi_probe_target,omitempty"`
	Candidate        *CandidateInfo        `json:"candidate,omitempty"`
	PreparedLease    *PreparedLeaseInfo    `json:"prepared_lease,omitempty"`
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

// Call sends one read-only operation (Ping, RecoverScan, HelperInfo or ListLabs) to the helper.
// It never retries.
func Call(ctx context.Context, socketPath string, op string) (Response, error) {
	if op != OpPing && op != OpRecoverScan && op != OpHelperInfo && op != OpListLabs && op != OpMultiProbePolicy {
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
		return Response{}, &Error{Code: CodeRuntimeUnavailable, Message: "helper unreachable: " + err.Error()}
	}
	defer conn.Close()

	// Test servers on temporary paths run unprivileged.
	if socketPath == SocketPath {
		if err := verifyProductionPeer(conn); err != nil {
			return Response{}, &Error{Code: CodeRuntimeUnavailable, Message: err.Error()}
		}
	}

	timeout := 5 * time.Second
	if duration := operationResponseTimeout(req.Operation); duration > 0 {
		timeout = duration + 5*time.Second
	}

	deadline := time.Now().Add(timeout)
	if end, ok := ctx.Deadline(); ok && end.Before(deadline) {
		deadline = end
	}

	if err := conn.SetDeadline(deadline); err != nil {
		return Response{}, err
	}

	sentAt := time.Now()

	if err := WriteFrame(conn, req); err != nil {
		return Response{}, err
	}

	var resp Response
	if err := ReadFrame(conn, &resp); err != nil {
		return Response{}, err
	}

	receivedAt := time.Now()

	if olderHelperDisabled(req, resp) {
		return Response{}, &Error{Code: CodeOperationDisabled, Message: "operation not enabled"}
	}

	if resp.Version != Version ||
		resp.Operation != req.Operation ||
		resp.NetworkReady ||
		(resp.OK && (resp.Error != "" || resp.Code != "")) ||
		(len(resp.Items) != 0 && req.Operation != OpRecoverScan) {
		return Response{}, errors.New("helper returned an invalid response")
	}

	// Accept helper metadata only when it was asked for and the request succeeded.
	if resp.Info != nil && (req.Operation != OpHelperInfo || !resp.OK) {
		return Response{}, errors.New("unexpected helper identity metadata")
	}

	if req.Operation == OpHelperInfo && resp.OK && !resp.Info.valid() {
		return Response{}, errors.New("invalid helper identity metadata")
	}

	if !validLabResponse(req, resp) {
		return Response{}, errors.New("invalid lab lifecycle response")
	}

	if !validLabListResponse(req, resp) {
		return Response{}, errors.New("invalid managed lab list")
	}

	if !validStageResponse(req, resp) {
		return Response{}, errors.New("invalid WireGuard stage response")
	}

	if !validProbeResponse(req, resp) {
		return Response{}, errors.New("invalid managed probe response")
	}

	if !validMultiProbeResponse(req, resp) {
		return Response{}, errors.New("invalid managed multi-source probe response")
	}

	if !validMultiProbePolicyResponse(req, resp) {
		return Response{}, errors.New("invalid multi-source policy response")
	}

	if !validMultiProbeTargetResponse(req, resp) {
		return Response{}, errors.New("invalid multi-source target response")
	}

	// helperctl runs in the helper's own runtime, so this is the same wall clock; the helper's
	// monotonic deadline stays authoritative.
	if !validCandidateResponse(req, resp, receivedAt) {
		return Response{}, errors.New("invalid or expired egress candidate response")
	}

	if !validPreparedLeaseResponse(req, resp, receivedAt) {
		return Response{}, errors.New("invalid or expired prepared lease response")
	}

	// The attempt must lie between writing this request and reading its answer.
	if resp.MultiProbe != nil && !multiProbeWithin(resp.MultiProbe, sentAt, receivedAt) {
		return Response{}, errors.New("multi-source evidence outside this request")
	}

	if !resp.OK {
		code, message := resp.Code, resp.Error
		if !knownCodes[code] {
			code = CodeInternal
		}

		if message == "" {
			message = "helper denied request"
		}

		return Response{}, &Error{Code: code, Message: message}
	}

	return resp, nil
}

// CreateSealedLab: the helper picks the namespace name.
func CreateSealedLab(
	ctx context.Context,
	socketPath string,
	profileID string,
	capability helperauth.SignedCapability,
) (Response, error) {
	intent := helperauth.Intent{Operation: helperauth.OpCreateLab, ProfileID: profileID}

	return callRequest(ctx, socketPath, Request{
		Version:    Version,
		Operation:  intent.Operation,
		Intent:     &intent,
		Capability: &capability,
	})
}

func VerifySealedLab(ctx context.Context, socketPath, profileID, namespace string) (Response, error) {
	intent := helperauth.Intent{Operation: OpVerifyLab, ProfileID: profileID, Namespace: namespace}

	return callRequest(ctx, socketPath, Request{Version: Version, Operation: OpVerifyLab, Intent: &intent})
}

// DeleteSealedLab needs no capability, so cleanup works while the controller is unreachable.
func DeleteSealedLab(ctx context.Context, socketPath, profileID, namespace string) (Response, error) {
	intent := helperauth.Intent{Operation: OpDeleteLab, ProfileID: profileID, Namespace: namespace}

	return callRequest(ctx, socketPath, Request{Version: Version, Operation: OpDeleteLab, Intent: &intent})
}
