//go:build linux

package helperipc

import (
	"context"
	"net"
	"os"
	"testing"

	"github.com/VanChung369/egresslab/services/network-agent/internal/helperauth"
)

func TestMultiProbePolicyIPC(t *testing.T) {
	requireUnprivileged(t)

	ctx := context.Background()
	f, backend := newMultiProbeFixture(t)

	socket := serveWith(t, func(ctx context.Context, listener *net.UnixListener) error {
		return ServeWith(ctx, listener, uint32(os.Getuid()), ServerOptions{
			Verifier:  f.verifier,
			Labs:      f.labs,
			RuntimeID: multiProbeTestRuntimeID,
		})
	})

	identity, err := Call(ctx, socket, OpHelperInfo)
	if err != nil {
		t.Fatal(err)
	}

	response, err := Call(ctx, socket, OpMultiProbePolicy)
	if err != nil || response.MultiProbePolicy == nil || response.NetworkReady || response.Operation != OpMultiProbePolicy {
		t.Fatalf("invalid policy response: %+v %v", response, err)
	}

	if *response.MultiProbePolicy != (MultiProbePolicyInfo{
		Policy:          helperauth.OpPermitMultiProbe,
		IdentIPv4:       backend.pin.String(),
		HelperID:        identity.Info.HelperID,
		RuntimeID:       identity.Info.RuntimeID,
		PublicKeySHA256: identity.Info.PublicKeySHA256,
	}) {
		t.Fatalf("policy not bound to this helper: %+v %+v", response.MultiProbePolicy, identity.Info)
	}

	// A read-only operation refuses authorization fields, and consumes nothing.
	req := f.mint(multiProbeIntent(f.lab, backend.pin.String()))

	bad := rawRequest(t, socket, Request{
		Version:    Version,
		Operation:  OpMultiProbePolicy,
		Intent:     req.Intent,
		Capability: req.Capability,
	})

	if bad.OK || bad.Code != CodeInvalidRequest || bad.MultiProbePolicy != nil {
		t.Fatalf("authorization fields accepted by policy discovery: %+v", bad)
	}

	if backend.calls != 0 {
		t.Fatal("policy discovery ran a probe")
	}

	result, err := ProbeEgressMulti(ctx, socket, f.lab.ProfileID, f.lab.Namespace, *req.Capability)
	if err != nil || result.MultiProbe == nil {
		t.Fatalf("capability consumed by policy discovery: %v", err)
	}
}

func TestMultiProbePolicyDisabledIPC(t *testing.T) {
	requireUnprivileged(t)

	f := newTunnelFixture(t)
	socket := serveLifecycleTest(t, f.verifier, f.labs)

	response, err := Call(context.Background(), socket, OpMultiProbePolicy)
	if ErrorCode(err) != CodeOperationDisabled || response.MultiProbePolicy != nil {
		t.Fatalf("policy of a helper without the multi-source probe: %+v %v", response, err)
	}
}

// The client applies the same checks to what a helper sends back.
func TestClientValidatesMultiProbePolicy(t *testing.T) {
	requireUnprivileged(t)

	ctx := context.Background()
	valid := MultiProbePolicyInfo{
		Policy:          helperauth.OpPermitMultiProbe,
		IdentIPv4:       "9.9.9.9",
		HelperID:        "helper_0123456789abcdef0123456789abcdef",
		RuntimeID:       multiProbeTestRuntimeID,
		PublicKeySHA256: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
	}

	invalid := valid
	invalid.IdentIPv4 = "10.0.0.1"

	for name, tt := range map[string]struct {
		op   string
		resp func(Request) Response
		ok   bool
	}{
		"valid policy": {OpMultiProbePolicy, func(r Request) Response {
			return Response{Version: Version, Operation: r.Operation, OK: true, MultiProbePolicy: &valid}
		}, true},
		"invalid policy": {OpMultiProbePolicy, func(r Request) Response {
			return Response{Version: Version, Operation: r.Operation, OK: true, MultiProbePolicy: &invalid}
		}, false},
		"missing policy": {OpMultiProbePolicy, func(r Request) Response {
			return Response{Version: Version, Operation: r.Operation, OK: true}
		}, false},
		"failure with policy": {OpMultiProbePolicy, func(r Request) Response {
			return Response{Version: Version, Operation: r.Operation, Code: CodeOperationDisabled, MultiProbePolicy: &valid}
		}, false},
		"unsolicited policy": {OpPing, func(r Request) Response {
			return Response{Version: Version, Operation: r.Operation, OK: true, MultiProbePolicy: &valid}
		}, false},
	} {
		socket := fakeHelper(t, tt.resp)

		response, err := Call(ctx, socket, tt.op)
		if (err == nil) != tt.ok || (err != nil && response.MultiProbePolicy != nil) {
			t.Errorf("%s: want accepted %t: %+v %v", name, tt.ok, response, err)
		}

		if !tt.ok && ErrorCode(err) != CodeInternal {
			t.Errorf("%s: code %s", name, ErrorCode(err))
		}
	}
}
