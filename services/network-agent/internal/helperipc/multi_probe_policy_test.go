package helperipc

import (
	"context"
	"errors"
	"testing"

	"github.com/VanChung369/egresslab/services/network-agent/internal/helperauth"
)

const multiProbeTestRuntimeID = "runtime_0123456789abcdef0123456789abcdef"

func TestReadMultiProbePolicy(t *testing.T) {
	ctx := context.Background()
	f, backend := newMultiProbeFixture(t)

	policy, err := f.labs.readMultiProbePolicy(ctx, f.verifier, multiProbeTestRuntimeID)
	helperID, fingerprint := f.verifier.Identity()

	if err != nil || policy != (MultiProbePolicyInfo{
		Policy:          helperauth.OpPermitMultiProbe,
		IdentIPv4:       "9.9.9.9",
		HelperID:        helperID,
		RuntimeID:       multiProbeTestRuntimeID,
		PublicKeySHA256: fingerprint,
	}) {
		t.Fatalf("unexpected policy: %+v %v", policy, err)
	}

	cancelled, cancel := context.WithCancel(ctx)
	cancel()

	for name, tt := range map[string]struct {
		setup, undo func()
		cancelled   bool
		noVerifier  bool
		noRuntimeID bool
		code        string
	}{
		"busy":   {setup: func() { f.labs.mu.Lock() }, undo: func() { f.labs.mu.Unlock() }, code: CodeLabBusy},
		"closed": {setup: func() { f.labs.closed = true }, undo: func() { f.labs.closed = false }, code: CodeRuntimeUnavailable},
		"kernel uncertain": {setup: func() { f.labs.blockCreation = true }, undo: func() { f.labs.blockCreation = false },
			code: CodeStateUncertain},
		"retained faulted tunnel": {
			setup: func() {
				lab := f.labs.labs.peek(f.lab.ProfileID)
				lab.State = LabFaulted
				f.labs.labs.set(f.lab.ProfileID, lab)
			},
			undo: func() {
				lab := f.labs.labs.peek(f.lab.ProfileID)
				lab.State = LabTunnelConfigured
				f.labs.labs.set(f.lab.ProfileID, lab)
			},
			code: CodeStateUncertain,
		},
		"policy unavailable": {setup: func() { backend.pinErr = errors.New("no policy") }, undo: func() { backend.pinErr = nil },
			code: CodeRuntimeUnavailable},
		"shutting down": {cancelled: true, code: CodeRuntimeUnavailable},
		"shutting down during another operation": {setup: func() { f.labs.mu.Lock() }, undo: func() { f.labs.mu.Unlock() },
			cancelled: true, code: CodeRuntimeUnavailable},
		"no verifier":         {noVerifier: true, code: CodeRuntimeUnavailable},
		"no runtime identity": {noRuntimeID: true, code: CodeRuntimeUnavailable},
	} {
		callCtx, v, runtimeID := ctx, f.verifier, multiProbeTestRuntimeID

		if tt.cancelled {
			callCtx = cancelled
		}

		if tt.noVerifier {
			v = nil
		}

		if tt.noRuntimeID {
			runtimeID = ""
		}

		if tt.setup != nil {
			tt.setup()
		}

		policy, err := f.labs.readMultiProbePolicy(callCtx, v, runtimeID)

		if tt.undo != nil {
			tt.undo()
		}

		if labCode(err) != tt.code || policy != (MultiProbePolicyInfo{}) {
			t.Errorf("%s: %+v %v", name, policy, err)
		}
	}

	disabled := newTunnelFixture(t)
	if _, err := disabled.labs.readMultiProbePolicy(ctx, disabled.verifier, multiProbeTestRuntimeID); labCode(err) !=
		CodeRuntimeUnavailable {
		t.Fatalf("policy of a lifecycle without the multi-source probe: %v", err)
	}

	if backend.calls != 0 || backend.cleanups != 0 || f.labs.labs.peek(f.lab.ProfileID).State != LabTunnelConfigured {
		t.Fatal("reading the policy touched the backend or the lab")
	}
}

func TestMultiProbePolicyResponseValidation(t *testing.T) {
	valid := MultiProbePolicyInfo{
		Policy:          helperauth.OpPermitMultiProbe,
		IdentIPv4:       "9.9.9.9",
		HelperID:        "helper_0123456789abcdef0123456789abcdef",
		RuntimeID:       multiProbeTestRuntimeID,
		PublicKeySHA256: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
	}

	req := Request{Version: Version, Operation: OpMultiProbePolicy}
	ok := func(p *MultiProbePolicyInfo) Response {
		return Response{Version: Version, Operation: OpMultiProbePolicy, OK: true, MultiProbePolicy: p}
	}

	if !validMultiProbePolicyResponse(req, ok(&valid)) {
		t.Fatal("valid policy refused")
	}

	for name, mutate := range map[string]func(*MultiProbePolicyInfo){
		"unsupported policy":  func(p *MultiProbePolicyInfo) { p.Policy = "PermitMultiProbeV3" },
		"legacy policy":       func(p *MultiProbePolicyInfo) { p.Policy = helperauth.OpPermitProbe },
		"missing pin":         func(p *MultiProbePolicyInfo) { p.IdentIPv4 = "" },
		"Cloudflare as pin":   func(p *MultiProbePolicyInfo) { p.IdentIPv4 = "1.1.1.1" },
		"private pin":         func(p *MultiProbePolicyInfo) { p.IdentIPv4 = "10.0.0.1" },
		"host name as pin":    func(p *MultiProbePolicyInfo) { p.IdentIPv4 = "4.ident.me" },
		"non-canonical pin":   func(p *MultiProbePolicyInfo) { p.IdentIPv4 = "009.9.9.9" },
		"invalid epoch":       func(p *MultiProbePolicyInfo) { p.HelperID = "helper_invalid" },
		"missing epoch":       func(p *MultiProbePolicyInfo) { p.HelperID = "" },
		"missing runtime ID":  func(p *MultiProbePolicyInfo) { p.RuntimeID = "" },
		"invalid runtime ID":  func(p *MultiProbePolicyInfo) { p.RuntimeID = "runtime_x" },
		"invalid fingerprint": func(p *MultiProbePolicyInfo) { p.PublicKeySHA256 = "invalid" },
		"upper-case fingerprint": func(p *MultiProbePolicyInfo) {
			p.PublicKeySHA256 = "0123456789ABCDEF0123456789abcdef0123456789abcdef0123456789abcdef"
		},
	} {
		bad := valid
		mutate(&bad)

		if validMultiProbePolicyResponse(req, ok(&bad)) {
			t.Errorf("%s accepted", name)
		}
	}

	for name, tt := range map[string]struct {
		req  Request
		resp Response
	}{
		"success without policy": {req, ok(nil)},
		"failure with policy": {req, Response{Version: Version, Operation: OpMultiProbePolicy,
			Code: CodeOperationDisabled, MultiProbePolicy: &valid}},
		"unsolicited policy": {Request{Version: Version, Operation: OpPing},
			Response{Version: Version, Operation: OpPing, OK: true, MultiProbePolicy: &valid}},
	} {
		if validMultiProbePolicyResponse(tt.req, tt.resp) {
			t.Errorf("%s accepted", name)
		}
	}
}
