//go:build linux

package helperipc

import (
	"context"
	"testing"

	"github.com/VanChung369/egresslab/services/network-agent/internal/helperauth"
)

// TestRefusalCodes walks the refusals a client can trigger and checks each carries its code.
func TestRefusalCodes(t *testing.T) {
	labs, backend, v, mint := newLifecycleFixture(t)
	socket := serveLifecycleTest(t, v, labs)
	plain := serveAuthorizedTest(t, nil)
	ctx := context.Background()

	created, err := CreateSealedLab(ctx, socket, lifecycleProfile, *mint(lifecycleProfile).Capability)
	if err != nil {
		t.Fatal(err)
	}

	lab := *created.Lab
	intent := testIntent()
	token := mint("profile_ffffffffffffffff").Capability

	withCapability := existingLabRequest(OpDeleteLab, lab)
	withCapability.Capability = token

	otherNamespace := existingLabRequest(OpVerifyLab, lab)
	otherNamespace.Intent.Namespace = "egresslab-lab-ffffffffffffffff"

	missing := existingLabRequest(OpVerifyLab, lab)
	missing.Intent.ProfileID = "profile_ffffffffffffffff"

	unsigned := mint("profile_ffffffffffffffff")
	unsigned.Capability = nil

	forged := mint("profile_ffffffffffffffff")
	forged.Capability.Signature = token.Signature[:len(token.Signature)-2] + "AA"

	tests := []struct {
		name   string
		socket string
		req    Request
		code   string
	}{
		{"unsupported version", socket, Request{Version: 2, Operation: OpPing}, CodeInvalidRequest},
		{"authorization fields on Ping", socket, Request{Version: Version, Operation: OpPing, Intent: &intent}, CodeInvalidRequest},
		{"tunnel operation", socket, Request{Version: Version, Operation: helperauth.OpConnectTunnel}, CodeOperationDisabled},
		{"AuthorizeCheck without a key", plain, Request{Version: Version, Operation: OpAuthorizeCheck, Intent: &intent, Capability: token}, CodeOperationDisabled},
		{"lifecycle disabled", plain, Request{Version: Version, Operation: OpListLabs}, CodeOperationDisabled},
		{"CreateLab without a capability", socket, unsigned, CodeAuthorizationDenied},
		{"forged capability", socket, forged, CodeAuthorizationDenied},
		{"DeleteLab with a capability", socket, withCapability, CodeAuthorizationDenied},
		{"second lab for a profile", socket, mint(lifecycleProfile), CodeLabExists},
		{"no lab for the profile", socket, missing, CodeLabNotFound},
		{"another namespace", socket, otherNamespace, CodeOwnershipMismatch},
		{"malformed intent", socket, Request{Version: Version, Operation: OpVerifyLab, Intent: &intent}, CodeInvalidRequest},
	}

	for _, tt := range tests {
		resp := rawRequest(t, tt.socket, tt.req)
		if resp.OK || resp.Code != tt.code || !knownCodes[resp.Code] || resp.Error == "" {
			t.Errorf("%s: got %+v, want code %s", tt.name, resp, tt.code)
		}
	}

	if resp := rawExchange(t, socket, []byte("{")); resp.Code != CodeInvalidRequest {
		t.Errorf("invalid frame: %+v", resp)
	}

	labs.mu.Lock()
	busy := rawRequest(t, socket, Request{Version: Version, Operation: OpListLabs})
	labs.mu.Unlock()

	if busy.Code != CodeLabBusy {
		t.Errorf("busy registry: %+v", busy)
	}

	labs.mu.Lock()
	backend.verifyErr = ErrLabFirewallDrift
	labs.mu.Unlock()

	if _, err := VerifySealedLab(ctx, socket, lab.ProfileID, lab.Namespace); ErrorCode(err) != CodeFirewallDrift {
		t.Errorf("drift: %v (%s)", err, ErrorCode(err))
	}

	if _, err := VerifySealedLab(ctx, socket, lab.ProfileID, lab.Namespace); ErrorCode(err) != CodeLabFaulted {
		t.Errorf("faulted lab: %v (%s)", err, ErrorCode(err))
	}

	if _, err := Call(ctx, socket+".missing", OpPing); ErrorCode(err) != CodeRuntimeUnavailable {
		t.Errorf("unreachable helper: %v", err)
	}
}
