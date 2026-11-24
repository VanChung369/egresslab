//go:build linux

package helperipc

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/VanChung369/egresslab/services/network-agent/internal/helperauth"
)

const testHelperID = "helper_0123456789abcdef0123456789abcdef"

func testIntent() helperauth.Intent {
	return helperauth.Intent{
		Operation: helperauth.OpConnectTunnel,
		ProfileID: "profile_0123456789abcdef",
		Namespace: "egresslab-lab-0123456789abcdef",
		StageID:   "wgstage_0123456789abcdef0123456789abcdef",
	}
}

// authorizedServer starts ServeAuthorized for the current (non-root) user and returns the socket
// and a function that mints capabilities with the matching private key.
func authorizedServer(t *testing.T) (string, func(helperauth.Intent) helperauth.SignedCapability) {
	t.Helper()
	requireUnprivileged(t)

	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	verifier, err := helperauth.NewVerifier(public, testHelperID)
	if err != nil {
		t.Fatal(err)
	}

	socket := serveAuthorizedTest(t, verifier)

	mint := func(intent helperauth.Intent) helperauth.SignedCapability {
		t.Helper()

		claims, err := helperauth.NewClaims(intent, testHelperID, time.Now())
		if err != nil {
			t.Fatal(err)
		}

		token, err := helperauth.Mint(private, claims)
		if err != nil {
			t.Fatal(err)
		}

		return token
	}

	return socket, mint
}

func serveAuthorizedTest(t *testing.T, v *helperauth.Verifier) string {
	t.Helper()
	requireUnprivileged(t)

	return serveWith(t, func(ctx context.Context, listener *net.UnixListener) error {
		return ServeAuthorized(ctx, listener, uint32(os.Getuid()), nil, v)
	})
}

func rawRequest(t *testing.T, socket string, req any) Response {
	t.Helper()

	payload, err := json.Marshal(req)
	if err != nil {
		t.Fatal(err)
	}

	return rawExchange(t, socket, payload)
}

func TestAuthorizeCheckEndToEnd(t *testing.T) {
	socket, mint := authorizedServer(t)
	ctx := context.Background()
	intent := testIntent()
	token := mint(intent)

	// A different requested stage fails without consuming the nonce.
	wrong := intent
	wrong.StageID = "wgstage_ffffffffffffffffffffffffffffffff"

	if _, err := CheckCapability(ctx, socket, wrong, token); err == nil || err.Error() != "authorization denied" {
		t.Fatalf("wrong intent: %v", err)
	}

	checked, err := CheckCapability(ctx, socket, intent, token)
	if err != nil || !checked.OK || checked.NetworkReady || len(checked.Items) != 0 ||
		checked.Operation != OpAuthorizeCheck {
		t.Fatalf("authorization check: %+v %v", checked, err)
	}

	// The same signed capability cannot be used twice.
	if _, err := CheckCapability(ctx, socket, intent, token); err == nil || err.Error() != "authorization denied" {
		t.Fatalf("replay: %v", err)
	}

	// The read-only client still refuses mutations.
	if _, err := Call(ctx, socket, helperauth.OpConnectTunnel); err == nil || !strings.Contains(err.Error(), "not available") {
		t.Fatalf("mutation client accepted: %v", err)
	}
}

func TestMutationWithValidCapabilityIsRefused(t *testing.T) {
	socket, mint := authorizedServer(t)
	intent := testIntent()
	token := mint(intent)

	// The operation the capability names is still not an enabled IPC operation, and the
	// refusal does not reach the verifier.
	for _, op := range []string{helperauth.OpConnectTunnel, helperauth.OpPermitProbe, "CreateLab"} {
		resp := rawRequest(t, socket, Request{Version: Version, Operation: op, Intent: &intent, Capability: &token})

		if resp.OK || resp.Error != "operation not enabled" || resp.NetworkReady {
			t.Fatalf("%s with a valid capability: %+v", op, resp)
		}
	}

	if _, err := CheckCapability(context.Background(), socket, intent, token); err != nil {
		t.Fatalf("nonce consumed by a refused mutation: %v", err)
	}
}

func TestAuthorizationFieldsOnReadOnlyOperations(t *testing.T) {
	socket, mint := authorizedServer(t)
	intent := testIntent()
	token := mint(intent)

	for _, op := range []string{OpPing, OpRecoverScan, OpHelperInfo} {
		resp := rawRequest(t, socket, Request{Version: Version, Operation: op, Intent: &intent, Capability: &token})

		if resp.OK || resp.Error != "unexpected authorization fields" {
			t.Fatalf("%s with authorization fields: %+v", op, resp)
		}
	}

	// Missing halves of an AuthorizeCheck.
	for _, req := range []Request{
		{Version: Version, Operation: OpAuthorizeCheck, Intent: &intent},
		{Version: Version, Operation: OpAuthorizeCheck, Capability: &token},
	} {
		if resp := rawRequest(t, socket, req); resp.OK || resp.Error != "authorization unavailable" {
			t.Fatalf("incomplete AuthorizeCheck: %+v", resp)
		}
	}

	// Unknown fields nested in the capability are rejected by the frame decoder.
	payload := strings.Replace(mustJSON(t, Request{
		Version: Version, Operation: OpAuthorizeCheck, Intent: &intent, Capability: &token,
	}), `"helper_id"`, `"admin":true,"helper_id"`, 1)

	if resp := rawExchange(t, socket, []byte(payload)); resp.OK || resp.Error != "invalid request frame" {
		t.Fatalf("nested unknown field: %+v", resp)
	}

	// None of the refusals above consumed the nonce.
	if _, err := CheckCapability(context.Background(), socket, intent, token); err != nil {
		t.Fatalf("nonce consumed by a refused request: %v", err)
	}
}

func TestAuthorizeCheckIsDisabledByDefault(t *testing.T) {
	socket := serveAuthorizedTest(t, nil)
	intent := testIntent()

	if _, err := CheckCapability(context.Background(), socket, intent, helperauth.SignedCapability{}); err == nil ||
		err.Error() != "authorization unavailable" {
		t.Fatalf("unconfigured helper accepted authorization: %v", err)
	}
}

func mustJSON(t *testing.T, value any) string {
	t.Helper()

	data, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}

	return string(data)
}
