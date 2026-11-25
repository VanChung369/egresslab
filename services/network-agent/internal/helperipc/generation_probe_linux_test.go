//go:build linux

package helperipc

import (
	"context"
	"net"
	"os"
	"testing"

	"github.com/VanChung369/egresslab/services/network-agent/internal/helperauth"
)

// Real socket, framing, dispatcher and Ed25519 verifier; only the kernel backend is fake.
func TestGenerationProbeIPC(t *testing.T) {
	requireUnprivileged(t)

	ctx := context.Background()
	f, backend := newGenerationProbeFixture(t)

	socket := serveWith(t, func(ctx context.Context, listener *net.UnixListener) error {
		return ServeWith(ctx, listener, uint32(os.Getuid()), ServerOptions{
			Verifier:  f.verifier,
			Labs:      f.labs,
			RuntimeID: multiProbeTestRuntimeID,
		})
	})

	response, err := ReadMultiProbeTarget(ctx, socket, f.lab.ProfileID, f.lab.Namespace)
	if err != nil || response.MultiProbeTarget == nil || response.NetworkReady {
		t.Fatalf("target discovery: %+v %v", response, err)
	}

	target := response.MultiProbeTarget
	if target.TunnelGeneration != ipcGenerationA || target.Policy != helperauth.OpPermitMultiProbeV2 {
		t.Fatalf("incorrect target: %+v", target)
	}

	req := f.mint(generationProbeIntent(t, f.lab, target.IdentIPv4, target.TunnelGeneration))

	// The read-only target takes no capability.
	intent := generationTargetIntent(f.lab)
	bad := rawRequest(t, socket, Request{Version: Version, Operation: OpMultiProbeTarget, Intent: &intent,
		Capability: req.Capability})

	if bad.OK || bad.Code != CodeInvalidRequest || bad.MultiProbeTarget != nil || backend.calls != 0 {
		t.Fatalf("target discovery took a capability: %+v", bad)
	}

	probed, err := ProbeEgressMultiV2(ctx, socket, f.lab.ProfileID, f.lab.Namespace, *req.Capability)
	if err != nil || probed.MultiProbe == nil || probed.NetworkReady ||
		probed.MultiProbe.TunnelGeneration != target.TunnelGeneration ||
		probed.MultiProbe.AttemptNonce != req.Capability.Claims.Nonce {
		t.Fatalf("V2 probe: %+v %v", probed, err)
	}

	if _, err := ProbeEgressMultiV2(ctx, socket, f.lab.ProfileID, f.lab.Namespace, *req.Capability); ErrorCode(err) !=
		CodeAuthorizationDenied {
		t.Fatalf("V2 replay accepted: %v", err)
	}

	legacy := f.mint(multiProbeIntent(f.lab, backend.pin.String()))
	if _, err := ProbeEgressMulti(ctx, socket, f.lab.ProfileID, f.lab.Namespace, *legacy.Capability); ErrorCode(err) !=
		CodeOperationDisabled {
		t.Fatalf("V1 downgrade accepted: %v", err)
	}

	if backend.calls != 1 {
		t.Fatal("unexpected probe count")
	}

	if _, err := DeleteSealedLab(ctx, socket, f.lab.ProfileID, f.lab.Namespace); err != nil {
		t.Fatal(err)
	}
}

// The production helper of this step (V1) refuses V2 and the target read over the socket.
func TestGenerationProbeDisabledOverIPC(t *testing.T) {
	ctx := context.Background()
	f, backend := newMultiProbeFixture(t)
	socket := serveLifecycleTest(t, f.verifier, f.labs)

	v2 := f.mint(generationProbeIntent(t, f.lab, backend.pin.String(), ipcGenerationA))
	if _, err := ProbeEgressMultiV2(ctx, socket, f.lab.ProfileID, f.lab.Namespace, *v2.Capability); ErrorCode(err) !=
		CodeOperationDisabled {
		t.Fatalf("V2 on a V1 helper: %v", err)
	}

	if _, err := ReadMultiProbeTarget(ctx, socket, f.lab.ProfileID, f.lab.Namespace); ErrorCode(err) !=
		CodeOperationDisabled {
		t.Fatalf("target on a V1 helper: %v", err)
	}

	if backend.calls != 0 {
		t.Fatal("a refused request reached the backend")
	}
}
