//go:build linux

package helperipc

import (
	"context"
	"errors"
	"testing"

	"github.com/VanChung369/egresslab/services/network-agent/internal/helperauth"
)

func TestSignedTunnelIPC(t *testing.T) {
	requireUnprivileged(t)

	f := newTunnelFixture(t)
	socket := serveLifecycleTest(t, f.verifier, f.labs)
	ctx := context.Background()
	req := f.connectRequest()

	resp, err := ConnectTunnel(ctx, socket, f.lab.ProfileID, f.lab.Namespace, tunnelTestStage, *req.Capability)
	if err != nil || resp.Lab == nil || resp.Lab.State != LabTunnelConfigured || resp.NetworkReady {
		t.Fatalf("connect: %+v %v", resp, err)
	}

	listed, err := Call(ctx, socket, OpListLabs)
	if err != nil || len(listed.Labs) != 1 || listed.Labs[0].State != LabTunnelConfigured {
		t.Fatalf("list: %+v %v", listed, err)
	}

	verified, err := VerifySealedLab(ctx, socket, f.lab.ProfileID, f.lab.Namespace)
	if err != nil || verified.Lab == nil || verified.Lab.State != LabTunnelConfigured || verified.NetworkReady {
		t.Fatalf("verify: %+v %v", verified, err)
	}

	create := f.mint(helperauth.Intent{Operation: helperauth.OpCreateLab, ProfileID: tunnelTestProfile})
	if _, err := CreateSealedLab(ctx, socket, tunnelTestProfile, *create.Capability); ErrorCode(err) != CodeLabBusy {
		t.Fatalf("create while the tunnel slot is held: %v", err)
	}

	probe := rawRequest(t, socket, Request{Version: Version, Operation: helperauth.OpPermitProbe})
	if probe.OK || probe.Code != CodeOperationDisabled {
		t.Fatal("probe unexpectedly enabled")
	}

	disconnected, err := DisconnectTunnel(ctx, socket, f.lab.ProfileID, f.lab.Namespace)
	if err != nil || disconnected.Lab == nil || disconnected.Lab.State != LabSealed {
		t.Fatalf("disconnect: %+v %v", disconnected, err)
	}

	if _, err := ConnectTunnel(ctx, socket, f.lab.ProfileID, f.lab.Namespace, tunnelTestStage, *req.Capability); ErrorCode(err) != CodeAuthorizationDenied {
		t.Fatalf("replay: %v", err)
	}

	if _, err := DeleteSealedLab(ctx, socket, f.lab.ProfileID, f.lab.Namespace); err != nil {
		t.Fatal(err)
	}
}

func TestTunnelIPCCodes(t *testing.T) {
	requireUnprivileged(t)

	f := newTunnelFixture(t)
	socket := serveLifecycleTest(t, f.verifier, f.labs)
	ctx := context.Background()

	f.tunnels.connectErr = errors.New("ambiguous")

	req := f.connectRequest()
	if _, err := ConnectTunnel(ctx, socket, f.lab.ProfileID, f.lab.Namespace, tunnelTestStage, *req.Capability); ErrorCode(err) != CodeStateUncertain {
		t.Fatalf("failed connect: %v", err)
	}

	// The client accepts a faulted lab from Disconnect.
	resp, err := DisconnectTunnel(ctx, socket, f.lab.ProfileID, f.lab.Namespace)
	if err != nil || resp.Lab == nil || resp.Lab.State != LabFaulted {
		t.Fatalf("disconnect after a failed attempt: %+v %v", resp, err)
	}

	if _, err := DeleteSealedLab(ctx, socket, f.lab.ProfileID, f.lab.Namespace); err != nil {
		t.Fatal(err)
	}

	f.lab = f.createLab(t, lifecycleProfile)
	f.tunnels.connectErr = errors.Join(ErrStageNotFound, errors.New("replaced"))

	req = f.connectRequest()
	if _, err := ConnectTunnel(ctx, socket, f.lab.ProfileID, f.lab.Namespace, tunnelTestStage, *req.Capability); ErrorCode(err) != CodeStageNotFound {
		t.Fatalf("stale stage: %v", err)
	}
}

func TestTunnelOperationsDisabledWithoutBackend(t *testing.T) {
	labs, _, v, mint := newLifecycleFixture(t)
	socket := serveLifecycleTest(t, v, labs)
	ctx := context.Background()

	created, err := CreateSealedLab(ctx, socket, lifecycleProfile, *mint(lifecycleProfile).Capability)
	if err != nil {
		t.Fatal(err)
	}

	lab := created.Lab

	if _, err := DisconnectTunnel(ctx, socket, lab.ProfileID, lab.Namespace); ErrorCode(err) != CodeOperationDisabled {
		t.Fatalf("disconnect: %v", err)
	}

	capability := *mint(lifecycleProfile).Capability
	if _, err := ConnectTunnel(ctx, socket, lab.ProfileID, lab.Namespace, tunnelTestStage, capability); ErrorCode(err) != CodeOperationDisabled {
		t.Fatalf("connect: %v", err)
	}
}
