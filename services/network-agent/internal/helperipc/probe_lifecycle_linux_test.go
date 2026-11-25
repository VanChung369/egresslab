//go:build linux

package helperipc

import (
	"context"
	"testing"

	"github.com/VanChung369/egresslab/services/network-agent/internal/helperauth"
)

// Through the real Unix socket, framing, dispatch and verifier; only the kernel backend is fake.
func TestSignedProbeIPC(t *testing.T) {
	requireUnprivileged(t)

	f, backend := newProbeFixture(t)
	socket := serveLifecycleTest(t, f.verifier, f.labs)
	ctx := context.Background()

	req := f.mint(probeIntent(f.lab))

	response, err := ProbeEgress(ctx, socket, f.lab.ProfileID, f.lab.Namespace, *req.Capability)
	if err != nil || response.Probe == nil || response.Probe.IPv4.String() != "8.8.4.4" || response.Lab != nil ||
		response.NetworkReady || response.Probe.ProfileID != f.lab.ProfileID {
		t.Fatalf("probe: %+v %v", response, err)
	}

	_, err = ProbeEgress(ctx, socket, f.lab.ProfileID, f.lab.Namespace, *req.Capability)
	if ErrorCode(err) != CodeAuthorizationDenied {
		t.Fatalf("probe replay: %v", err)
	}

	// A capability for another destination is refused before it is checked.
	other := probeIntent(f.lab)
	other.ProbeIPv4 = "8.8.8.8"
	wrong := f.mint(other)

	if _, err := callRequest(ctx, socket, wrong); ErrorCode(err) != CodeInvalidRequest {
		t.Fatalf("arbitrary destination: %v", err)
	}

	listed, err := Call(ctx, socket, OpListLabs)
	if err != nil || len(listed.Labs) != 1 || listed.Labs[0].State != LabTunnelConfigured {
		t.Fatalf("lab state: %+v %v", listed, err)
	}

	backend.probeErr = context.DeadlineExceeded

	failed := f.mint(probeIntent(f.lab))
	_, err = ProbeEgress(ctx, socket, f.lab.ProfileID, f.lab.Namespace, *failed.Capability)
	if ErrorCode(err) != CodeLabFaulted {
		t.Fatalf("failed probe: %v", err)
	}

	if _, err := DeleteSealedLab(ctx, socket, f.lab.ProfileID, f.lab.Namespace); err != nil {
		t.Fatal(err)
	}
}

func TestProbeDisabledOverIPC(t *testing.T) {
	requireUnprivileged(t)

	f := newTunnelFixture(t)
	if _, err := f.execute(f.connectRequest()); err != nil {
		t.Fatal(err)
	}

	socket := serveLifecycleTest(t, f.verifier, f.labs)
	req := f.mint(helperauth.Intent{
		Operation: helperauth.OpPermitProbe,
		ProfileID: f.lab.ProfileID,
		Namespace: f.lab.Namespace,
		ProbeIPv4: ProbeDestinationIPv4,
	})

	_, err := ProbeEgress(context.Background(), socket, f.lab.ProfileID, f.lab.Namespace, *req.Capability)
	if ErrorCode(err) != CodeOperationDisabled {
		t.Fatalf("probe on a helper without -enable-probe: %v", err)
	}
}
