//go:build linux

package helperipc

import (
	"context"
	"net"
	"os"
	"testing"

	"github.com/VanChung369/egresslab/services/network-agent/internal/helperauth"
)

func serveCandidateTest(t *testing.T, f *tunnelFixture) string {
	t.Helper()
	requireUnprivileged(t)

	return serveWith(t, func(ctx context.Context, listener *net.UnixListener) error {
		return ServeWith(ctx, listener, uint32(os.Getuid()), ServerOptions{
			Verifier:  f.verifier,
			Labs:      f.labs,
			RuntimeID: multiProbeTestRuntimeID,
		})
	})
}

func TestCandidateReservationIPC(t *testing.T) {
	ctx := context.Background()
	f, backend, req := newVerifiedCandidateFixture(t)
	socket := serveCandidateTest(t, f)

	resp, err := ReserveEgressCandidate(ctx, socket, f.lab.ProfileID, f.lab.Namespace, *req.Capability)
	if err != nil || resp.Candidate == nil || resp.NetworkReady || resp.Operation != helperauth.OpReserveEgressCandidate {
		t.Fatalf("candidate IPC failed: %+v %v", resp, err)
	}

	if resp.Candidate.EvidenceNonce != req.Intent.EvidenceNonce ||
		resp.Candidate.ReservationNonce != req.Capability.Claims.Nonce ||
		resp.Candidate.TunnelGeneration != ipcGenerationA {
		t.Fatal("incorrect reservation identity")
	}

	second := f.mint(*req.Intent)
	if _, err := ReserveEgressCandidate(ctx, socket, f.lab.ProfileID, f.lab.Namespace, *second.Capability); ErrorCode(err) != CodeEvidenceUnavailable {
		t.Fatalf("evidence consumed twice over IPC: %v", err)
	}

	// A probe capability cannot authorize a reservation; the client refuses it before sending.
	probe := f.mint(generationProbeIntent(t, f.lab, backend.pin.String(), ipcGenerationA))
	if _, err := ReserveEgressCandidate(ctx, socket, f.lab.ProfileID, f.lab.Namespace, *probe.Capability); ErrorCode(err) != CodeInvalidRequest {
		t.Fatalf("probe capability authorized a reservation: %v", err)
	}

	// Sent raw, it is refused by the helper as well.
	raw := rawRequest(t, socket, Request{Version: Version, Operation: helperauth.OpReserveEgressCandidate,
		Intent: probe.Intent, Capability: probe.Capability})
	if raw.OK || raw.Candidate != nil || raw.Code != CodeInvalidRequest {
		t.Fatalf("raw probe capability as reservation: %+v", raw)
	}

	if _, err := DeleteSealedLab(ctx, socket, f.lab.ProfileID, f.lab.Namespace); err != nil {
		t.Fatal(err)
	}
}

func TestCandidateReservationDisabledWithoutGenerations(t *testing.T) {
	f, _, req := newVerifiedCandidateFixture(t)
	f.labs.generationProbes = nil
	socket := serveCandidateTest(t, f)

	raw := rawRequest(t, socket, req)
	if raw.OK || raw.Candidate != nil || raw.Code != CodeOperationDisabled {
		t.Fatalf("reservation without the V2 lifecycle: %+v", raw)
	}
}
