//go:build linux

package helperipc

import (
	"context"
	"testing"

	"github.com/VanChung369/egresslab/services/network-agent/internal/helperauth"
)

// A real Unix socket and real signatures; the kernel backend is the fake one.
func TestPreparedLeaseIPC(t *testing.T) {
	ctx := context.Background()
	f, _, req := newPreparedLeaseFixture(t)
	socket := serveCandidateTest(t, f)

	resp, err := PrepareEgressLease(ctx, socket, f.lab.ProfileID, f.lab.Namespace, *req.Capability)
	if err != nil || resp.PreparedLease == nil || resp.NetworkReady || resp.Operation != helperauth.OpPrepareEgressLease {
		t.Fatalf("lease preparation failed: %+v %v", resp, err)
	}

	if !resp.PreparedLease.matchesCapability(req.Intent, req.Capability) ||
		resp.PreparedLease.ReservationID != testLeaseReservation || resp.PreparedLease.AuthorityID != testLeaseAuthority {
		t.Fatal("incorrect prepared lease identity")
	}

	second := f.mint(*req.Intent)
	if _, err := PrepareEgressLease(ctx, socket, f.lab.ProfileID, f.lab.Namespace, *second.Capability); ErrorCode(err) != CodeLabBusy {
		t.Fatalf("duplicate preparation accepted: %v", err)
	}

	// The client refuses arguments other than the signed ones before dialing.
	if _, err := PrepareEgressLease(ctx, socket, f.lab.ProfileID, "egresslab-lab-ffffffffffffffff", *second.Capability); ErrorCode(err) != CodeInvalidRequest {
		t.Fatalf("mismatched namespace sent: %v", err)
	}

	if _, err := DeleteSealedLab(ctx, socket, f.lab.ProfileID, f.lab.Namespace); err != nil {
		t.Fatal(err)
	}
}

func TestPreparedLeaseIPCDisabledWithoutGenerations(t *testing.T) {
	f, _, req := newPreparedLeaseFixture(t)
	f.labs.generationProbes = nil
	socket := serveCandidateTest(t, f)

	raw := rawRequest(t, socket, req)
	if raw.OK || raw.PreparedLease != nil || raw.NetworkReady || raw.Code != CodeOperationDisabled {
		t.Fatalf("preparation without the V2 lifecycle: %+v", raw)
	}
}
