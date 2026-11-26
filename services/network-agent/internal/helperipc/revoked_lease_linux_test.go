//go:build linux

package helperipc

import (
	"context"
	"errors"
	"testing"

	"github.com/VanChung369/egresslab/services/network-agent/internal/helperauth"
)

func TestRevokedLeaseIPC(t *testing.T) {
	ctx := context.Background()
	f, backend, preparation := newPreparedLeaseFixture(t)
	socket := serveCandidateTest(t, f)

	prepared, err := PrepareEgressLease(ctx, socket, f.lab.ProfileID, f.lab.Namespace, *preparation.Capability)
	if err != nil || prepared.PreparedLease == nil {
		t.Fatal("preparation failed:", err)
	}

	req := revokeRequest(t, f, preparation)

	resp, err := RevokeEgressLease(ctx, socket, f.lab.ProfileID, f.lab.Namespace, *req.Capability)
	if err != nil || resp.RevokedLease == nil || resp.NetworkReady || resp.Operation != helperauth.OpRevokeEgressLease ||
		!resp.RevokedLease.matchesCapability(req.Intent, req.Capability) || backend.cleanups != 1 {
		t.Fatalf("revocation failed: %+v %v", resp, err)
	}

	revoke := func(namespace string, capability helperauth.SignedCapability) string {
		_, err := RevokeEgressLease(ctx, socket, f.lab.ProfileID, namespace, capability)
		return ErrorCode(err)
	}

	// A preparation capability is not a revocation capability.
	if code := revoke(f.lab.Namespace, *preparation.Capability); code != CodeInvalidRequest {
		t.Fatal("preparation capability accepted for revocation:", code)
	}

	if code := revoke("egresslab-lab-ffffffffffffffff", *req.Capability); code != CodeInvalidRequest {
		t.Fatal("revocation for another lab sent:", code)
	}

	if code := revoke(f.lab.Namespace, *req.Capability); code != CodeAuthorizationDenied {
		t.Fatal("replayed revocation:", code)
	}

	confirmed, err := RevokeEgressLease(ctx, socket, f.lab.ProfileID, f.lab.Namespace, *f.mint(*req.Intent).Capability)
	if err != nil || confirmed.RevokedLease == nil || backend.cleanups != 1 {
		t.Fatalf("fresh confirmation: %+v %v", confirmed, err)
	}
}

func TestRevocationDisabledWithoutGenerationsOverIPC(t *testing.T) {
	f, backend, preparation := newPreparedLeaseFixture(t)
	req := revokeRequest(t, f, preparation)
	f.labs.generationProbes = nil
	socket := serveCandidateTest(t, f)

	raw := rawRequest(t, socket, req)
	if raw.OK || raw.RevokedLease != nil || raw.Code != CodeOperationDisabled || backend.cleanups != 0 {
		t.Fatalf("revocation without the V2 lifecycle: %+v", raw)
	}
}

func TestClientValidatesRevokedLease(t *testing.T) {
	ctx := context.Background()
	f, _, preparation := newPreparedLeaseFixture(t)
	req := revokeRequest(t, f, preparation)
	helperID, fingerprint := f.verifier.Identity()

	receipt := RevokedLeaseInfo{Intent: *req.Intent, HelperID: helperID, PublicKeySHA256: fingerprint,
		RevocationNonce: req.Capability.Claims.Nonce, GenerationRetired: true}

	for name, tc := range map[string]struct {
		edit func(*RevokedLeaseInfo)
		ok   bool
	}{
		"valid":            {func(*RevokedLeaseInfo) {}, true},
		"other nonce":      {func(r *RevokedLeaseInfo) { r.RevocationNonce = "ffffffffffffffffffffffffffffffff" }, false},
		"not retired":      {func(r *RevokedLeaseInfo) { r.GenerationRetired = false }, false},
		"other generation": {func(r *RevokedLeaseInfo) { r.Intent.TunnelGeneration = ipcGenerationB }, false},
	} {
		t.Run(name, func(t *testing.T) {
			answer := receipt
			tc.edit(&answer)

			socket := fakeHelper(t, func(req Request) Response {
				return Response{Version: Version, Operation: req.Operation, OK: true, RevokedLease: &answer}
			})

			resp, err := RevokeEgressLease(ctx, socket, f.lab.ProfileID, f.lab.Namespace, *req.Capability)
			if tc.ok != (err == nil) || (err != nil && err.Error() != "invalid revoked lease response") ||
				(tc.ok && resp.RevokedLease == nil) {
				t.Fatalf("receipt %s: %+v %v", name, resp, err)
			}
		})
	}
}

func TestRevocationUncertainKeepsRecoveryPath(t *testing.T) {
	f, backend, preparation := newPreparedLeaseFixture(t)
	req := revokeRequest(t, f, preparation)
	backend.cleanupErr = errors.New("synthetic cleanup failure")
	socket := serveCandidateTest(t, f)

	raw := rawRequest(t, socket, req)
	if raw.OK || raw.Code != CodeStateUncertain || raw.Error != revocationUncertainMessage || raw.RevokedLease != nil {
		t.Fatalf("uncertain revocation: %+v", raw)
	}

	backend.cleanupErr = nil

	resp, err := RevokeEgressLease(context.Background(), socket, f.lab.ProfileID, f.lab.Namespace, *f.mint(*req.Intent).Capability)
	if err != nil || resp.RevokedLease == nil || backend.cleanups != 2 {
		t.Fatalf("confirmation after the uncertain revocation: %+v %v", resp, err)
	}
}
