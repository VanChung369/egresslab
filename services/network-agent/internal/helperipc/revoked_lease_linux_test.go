//go:build linux

package helperipc

import (
	"context"
	"errors"
	"net"
	"os"
	"sync/atomic"
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

func TestRecoveredGenerationIPC(t *testing.T) {
	requireUnprivileged(t)

	f, _, preparation := newPreparedLeaseFixture(t)

	revocation, err := helperauth.NewRevokeEgressLeaseIntent(*preparation.Intent)
	if err != nil {
		t.Fatal(err)
	}

	const oldID = "helper_ffffffffffffffffffffffffffffffff"

	intent, err := helperauth.NewRecoverRetiredGenerationIntent(revocation, oldID)
	if err != nil {
		t.Fatal(err)
	}

	helperID, fingerprint := f.verifier.Identity()

	const (
		oldBoot = "11111111-2222-4333-8444-555555555555"
		newBoot = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"
	)

	var sameBoot atomic.Bool

	socket := serveWith(t, func(ctx context.Context, listener *net.UnixListener) error {
		return ServeWith(ctx, listener, uint32(os.Getuid()), ServerOptions{
			Verifier:  f.verifier,
			RuntimeID: multiProbeTestRuntimeID,
			ReadEpochRecovery: func(original, current, runtime, key string) (string, string, error) {
				if original != oldID || current != helperID || runtime != multiProbeTestRuntimeID || key != fingerprint {
					return "", "", errors.New("identity mismatch")
				}

				if sameBoot.Load() {
					return "", "", errors.New("kernel reboot not established")
				}

				return oldBoot, newBoot, nil
			},
		})
	})

	req := f.mint(intent)

	response, err := RevokeEgressLease(context.Background(), socket, intent.ProfileID, intent.Namespace, *req.Capability)
	if err != nil || response.RevokedLease == nil || response.NetworkReady ||
		response.Operation != helperauth.OpRecoverRetiredGeneration ||
		response.RevokedLease.OriginalBootID != oldBoot || response.RevokedLease.CurrentBootID != newBoot {
		t.Fatalf("recovery IPC failed: %+v %v", response, err)
	}

	if _, err := RevokeEgressLease(context.Background(), socket, intent.ProfileID, intent.Namespace,
		*req.Capability); ErrorCode(err) != CodeAuthorizationDenied {
		t.Fatalf("recovery replay was not refused: %v", err)
	}

	sameBoot.Store(true)

	if _, err := RevokeEgressLease(context.Background(), socket, intent.ProfileID, intent.Namespace,
		*f.mint(intent).Capability); ErrorCode(err) != CodeAuthorizationDenied {
		t.Fatalf("same-boot recovery was not refused: %v", err)
	}

	self, err := helperauth.NewRecoverRetiredGenerationIntent(revocation, helperID)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := RevokeEgressLease(context.Background(), socket, self.ProfileID, self.Namespace,
		*f.mint(self).Capability); ErrorCode(err) != CodeAuthorizationDenied {
		t.Fatalf("recovery by the original epoch itself was not refused: %v", err)
	}
}
