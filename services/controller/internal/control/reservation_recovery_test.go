//go:build windows || linux || darwin

package control

import (
	"context"
	"errors"
	"testing"
)

const recoveredTestHelper = "helper_ffffffffffffffffffffffffffffffff"

type recoveryFlowTransport struct {
	releaseFlowTransport
	mode string
}

func (f *recoveryFlowTransport) RevokeEgressLease(_ context.Context, profileID, namespace string,
	capability LabCapability) (LabRevokedLeaseInfo, error) {
	f.calls = append(f.calls, "recover")

	hold := f.fixture.admission.hold

	binding, err := revokeIntentFromHold(f.fixture.authority.Info(), hold)
	if err != nil {
		return LabRevokedLeaseInfo{}, err
	}

	expected, err := NewLabRecoverRetiredGenerationIntent(binding, hold.Owner.HelperEpoch)
	if err != nil || capability.Claims.Intent != expected || capability.Claims.HelperID != recoveredTestHelper ||
		profileID != hold.Owner.ProfileID || namespace != hold.Owner.Namespace ||
		!verifyIssuedLabCapability(f.fixture.admission.publicKey, capability) {
		return LabRevokedLeaseInfo{}, errors.New("invalid recovery request")
	}

	if _, err := f.fixture.authority.Lookup(hold.ID); err != nil {
		return LabRevokedLeaseInfo{}, errors.New("hold released too early")
	}

	if f.mode == "lost receipt" {
		return LabRevokedLeaseInfo{}, errors.New("synthetic response loss")
	}

	receipt := LabRevokedLeaseInfo{
		Intent:            expected,
		HelperID:          recoveredTestHelper,
		PublicKeySHA256:   hold.PublicKeySHA256,
		RevocationNonce:   capability.Claims.Nonce,
		GenerationRetired: true,
		OriginalBootID:    "11111111-2222-4333-8444-555555555555",
		CurrentBootID:     "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee",
	}

	switch f.mode {
	case "same boot":
		receipt.CurrentBootID = receipt.OriginalBootID
	case "no boot":
		receipt.OriginalBootID, receipt.CurrentBootID = "", ""
	case "wrong original epoch":
		receipt.Intent.OriginalHelperID = "helper_eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
	case "wrong reservation":
		receipt.Intent.ReservationID = "reservation_ffffffffffffffffffffffffffffffff"
	case "revocation receipt":
		receipt.Intent = binding
		receipt.OriginalBootID, receipt.CurrentBootID = "", ""
	}

	return receipt, nil
}

func TestReservationRecoveryFlow(t *testing.T) {
	for _, mode := range []string{
		"success", "same boot", "no boot", "wrong original epoch", "wrong reservation", "revocation receipt",
		"lost receipt", "same helper",
	} {
		t.Run(mode, func(t *testing.T) {
			f := newReleaseTestFixture(t)

			transport := &recoveryFlowTransport{
				releaseFlowTransport: releaseFlowTransport{
					fixture: f,
					now:     f.now,
					helperEdit: func(info *LabHelperInfo) {
						if mode != "same helper" {
							info.HelperID = recoveredTestHelper
						}
					},
				},
				mode: mode,
			}

			result, err := f.authority.retireEgressAt(context.Background(), f.admission.hold.ID, transport, f.signer,
				f.admission.runtime, transport.clock, true)

			// A new process replays the journal, recovery release included.
			reopened, openErr := OpenReservationAuthority(f.dir, f.signer)
			if openErr != nil {
				t.Fatal(openErr)
			}

			items, listErr := reopened.List()
			if listErr != nil {
				t.Fatal(listErr)
			}

			if mode == "success" {
				if err != nil || len(items) != 0 || !result.RevokedLease.GenerationRetired ||
					result.RevokedLease.Intent.Operation != LabRecoverRetiredGenerationOp ||
					result.RevokedLease.Intent.OriginalHelperID != f.admission.hold.Owner.HelperEpoch ||
					result.RevokedLease.HelperID != recoveredTestHelper {
					t.Fatalf("recovery failed: %v", err)
				}

				if _, err := f.authority.retireEgressAt(context.Background(), f.admission.hold.ID, transport,
					f.signer, f.admission.runtime, transport.clock, true); !errors.Is(err, ErrReservationNotFound) {
					t.Fatalf("second recovery not refused: %v", err)
				}

				return
			}

			if err == nil || len(items) != 1 || items[0].ID != f.admission.hold.ID {
				t.Fatal("invalid recovery released ownership")
			}

			if mode == "same helper" && len(transport.calls) != 1 {
				t.Fatal("same-epoch recovery was sent")
			}
		})
	}
}

// A normal release from a later epoch, or a recovery receipt for a normal release, never commits.
func TestReservationRecoveryAdmission(t *testing.T) {
	f := newReleaseTestFixture(t)
	admission := f.admission

	binding, err := revokeIntentFromHold(f.authority.Info(), admission.hold)
	if err != nil {
		t.Fatal(err)
	}

	recovery, err := NewLabRecoverRetiredGenerationIntent(binding, admission.hold.Owner.HelperEpoch)
	if err != nil || !ValidLabRecoverRetiredGenerationIntent(recovery) || ValidLabRevokeEgressLeaseIntent(recovery) {
		t.Fatal("invalid recovery intent")
	}

	if _, err := NewLabRecoverRetiredGenerationIntent(recovery, admission.hold.Owner.HelperEpoch); err == nil {
		t.Fatal("recovery of a recovery accepted")
	}

	receipt := admission.receipt
	receipt.OriginalBootID = "11111111-2222-4333-8444-555555555555"
	receipt.CurrentBootID = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"

	if receipt.Valid() {
		t.Fatal("normal revocation accepted boot IDs")
	}

	if err := validateReleaseAdmission(f.authority.Info(), admission, f.now); err != nil {
		t.Fatal(err)
	}

	foreign := admission
	foreign.helper.HelperID = recoveredTestHelper

	if err := validateReleaseAdmission(f.authority.Info(), foreign, f.now); err == nil {
		t.Fatal("a later epoch released through a normal revocation")
	}
}
