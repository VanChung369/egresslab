package helperipc

import (
	"context"
	"fmt"
	"regexp"

	"github.com/VanChung369/egresslab/services/network-agent/internal/helperauth"
)

// EpochRecoveryReader proves from the persistent witnesses that the original epoch belonged to an
// earlier kernel boot than the current one, and returns both boot IDs.
type EpochRecoveryReader func(originalID, currentID, runtimeID, fingerprint string) (
	originalBootID, currentBootID string, err error)

var recoveryBootPattern = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

func validRecoveryBootID(id string) bool {
	return recoveryBootPattern.MatchString(id) && id != "00000000-0000-0000-0000-000000000000"
}

func (r *RevokedLeaseInfo) validRecoveryBoundary() bool {
	if r.Intent.Operation == helperauth.OpRevokeEgressLease {
		return r.OriginalBootID == "" && r.CurrentBootID == ""
	}

	return helperauth.ValidRecoverRetiredGenerationIntent(r.Intent) &&
		r.Intent.OriginalHelperID != r.HelperID &&
		validRecoveryBootID(r.OriginalBootID) &&
		validRecoveryBootID(r.CurrentBootID) &&
		r.OriginalBootID != r.CurrentBootID
}

// recoverRetiredGeneration attests that a kernel reboot ended the original epoch's generation. It
// touches no network resource and keeps no record: the controller's journal decides once.
func recoverRetiredGeneration(
	ctx context.Context,
	req Request,
	v *helperauth.Verifier,
	runtimeID string,
	read EpochRecoveryReader,
) (RevokedLeaseInfo, error) {
	if req.Version != Version || req.Operation != helperauth.OpRecoverRetiredGeneration || req.Intent == nil ||
		!helperauth.ValidRecoverRetiredGenerationIntent(*req.Intent) {
		return RevokedLeaseInfo{}, errLabInvalid
	}

	if v == nil || read == nil || req.Capability == nil {
		return RevokedLeaseInfo{}, errLabUnavailable
	}

	if ctx.Err() != nil {
		return RevokedLeaseInfo{}, errLabUnavailable
	}

	intent := *req.Intent
	helperID, fingerprint := v.Identity()
	nonce := req.Capability.Claims.Nonce

	if intent.RuntimeID != runtimeID || intent.OriginalHelperID == helperID ||
		nonce == intent.EvidenceNonce || nonce == intent.ReservationNonce {
		return RevokedLeaseInfo{}, errLabAuthorization
	}

	if err := v.VerifyAndConsume(*req.Capability, intent); err != nil {
		return RevokedLeaseInfo{}, fmt.Errorf("%w: %w", errLabAuthorization, err)
	}

	originalBoot, currentBoot, err := read(intent.OriginalHelperID, helperID, runtimeID, fingerprint)
	if err != nil {
		return RevokedLeaseInfo{}, fmt.Errorf("%w: epoch witness: %w", errLabAuthorization, err)
	}

	if ctx.Err() != nil {
		return RevokedLeaseInfo{}, errLabUnavailable
	}

	receipt := RevokedLeaseInfo{
		Intent:            intent,
		HelperID:          helperID,
		PublicKeySHA256:   fingerprint,
		RevocationNonce:   nonce,
		GenerationRetired: true,
		OriginalBootID:    originalBoot,
		CurrentBootID:     currentBoot,
	}

	if !receipt.matchesCapability(req.Intent, req.Capability) {
		return RevokedLeaseInfo{}, errLabUncertain
	}

	return receipt, nil
}
