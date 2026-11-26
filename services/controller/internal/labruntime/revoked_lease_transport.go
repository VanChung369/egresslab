package labruntime

import (
	"context"
	"encoding/json"

	"github.com/VanChung369/egresslab/services/controller/internal/control"
)

var _ control.LeaseRevocationTransport = HelperTransport(nil)

// RevokeEgressLease submits exactly one signed revocation or reboot-bound recovery, on stdin only. It
// never retries or falls back to Disconnect.
func (t *commandTransport) RevokeEgressLease(
	ctx context.Context,
	profileID, namespace string,
	capability control.LabCapability,
) (control.LabRevokedLeaseInfo, error) {
	intent := capability.Claims.Intent

	if !control.ValidLabRetirementIntent(intent) || intent.ProfileID != profileID || intent.Namespace != namespace {
		return control.LabRevokedLeaseInfo{}, Errorf(CodeInvalidRequest, "invalid lease revocation capability")
	}

	payload, err := json.Marshal(capability)
	if err != nil {
		return control.LabRevokedLeaseInfo{}, err
	}
	defer clear(payload)

	// A recovery travels the same helperctl command; the signed operation tells them apart.
	resp, err := t.run(ctx, intent.Operation, payload, "revoke-egress-lease", profileID, namespace)
	if err != nil {
		switch ErrorCode(err) {
		case CodeRuntimeUnavailable, CodeInternal, CodeStateUncertain:
			// The helper may have retired the generation before the answer was lost; its own advice
			// (keep it running: a restart loses the retirement record) is kept.
			return control.LabRevokedLeaseInfo{}, Errorf(CodeStateUncertain, "lease revocation outcome uncertain: "+err.Error())
		default:
			return control.LabRevokedLeaseInfo{}, err
		}
	}

	if resp.RevokedLease == nil || !resp.RevokedLease.MatchesCapability(capability) {
		return control.LabRevokedLeaseInfo{}, Errorf(CodeStateUncertain, "helper returned a mismatched revocation receipt")
	}

	return *resp.RevokedLease, nil
}
