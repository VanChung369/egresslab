package labruntime

import (
	"context"
	"encoding/json"

	"github.com/VanChung369/egresslab/services/controller/internal/control"
)

var _ control.LeasePreparationTransport = HelperTransport(nil)

// PrepareEgressLease submits exactly one signed preparation, on stdin only. It never retries or
// falls back to another operation.
func (t *commandTransport) PrepareEgressLease(
	ctx context.Context,
	profileID, namespace string,
	capability control.LabCapability,
) (control.LabPreparedLeaseInfo, error) {
	signed := capability.Claims.Intent

	expected, err := control.NewLabPrepareEgressLeaseIntent(profileID, namespace, signed.ProbeIPv4,
		signed.TunnelGeneration, signed.EvidenceNonce, signed.ReservationNonce, signed.RuntimeID, signed.AuthorityID,
		signed.ReservationID, signed.EgressIPv4)
	if err != nil || signed != expected {
		return control.LabPreparedLeaseInfo{}, Errorf(CodeInvalidRequest, "invalid lease preparation capability")
	}

	payload, err := json.Marshal(capability)
	if err != nil {
		return control.LabPreparedLeaseInfo{}, err
	}
	defer clear(payload)

	resp, err := t.run(ctx, control.LabPrepareEgressLeaseOp, payload, "prepare-egress-lease", profileID, namespace)
	if err != nil {
		switch ErrorCode(err) {
		case CodeRuntimeUnavailable, CodeInternal, CodeStateUncertain:
			// The helper may have consumed the candidate before the response was lost.
			return control.LabPreparedLeaseInfo{}, Errorf(CodeStateUncertain, "lease preparation outcome uncertain")
		default:
			return control.LabPreparedLeaseInfo{}, err
		}
	}

	if resp.PreparedLease == nil || !resp.PreparedLease.MatchesCapability(capability) {
		return control.LabPreparedLeaseInfo{}, Errorf(CodeStateUncertain, "helper returned a mismatched prepared lease receipt")
	}

	return *resp.PreparedLease, nil
}
