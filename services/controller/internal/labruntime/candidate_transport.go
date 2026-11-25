package labruntime

import (
	"context"
	"encoding/json"

	"github.com/VanChung369/egresslab/services/controller/internal/control"
)

var _ control.ReservationTransport = HelperTransport(nil)

// ReserveEgressCandidate submits exactly one signed candidate request, on stdin only. It never
// retries, never asks for a fresh candidate and never names an address.
func (t *commandTransport) ReserveEgressCandidate(
	ctx context.Context,
	profileID, namespace string,
	capability control.LabCapability,
) (control.LabCandidateInfo, error) {
	signed := capability.Claims.Intent

	expected, err := control.NewLabReserveEgressCandidateIntent(profileID, namespace, signed.ProbeIPv4,
		signed.TunnelGeneration, signed.EvidenceNonce)
	if err != nil || signed != expected {
		return control.LabCandidateInfo{}, Errorf(CodeInvalidRequest, "invalid candidate reservation capability")
	}

	payload, err := json.Marshal(capability)
	if err != nil {
		return control.LabCandidateInfo{}, err
	}
	defer clear(payload)

	resp, err := t.run(ctx, control.LabReserveEgressCandidateOp, payload, "reserve-egress-candidate", profileID,
		namespace)
	if err != nil {
		switch ErrorCode(err) {
		case CodeRuntimeUnavailable, CodeInternal, CodeStateUncertain:
			// The helper may have consumed the evidence before the response was lost.
			return control.LabCandidateInfo{}, Errorf(CodeStateUncertain,
				"candidate reservation outcome uncertain; inspect the lab")
		default:
			return control.LabCandidateInfo{}, err
		}
	}

	if resp.Candidate == nil || !resp.Candidate.MatchesCapability(capability) {
		return control.LabCandidateInfo{}, Errorf(CodeStateUncertain, "helper returned a mismatched candidate receipt")
	}

	return *resp.Candidate, nil
}
