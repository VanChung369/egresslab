package labruntime

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/VanChung369/egresslab/services/controller/internal/control"
)

// MultiProbePolicy reads the helper's public policy metadata. It authorizes nothing and selects no
// operation version.
func (t *commandTransport) MultiProbePolicy(ctx context.Context) (control.LabMultiProbePolicy, error) {
	resp, err := t.run(ctx, control.LabMultiProbePolicyOp, nil, "multi-probe-policy")
	if err != nil {
		return control.LabMultiProbePolicy{}, err
	}

	if resp.MultiProbePolicy == nil || !resp.MultiProbePolicy.Valid() {
		return control.LabMultiProbePolicy{}, Errorf(CodeRuntimeUntrusted, "unsupported or invalid multi-source policy")
	}

	return *resp.MultiProbePolicy, nil
}

// MultiProbeTarget reads the lab's current tunnel generation and the V2 policy. It sends no
// capability.
func (t *commandTransport) MultiProbeTarget(
	ctx context.Context,
	profileID, namespace string,
) (control.LabMultiProbeTarget, error) {
	if !control.ValidProfileID(profileID) || !control.ValidLabNamespace(namespace) {
		return control.LabMultiProbeTarget{}, Errorf(CodeInvalidRequest, "invalid multi-source target request")
	}

	resp, err := t.run(ctx, control.LabMultiProbeTargetOp, nil, "multi-probe-target", profileID, namespace)
	if err != nil {
		return control.LabMultiProbeTarget{}, err
	}

	if resp.MultiProbeTarget == nil || !resp.MultiProbeTarget.Valid() {
		return control.LabMultiProbeTarget{}, Errorf(CodeRuntimeUntrusted, "invalid multi-source target")
	}

	if resp.MultiProbeTarget.ProfileID != profileID || resp.MultiProbeTarget.Namespace != namespace {
		return control.LabMultiProbeTarget{}, Errorf(CodeOwnershipMismatch,
			"helper returned a different multi-source target")
	}

	return *resp.MultiProbeTarget, nil
}

// ProbeEgressMulti sends one PermitMultiProbeV2 capability on stdin only; the launcher gets no
// destination or generation argument. Nothing is retried or falls back to V1.
func (t *commandTransport) ProbeEgressMulti(
	ctx context.Context,
	profileID, namespace string,
	capability control.LabCapability,
) (control.LabMultiProbeInfo, error) {
	expected, err := control.NewLabGenerationProbeIntent(profileID, namespace, capability.Claims.Intent.ProbeIPv4,
		capability.Claims.Intent.TunnelGeneration)
	if err != nil || capability.Claims.Intent != expected {
		return control.LabMultiProbeInfo{}, Errorf(CodeInvalidRequest, "invalid PermitMultiProbeV2 request")
	}

	payload, err := json.Marshal(capability)
	if err != nil {
		return control.LabMultiProbeInfo{}, err
	}
	defer clear(payload)

	resp, err := t.run(ctx, control.LabMultiProbeV2Op, payload, "probe-egress-multi", profileID, namespace)
	if err != nil {
		return control.LabMultiProbeInfo{}, err
	}

	if resp.MultiProbe == nil || !resp.MultiProbe.MatchesCapability(capability) {
		return control.LabMultiProbeInfo{}, errors.New("helper returned mismatched generation-bound evidence")
	}

	return *resp.MultiProbe, nil
}
