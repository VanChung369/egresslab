package labruntime

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/VanChung369/egresslab/services/controller/internal/control"
)

// MultiProbePolicy reads the helper's public policy metadata. It authorizes nothing.
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

// ProbeEgressMulti sends the capability on stdin only, for exactly the intent it signs; the
// launcher gets no destination argument. The helper runs one whole attempt; nothing is retried.
func (t *commandTransport) ProbeEgressMulti(
	ctx context.Context,
	profileID, namespace string,
	capability control.LabCapability,
) (control.LabMultiProbeInfo, error) {
	expected, err := control.NewLabMultiProbeIntent(profileID, namespace, capability.Claims.Intent.ProbeIPv4)
	if err != nil || capability.Claims.Intent != expected {
		return control.LabMultiProbeInfo{}, Errorf(CodeInvalidRequest, "invalid PermitMultiProbeV1 request")
	}

	payload, err := json.Marshal(capability)
	if err != nil {
		return control.LabMultiProbeInfo{}, err
	}
	defer clear(payload)

	resp, err := t.run(ctx, control.LabMultiProbeOp, payload, "probe-egress-multi", profileID, namespace)
	if err != nil {
		return control.LabMultiProbeInfo{}, err
	}

	if resp.MultiProbe == nil || !resp.MultiProbe.MatchesIntent(expected) {
		return control.LabMultiProbeInfo{}, errors.New("helper returned mismatched multi-source evidence")
	}

	return *resp.MultiProbe, nil
}
