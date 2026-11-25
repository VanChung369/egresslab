package labruntime

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/VanChung369/egresslab/services/controller/internal/control"
)

// ProbeEgress sends the capability on stdin only, and only for the exact intent it signs. The
// helper runs one whole probe; nothing is retried.
func (t *commandTransport) ProbeEgress(
	ctx context.Context,
	profileID, namespace string,
	capability control.LabCapability,
) (control.LabProbeInfo, error) {
	expected := control.LabIntent{
		Operation: "PermitProbe",
		ProfileID: profileID,
		Namespace: namespace,
		ProbeIPv4: control.LabProbeIPv4,
	}

	if !control.ValidProfileID(profileID) || !control.ValidLabNamespace(namespace) ||
		capability.Claims.Intent != expected {
		return control.LabProbeInfo{}, Errorf(CodeInvalidRequest, "invalid PermitProbe request")
	}

	payload, err := json.Marshal(capability)
	if err != nil {
		return control.LabProbeInfo{}, err
	}
	defer clear(payload)

	resp, err := t.run(ctx, "PermitProbe", payload, "probe-egress", profileID, namespace)
	if err != nil {
		return control.LabProbeInfo{}, err
	}

	if resp.Probe.ProfileID != profileID || resp.Probe.Namespace != namespace {
		return control.LabProbeInfo{}, errors.New("helper returned a mismatched probe observation")
	}

	return *resp.Probe, nil
}
