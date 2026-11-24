package labruntime

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/VanChung369/egresslab/services/controller/internal/control"
)

func (t *commandTransport) StageInfo(ctx context.Context, profileID string) (control.LabStageInfo, error) {
	if !control.ValidProfileID(profileID) {
		return control.LabStageInfo{}, Errorf(CodeInvalidRequest, "invalid profile ID")
	}

	resp, err := t.run(ctx, "StageInfo", nil, "stage-info", profileID)
	if err != nil {
		return control.LabStageInfo{}, err
	}

	if resp.Stage.ProfileID != profileID {
		return control.LabStageInfo{}, errors.New("helper returned a mismatched stage")
	}

	return *resp.Stage, nil
}

// ConnectTunnel sends the capability on stdin only, and only for the exact intent it signs. It
// never retries.
func (t *commandTransport) ConnectTunnel(
	ctx context.Context,
	profileID, namespace, stageID string,
	capability control.LabCapability,
) (control.LabInfo, error) {
	expected := control.LabIntent{Operation: "ConnectTunnel", ProfileID: profileID, Namespace: namespace, StageID: stageID}

	if !control.ValidProfileID(profileID) || !control.ValidLabNamespace(namespace) || !control.ValidStageID(stageID) ||
		capability.Claims.Intent != expected {
		return control.LabInfo{}, Errorf(CodeInvalidRequest, "invalid ConnectTunnel request")
	}

	payload, err := json.Marshal(capability)
	if err != nil {
		return control.LabInfo{}, err
	}
	defer clear(payload)

	resp, err := t.run(ctx, "ConnectTunnel", payload, "connect-tunnel", profileID, namespace, stageID)
	if err != nil {
		return control.LabInfo{}, err
	}

	return checkLab(resp.Lab, profileID, namespace, control.LabTunnelConfigured)
}

// Disconnect keeps the namespace. A faulted answer means the tunnel is gone but the lab must be
// deleted, never reused.
func (t *commandTransport) Disconnect(ctx context.Context, profileID, namespace string) (control.LabInfo, error) {
	return t.existingLab(ctx, "Disconnect", "disconnect", profileID, namespace, control.LabSealed, control.LabFaulted)
}
