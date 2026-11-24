package control

import (
	"errors"
	"regexp"
	"time"
)

var labStageIDPattern = regexp.MustCompile(`^wgstage_[0-9a-f]{32}$`)

// LabStageInfo is the helper's StageInfo: metadata only, never the config.
type LabStageInfo struct {
	ProfileID  string `json:"profile_id"`
	StageID    string `json:"stage_id"`
	Compatible bool   `json:"vpn_lab_compatible"`
}

func ValidStageID(id string) bool { return labStageIDPattern.MatchString(id) }

func (s LabStageInfo) Valid() bool { return ValidProfileID(s.ProfileID) && ValidStageID(s.StageID) }

// MintConnectTunnel authorizes only the exact profile, runtime binding, namespace and current
// vault stage, for the helper process the binding names. It authorizes no probe or proxy traffic.
func MintConnectTunnel(
	signer LabSigner,
	profile RoutingProfile,
	binding RuntimeBinding,
	info LabHelperInfo,
	stage LabStageInfo,
	now time.Time,
) (LabCapability, error) {
	if !ValidProfileID(profile.ID) ||
		!profile.UniqueIPRequired ||
		!profile.KillSwitchRequired ||
		profile.Status != "unconfigured" ||
		profile.TunnelID != "" {
		return LabCapability{}, errors.New("profile does not satisfy tunnel lab policy")
	}

	if binding.ProfileID != profile.ID ||
		!ValidRuntimeID(binding.RuntimeID) ||
		binding.RuntimeID != info.RuntimeID ||
		!ValidLabNamespace(binding.Namespace) ||
		binding.HelperEpoch != info.HelperID {
		return LabCapability{}, errors.New("profile runtime binding is stale or mismatched")
	}

	if !stage.Valid() || stage.ProfileID != profile.ID || !stage.Compatible {
		return LabCapability{}, errors.New("invalid or incompatible WireGuard stage")
	}

	return mintLabCapability(signer, LabIntent{
		Operation: "ConnectTunnel",
		ProfileID: profile.ID,
		Namespace: binding.Namespace,
		StageID:   stage.StageID,
	}, info, now)
}
