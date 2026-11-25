package main

import (
	"fmt"
	"time"

	"github.com/VanChung369/egresslab/services/controller/internal/control"
	"github.com/VanChung369/egresslab/services/controller/internal/labruntime"
)

// probeEgress signs one PermitProbe for the profile's own configured tunnel in the current helper
// process and checks the observation it returns. The result is printed only: it is not stored,
// activates no lease and changes no binding. Nothing is retried.
func (s *session) probeEgress(profileID, namespace string) (control.LabProbeInfo, error) {
	profile, err := loadProfile(s.dataDir, profileID)
	if err != nil {
		return control.LabProbeInfo{}, err
	}

	state, err := control.LoadRuntimeState(s.dataDir)
	if err != nil {
		return control.LabProbeInfo{}, err
	}

	rt, info, err := s.currentRuntime(state)
	if err != nil {
		return control.LabProbeInfo{}, err
	}

	if err := requireSigningRuntime(rt, info); err != nil {
		return control.LabProbeInfo{}, err
	}

	binding, bound := state.Binding(profileID)
	if !bound || binding.RuntimeID != rt.ID || binding.Namespace != namespace || binding.HelperEpoch != info.HelperID {
		return control.LabProbeInfo{}, labruntime.Errorf(labruntime.CodeOwnershipMismatch, "missing or stale lab binding")
	}

	transport := s.provider.Transport()

	labs, err := transport.ListLabs(s.ctx)
	if err != nil {
		return control.LabProbeInfo{}, err
	}

	var lab control.LabInfo

	for _, item := range labs {
		if item.ProfileID == profileID {
			lab = item
			break
		}
	}

	switch {
	case lab.ProfileID == "":
		return control.LabProbeInfo{}, labruntime.Errorf(labruntime.CodeLabNotFound, "helper has no lab for this profile")
	case lab.Namespace != namespace:
		return control.LabProbeInfo{}, labruntime.Errorf(labruntime.CodeOwnershipMismatch,
			"helper returned a different namespace")
	case lab.State != control.LabTunnelConfigured:
		return control.LabProbeInfo{}, labruntime.Errorf(labruntime.CodeLabFaulted, "probe requires a configured tunnel")
	}

	keys, err := s.d.openKeys(s.dataDir)
	if err != nil {
		return control.LabProbeInfo{}, err
	}

	capability, err := control.MintPermitProbe(keys, profile, binding, info, lab, s.d.now())
	if err != nil {
		return control.LabProbeInfo{}, err
	}

	result, err := transport.ProbeEgress(s.ctx, profileID, namespace, capability)
	if err != nil {
		switch labruntime.ErrorCode(err) {
		case labruntime.CodeRuntimeUnavailable, labruntime.CodeInternal, labruntime.CodeStateUncertain:
			return control.LabProbeInfo{}, labruntime.Errorf(labruntime.CodeStateUncertain,
				fmt.Sprintf("PermitProbe result uncertain; inspect list-labs: %v", err))
		}

		return control.LabProbeInfo{}, err
	}

	if !result.ValidFor(profileID, namespace, time.Unix(capability.Claims.IssuedAt, 0), s.d.now()) {
		return control.LabProbeInfo{}, labruntime.Errorf(labruntime.CodeStateUncertain,
			"probe observation rejected (stale, foreign or clock skew); inspect list-labs")
	}

	return result, nil
}
