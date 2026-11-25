package main

import (
	"fmt"
	"time"

	"github.com/VanChung369/egresslab/services/controller/internal/control"
	"github.com/VanChung369/egresslab/services/controller/internal/labruntime"
)

// probeEgressMulti signs one PermitMultiProbeV2 for the tunnel generation the current helper process
// reports for the profile's own configured tunnel, and checks the evidence it returns. The result
// is printed only: no profile, binding, routing or lease state changes. Nothing is retried, and
// nothing falls back to PermitMultiProbeV1 or PermitProbe.
func (s *session) probeEgressMulti(profileID, namespace string) (control.LabMultiProbeInfo, error) {
	profile, err := loadProfile(s.dataDir, profileID)
	if err != nil {
		return control.LabMultiProbeInfo{}, err
	}

	state, err := control.LoadRuntimeState(s.dataDir)
	if err != nil {
		return control.LabMultiProbeInfo{}, err
	}

	rt, info, err := s.currentRuntime(state)
	if err != nil {
		return control.LabMultiProbeInfo{}, err
	}

	if err := requireSigningRuntime(rt, info); err != nil {
		return control.LabMultiProbeInfo{}, err
	}

	binding, bound := state.Binding(profileID)
	if !bound || binding.RuntimeID != rt.ID || binding.Namespace != namespace || binding.HelperEpoch != info.HelperID {
		return control.LabMultiProbeInfo{}, labruntime.Errorf(labruntime.CodeOwnershipMismatch,
			"missing or stale lab binding")
	}

	transport := s.provider.Transport()

	labs, err := transport.ListLabs(s.ctx)
	if err != nil {
		return control.LabMultiProbeInfo{}, err
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
		return control.LabMultiProbeInfo{}, labruntime.Errorf(labruntime.CodeLabNotFound,
			"helper has no lab for this profile")
	case lab.Namespace != namespace:
		return control.LabMultiProbeInfo{}, labruntime.Errorf(labruntime.CodeOwnershipMismatch,
			"helper returned a different namespace")
	case lab.State != control.LabTunnelConfigured:
		return control.LabMultiProbeInfo{}, labruntime.Errorf(labruntime.CodeLabFaulted,
			"multi-source probe requires a configured tunnel")
	}

	// Read right before signing, never reused: a reconnect makes a new generation.
	target, err := transport.MultiProbeTarget(s.ctx, profileID, namespace)
	if err != nil {
		return control.LabMultiProbeInfo{}, err
	}

	if !target.Matches(info, binding) || target.RuntimeID != rt.ID || target.PublicKeySHA256 != rt.PublicKeySHA256 {
		return control.LabMultiProbeInfo{}, labruntime.Errorf(labruntime.CodeRuntimeUntrusted,
			"multi-source target identity mismatch")
	}

	keys, err := s.d.openKeys(s.dataDir)
	if err != nil {
		return control.LabMultiProbeInfo{}, err
	}

	capability, err := control.MintPermitMultiProbeV2(keys, profile, binding, info, lab, target, s.d.now())
	if err != nil {
		return control.LabMultiProbeInfo{}, err
	}

	issuedAt := time.Unix(capability.Claims.IssuedAt, 0)
	sentAt := s.d.now()

	// The helper checks expiry again; this only avoids sending a capability already dead here.
	if sentAt.Before(issuedAt) || sentAt.Unix() >= capability.Claims.NotAfter {
		return control.LabMultiProbeInfo{}, labruntime.Errorf(labruntime.CodeAuthorizationDenied,
			"capability expired before submission")
	}

	result, err := transport.ProbeEgressMulti(s.ctx, profileID, namespace, capability)
	receivedAt := s.d.now()

	if err != nil {
		switch labruntime.ErrorCode(err) {
		case labruntime.CodeRuntimeUnavailable, labruntime.CodeInternal, labruntime.CodeStateUncertain:
			return control.LabMultiProbeInfo{}, labruntime.Errorf(labruntime.CodeStateUncertain,
				fmt.Sprintf("PermitMultiProbeV2 result uncertain; inspect list-labs: %v", err))
		}

		return control.LabMultiProbeInfo{}, err
	}

	// A refusal here does not mean the helper rolled the tunnel back: it may still be configured.
	if !result.ValidForCapability(capability, sentAt, receivedAt) {
		return control.LabMultiProbeInfo{}, labruntime.Errorf(labruntime.CodeStateUncertain,
			"generation-bound evidence rejected (foreign, stale or clock skew); inspect list-labs")
	}

	return result, nil
}
