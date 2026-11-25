package main

import (
	"fmt"
	"time"

	"github.com/VanChung369/egresslab/services/controller/internal/control"
	"github.com/VanChung369/egresslab/services/controller/internal/labruntime"
)

// probeEgressMulti signs one PermitMultiProbeV1 for the profile's own configured tunnel in the
// current helper process, against the policy that helper generation advertises, and checks the
// evidence it returns. The result is printed only: no profile, binding, routing or lease state
// changes. Nothing is retried, and nothing falls back to PermitProbe.
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

	// Read right before signing, and only accepted for the trusted helper generation.
	policy, err := transport.MultiProbePolicy(s.ctx)
	if err != nil {
		return control.LabMultiProbeInfo{}, err
	}

	if !policy.Matches(info) || policy.RuntimeID != rt.ID || policy.HelperID != binding.HelperEpoch ||
		policy.PublicKeySHA256 != rt.PublicKeySHA256 {
		return control.LabMultiProbeInfo{}, labruntime.Errorf(labruntime.CodeRuntimeUntrusted,
			"multi-source policy identity mismatch")
	}

	keys, err := s.d.openKeys(s.dataDir)
	if err != nil {
		return control.LabMultiProbeInfo{}, err
	}

	capability, err := control.MintPermitMultiProbe(keys, profile, binding, info, lab, policy, s.d.now())
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
				fmt.Sprintf("PermitMultiProbeV1 result uncertain; inspect list-labs: %v", err))
		}

		return control.LabMultiProbeInfo{}, err
	}

	// A refusal here does not mean the helper rolled the tunnel back: it may still be configured.
	if !result.ValidFor(capability.Claims.Intent, issuedAt, sentAt, receivedAt) {
		return control.LabMultiProbeInfo{}, labruntime.Errorf(labruntime.CodeStateUncertain,
			"multi-source evidence rejected (foreign, stale or clock skew); inspect list-labs")
	}

	return result, nil
}
