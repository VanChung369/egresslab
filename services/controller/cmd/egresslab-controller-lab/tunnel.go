package main

import (
	"fmt"

	"github.com/VanChung369/egresslab/services/controller/internal/control"
	"github.com/VanChung369/egresslab/services/controller/internal/labruntime"
)

// requireSigningRuntime: the controller signs only for the helper whose identity and public key
// were pinned at trust-runtime.
func requireSigningRuntime(rt control.TrustedRuntime, info control.LabHelperInfo) error {
	if !info.Valid() ||
		!info.AuthorizationConfigured ||
		info.RuntimeID != rt.ID ||
		info.PublicKeySHA256 != rt.PublicKeySHA256 {
		return labruntime.Errorf(labruntime.CodeRuntimeUntrusted,
			"the helper's public key is not the one pinned at trust-runtime; after replacing the controller key, run -approve trust-runtime again")
	}

	return nil
}

func (s *session) stageInfo(profileID string) (control.LabStageInfo, error) {
	if _, err := loadProfile(s.dataDir, profileID); err != nil {
		return control.LabStageInfo{}, err
	}

	state, err := control.LoadRuntimeState(s.dataDir)
	if err != nil {
		return control.LabStageInfo{}, err
	}

	rt, info, err := s.currentRuntime(state)
	if err != nil {
		return control.LabStageInfo{}, err
	}

	if err := requireSigningRuntime(rt, info); err != nil {
		return control.LabStageInfo{}, err
	}

	if binding, bound := state.Binding(profileID); bound && binding.RuntimeID != rt.ID {
		return control.LabStageInfo{}, labruntime.Errorf(labruntime.CodeOwnershipMismatch, "profile belongs to another runtime")
	}

	return s.provider.Transport().StageInfo(s.ctx, profileID)
}

// connectTunnel signs a ConnectTunnel only for the profile's own lab in the current helper
// process, and only for the vault's current, compatible stage. It never retries.
func (s *session) connectTunnel(profileID, namespace, stageID string) (control.LabInfo, error) {
	profile, err := loadProfile(s.dataDir, profileID)
	if err != nil {
		return control.LabInfo{}, err
	}

	state, err := control.LoadRuntimeState(s.dataDir)
	if err != nil {
		return control.LabInfo{}, err
	}

	rt, info, err := s.currentRuntime(state)
	if err != nil {
		return control.LabInfo{}, err
	}

	if err := requireSigningRuntime(rt, info); err != nil {
		return control.LabInfo{}, err
	}

	binding, bound := state.Binding(profileID)
	if !bound || binding.RuntimeID != rt.ID || binding.Namespace != namespace || binding.HelperEpoch != info.HelperID {
		return control.LabInfo{}, labruntime.Errorf(labruntime.CodeOwnershipMismatch,
			"missing or stale lab binding; inspect list-labs and verify-lab")
	}

	transport := s.provider.Transport()

	// The operator names the stage, and it must still be the current one.
	stage, err := transport.StageInfo(s.ctx, profileID)
	if err != nil {
		return control.LabInfo{}, err
	}

	if stage.StageID != stageID {
		return control.LabInfo{}, labruntime.Errorf(labruntime.CodeStageNotFound, "selected WireGuard stage is no longer current")
	}

	// The helper would fault the lab on an incompatible config, so it is refused here.
	if !stage.Compatible {
		return control.LabInfo{}, labruntime.Errorf(labruntime.CodeInvalidRequest,
			"WireGuard stage is not compatible with the VPN runtime")
	}

	// The helper must still own the lab, sealed and without a tunnel; ConnectTunnel checks the
	// kernel again.
	lab, err := transport.VerifyLab(s.ctx, profileID, namespace)
	if err != nil {
		return control.LabInfo{}, err
	}

	if lab.State != control.LabSealed {
		return control.LabInfo{}, labruntime.Errorf(labruntime.CodeLabBusy, "lab already has a tunnel")
	}

	keys, err := s.d.openKeys(s.dataDir)
	if err != nil {
		return control.LabInfo{}, err
	}

	capability, err := control.MintConnectTunnel(keys, profile, binding, info, stage, s.d.now())
	if err != nil {
		return control.LabInfo{}, err
	}

	connected, err := transport.ConnectTunnel(s.ctx, profileID, namespace, stageID, capability)
	if err != nil {
		switch labruntime.ErrorCode(err) {
		case labruntime.CodeRuntimeUnavailable, labruntime.CodeInternal, labruntime.CodeStateUncertain:
			return control.LabInfo{}, labruntime.Errorf(labruntime.CodeStateUncertain,
				fmt.Sprintf("ConnectTunnel result uncertain; inspect list-labs before retrying: %v", err))
		}

		return control.LabInfo{}, err
	}

	// runtimes.json keeps ownership only; the tunnel state stays with the helper.
	return connected, nil
}
