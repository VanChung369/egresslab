package main

import (
	"context"
	"encoding/json"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/VanChung369/egresslab/services/controller/internal/control"
	"github.com/VanChung369/egresslab/services/controller/internal/labruntime"
)

func (f *fakeRuntime) MultiProbePolicy(context.Context) (control.LabMultiProbePolicy, error) {
	f.calls = append(f.calls, control.LabMultiProbePolicyOp)

	if f.multiPolicyErr != nil {
		return control.LabMultiProbePolicy{}, f.multiPolicyErr
	}

	return f.multiPolicy(), nil
}

func (f *fakeRuntime) multiPolicy() control.LabMultiProbePolicy {
	policy := control.LabMultiProbePolicy{
		Policy:          control.LabMultiProbeV2Op,
		IdentIPv4:       "9.9.9.9",
		HelperID:        f.info.HelperID,
		RuntimeID:       f.info.RuntimeID,
		PublicKeySHA256: f.info.PublicKeySHA256,
	}

	if f.multiPolicyEdit != nil {
		f.multiPolicyEdit(&policy)
	}

	return policy
}

func (f *fakeRuntime) MultiProbeTarget(
	_ context.Context,
	profileID, namespace string,
) (control.LabMultiProbeTarget, error) {
	f.calls = append(f.calls, control.LabMultiProbeTargetOp)

	if f.multiPolicyErr != nil {
		return control.LabMultiProbeTarget{}, f.multiPolicyErr
	}

	if f.tunnelProfile != profileID || f.labs[profileID] != namespace || f.tunnelGeneration == "" {
		return control.LabMultiProbeTarget{}, labruntime.Errorf(labruntime.CodeInvalidRequest, "no configured tunnel")
	}

	target := control.LabMultiProbeTarget{
		ProfileID:           profileID,
		Namespace:           namespace,
		TunnelGeneration:    f.tunnelGeneration,
		LabMultiProbePolicy: f.multiPolicy(),
	}

	if f.multiTargetEdit != nil {
		f.multiTargetEdit(&target)
	}

	return target, nil
}

func (f *fakeRuntime) ProbeEgressMulti(
	_ context.Context,
	profileID, namespace string,
	capability control.LabCapability,
) (control.LabMultiProbeInfo, error) {
	f.calls = append(f.calls, control.LabMultiProbeV2Op)
	f.multiProbeCalls = append(f.multiProbeCalls, capability)
	f.lastMultiProbe = nil

	if f.multiProbeErr != nil {
		return control.LabMultiProbeInfo{}, f.multiProbeErr
	}

	if f.tunnelProfile != profileID || f.labs[profileID] != namespace {
		return control.LabMultiProbeInfo{}, labruntime.Errorf(labruntime.CodeLabFaulted, "no configured tunnel")
	}

	if capability.Claims.Intent.Operation != control.LabMultiProbeV2Op ||
		capability.Claims.Intent.TunnelGeneration != f.tunnelGeneration {
		return control.LabMultiProbeInfo{}, labruntime.Errorf(labruntime.CodeAuthorizationDenied, "generation mismatch")
	}

	now := time.Unix(1795500000, 0).UTC()
	ip := netip.MustParseAddr("8.8.4.4")

	result := control.LabMultiProbeInfo{
		ProfileID:   profileID,
		Namespace:   namespace,
		IPv4:        ip,
		StartedAt:   now,
		FinishedAt:  now,
		ObservedAt:  now,
		HandshakeAt: now.Add(-time.Second),
		Sources: []control.LabMultiProbeSourceInfo{
			{Source: control.LabProbeSource, DestinationIPv4: netip.MustParseAddr(control.LabProbeIPv4), IPv4: ip,
				ObservedAt: now},
			{Source: control.LabMultiProbeIdentSource, DestinationIPv4: netip.MustParseAddr("9.9.9.9"), IPv4: ip,
				ObservedAt: now},
		},
		TunnelGeneration: f.tunnelGeneration,
		AttemptNonce:     capability.Claims.Nonce,
	}

	if f.multiProbeEdit != nil {
		f.multiProbeEdit(&result)
	}

	f.lastMultiProbe = &result

	return result, nil
}

func TestControllerMultiProbeLifecycle(t *testing.T) {
	h := newHarness(t)
	a := h.runtimes["Ubuntu-A"]
	p := h.profile.ID
	a.stage = control.LabStageInfo{ProfileID: p, StageID: cliTestStage, Compatible: true}

	probe := func(distro string) []string {
		return []string{"-approve", "-wsl-distro", distro, "probe-egress-multi", p, labNS}
	}

	h.mustRun("-approve", "-wsl-distro", "Ubuntu-A", "trust-runtime")
	h.mustRun("-approve", "-wsl-distro", "Ubuntu-B", "trust-runtime")
	h.mustRun("-approve", "-wsl-distro", "Ubuntu-A", "create-lab", p)

	// A sealed lab is refused before anything is signed.
	h.requireCode(labruntime.CodeLabFaulted, probe("Ubuntu-A")...)

	h.mustRun("-approve", "-wsl-distro", "Ubuntu-A", "connect-tunnel", p, labNS, cliTestStage)

	if err := h.run("-wsl-distro", "Ubuntu-A", "probe-egress-multi", p, labNS); err == nil ||
		!strings.Contains(err.Error(), "requires -approve") {
		t.Fatal("probe accepted without approval")
	}

	h.requireCode(labruntime.CodeOwnershipMismatch, probe("Ubuntu-B")...)

	a.info.HelperID = epoch2
	h.requireCode(labruntime.CodeOwnershipMismatch, probe("Ubuntu-A")...)
	a.info.HelperID = epoch1

	// The policy must name exactly the trusted helper generation.
	for name, edit := range map[string]func(*control.LabMultiProbePolicy){
		"another epoch":       func(policy *control.LabMultiProbePolicy) { policy.HelperID = epoch2 },
		"another runtime":     func(policy *control.LabMultiProbePolicy) { policy.RuntimeID = runtimeB },
		"another fingerprint": func(policy *control.LabMultiProbePolicy) { policy.PublicKeySHA256 = strings.Repeat("f", 64) },
		"legacy policy":       func(policy *control.LabMultiProbePolicy) { policy.Policy = control.LabMultiProbeOp },
		"unsupported policy":  func(policy *control.LabMultiProbePolicy) { policy.Policy = "PermitMultiProbeV3" },
	} {
		a.multiPolicyEdit = edit

		if err := h.run(probe("Ubuntu-A")...); labruntime.ErrorCode(err) != labruntime.CodeRuntimeUntrusted {
			t.Errorf("%s: %v", name, err)
		}
	}

	a.multiPolicyEdit = nil
	a.multiPolicyErr = labruntime.Errorf(labruntime.CodeOperationDisabled, "operation not enabled")
	h.requireCode(labruntime.CodeOperationDisabled, probe("Ubuntu-A")...)
	a.multiPolicyErr = nil

	if len(a.multiProbeCalls) != 0 || len(a.probeCalls) != 0 || h.keys.signs != 2 {
		t.Fatalf("a refused probe was signed or reached the runtime (%d signatures)", h.keys.signs)
	}

	bindingBefore, _ := h.binding()

	h.mustRun(probe("Ubuntu-A")...)

	var output struct {
		control.LabMultiProbeInfo
		NetworkReady bool `json:"network_ready"`
	}

	if err := json.Unmarshal(h.out.Bytes(), &output); err != nil {
		t.Fatal(err)
	}

	if len(a.multiProbeCalls) != 1 {
		t.Fatalf("%d attempts", len(a.multiProbeCalls))
	}

	if output.IPv4.String() != "8.8.4.4" || output.NetworkReady || output.ProfileID != p || len(output.Sources) != 2 ||
		output.TunnelGeneration != a.tunnelGeneration || output.AttemptNonce != a.multiProbeCalls[0].Claims.Nonce ||
		!strings.Contains(h.out.String(), `"network_ready": false`) {
		t.Fatalf("invalid output: %s", h.out.String())
	}

	claims := a.multiProbeCalls[0].Claims
	if claims.Intent != (control.LabIntent{Operation: control.LabMultiProbeV2Op, ProfileID: p, Namespace: labNS,
		ProbeIPv4: "9.9.9.9", TunnelGeneration: a.tunnelGeneration}) || claims.HelperID != epoch1 {
		t.Fatalf("invalid signed operation: %+v", claims)
	}

	// Structurally valid evidence for another pin, or old evidence, is refused.
	a.multiProbeEdit = func(info *control.LabMultiProbeInfo) {
		info.Sources[1].DestinationIPv4 = netip.MustParseAddr("8.8.8.8")
	}
	h.requireCode(labruntime.CodeStateUncertain, probe("Ubuntu-A")...)

	a.multiProbeEdit = func(info *control.LabMultiProbeInfo) {
		shift := -10 * time.Minute
		info.StartedAt, info.FinishedAt = info.StartedAt.Add(shift), info.FinishedAt.Add(shift)
		info.ObservedAt, info.HandshakeAt = info.ObservedAt.Add(shift), info.HandshakeAt.Add(shift)

		for i := range info.Sources {
			info.Sources[i].ObservedAt = info.Sources[i].ObservedAt.Add(shift)
		}
	}
	h.requireCode(labruntime.CodeStateUncertain, probe("Ubuntu-A")...)

	a.multiProbeEdit = func(info *control.LabMultiProbeInfo) {
		info.TunnelGeneration = "tunnelgen_ffffffffffffffffffffffffffffffff"
	}
	h.requireCode(labruntime.CodeStateUncertain, probe("Ubuntu-A")...)

	a.multiProbeEdit = func(info *control.LabMultiProbeInfo) { info.AttemptNonce = strings.Repeat("f", 32) }
	h.requireCode(labruntime.CodeStateUncertain, probe("Ubuntu-A")...)
	a.multiProbeEdit = nil

	a.multiProbeErr = labruntime.Errorf(labruntime.CodeRuntimeUnavailable, "connection lost")
	h.requireCode(labruntime.CodeStateUncertain, probe("Ubuntu-A")...)

	a.multiProbeErr = labruntime.Errorf(labruntime.CodeLabFaulted, "second source failed")
	h.requireCode(labruntime.CodeLabFaulted, probe("Ubuntu-A")...)
	a.multiProbeErr = nil

	if len(a.multiProbeCalls) != 7 || len(a.probeCalls) != 0 {
		t.Fatalf("retried or fell back: %d multi-source, %d single-source", len(a.multiProbeCalls), len(a.probeCalls))
	}

	if bindingAfter, _ := h.binding(); bindingAfter != bindingBefore {
		t.Fatal("a probe changed the runtime binding")
	}

	h.mustRun("-approve", "-wsl-distro", "Ubuntu-A", "delete-lab", p, labNS)
}

// A capability that is already dead on the controller's clock is never sent.
func TestMultiProbeExpiredBeforeSubmission(t *testing.T) {
	h := newHarness(t)
	a := h.runtimes["Ubuntu-A"]
	p := h.profile.ID
	a.stage = control.LabStageInfo{ProfileID: p, StageID: cliTestStage, Compatible: true}

	h.mustRun("-approve", "-wsl-distro", "Ubuntu-A", "trust-runtime")
	h.mustRun("-approve", "-wsl-distro", "Ubuntu-A", "create-lab", p)
	h.mustRun("-approve", "-wsl-distro", "Ubuntu-A", "connect-tunnel", p, labNS, cliTestStage)

	clock := time.Unix(1795500000, 0)
	h.now = func() time.Time {
		clock = clock.Add(31 * time.Second)
		return clock
	}

	h.requireCode(labruntime.CodeAuthorizationDenied,
		"-approve", "-wsl-distro", "Ubuntu-A", "probe-egress-multi", p, labNS)

	if len(a.multiProbeCalls) != 0 {
		t.Fatal("an expired capability was sent")
	}
}

func TestMultiProbeCLIArguments(t *testing.T) {
	h := newHarness(t)

	for _, args := range [][]string{
		{"multi-probe-policy", "extra"},
		{"-approve", "probe-egress-multi", h.profile.ID},
		{"-approve", "probe-egress-multi", h.profile.ID, "invalid-namespace"},
		{"-approve", "probe-egress-multi", "profile_x", labNS},
		{"-approve", "probe-egress-multi", h.profile.ID, labNS, "9.9.9.9"},
		{"multi-probe-target"},
		{"multi-probe-target", h.profile.ID},
		{"multi-probe-target", h.profile.ID, "../default"},
		{"multi-probe-target", "profile_x", labNS},
		{"multi-probe-target", h.profile.ID, labNS, "tunnelgen_0123456789abcdef0123456789abcdef"},
	} {
		if err := h.run(args...); err == nil || !strings.Contains(err.Error(), "usage") {
			t.Fatalf("invalid arguments accepted: %v: %v", args, err)
		}
	}

	if h.reached != 0 {
		t.Fatal("invalid arguments reached a runtime")
	}
}

func TestControllerGenerationRediscovery(t *testing.T) {
	h := newHarness(t)
	a := h.runtimes["Ubuntu-A"]
	p := h.profile.ID
	a.stage = control.LabStageInfo{ProfileID: p, StageID: cliTestStage, Compatible: true}

	connect := []string{"-approve", "-wsl-distro", "Ubuntu-A", "connect-tunnel", p, labNS, cliTestStage}
	disconnect := []string{"-approve", "-wsl-distro", "Ubuntu-A", "disconnect", p, labNS}
	probe := []string{"-approve", "-wsl-distro", "Ubuntu-A", "probe-egress-multi", p, labNS}
	target := []string{"-wsl-distro", "Ubuntu-A", "multi-probe-target", p, labNS}

	h.mustRun("-approve", "-wsl-distro", "Ubuntu-A", "trust-runtime")
	h.mustRun("-approve", "-wsl-distro", "Ubuntu-A", "create-lab", p)
	h.mustRun(connect...)
	h.mustRun(probe...)
	h.mustRun(probe...)

	first, second := a.multiProbeCalls[0].Claims, a.multiProbeCalls[1].Claims
	if first.Intent != second.Intent || first.Nonce == second.Nonce {
		t.Fatal("two attempts on one tunnel must share the generation, not the nonce")
	}

	h.mustRun(disconnect...)
	h.requireCode(labruntime.CodeInvalidRequest, target...)
	h.mustRun(connect...)

	// Discovery raced a reconnect: the target still names the previous generation.
	a.multiTargetEdit = func(target *control.LabMultiProbeTarget) {
		target.TunnelGeneration = first.Intent.TunnelGeneration
	}
	h.requireCode(labruntime.CodeAuthorizationDenied, probe...)
	a.multiTargetEdit = nil

	if len(a.multiProbeCalls) != 3 {
		t.Fatal("a stale target was retried")
	}

	h.mustRun(probe...)

	next := a.multiProbeCalls[3].Claims
	if next.Intent.TunnelGeneration == first.Intent.TunnelGeneration ||
		next.Intent.TunnelGeneration != a.tunnelGeneration || next.Nonce == first.Nonce || len(a.probeCalls) != 0 {
		t.Fatal("generation was reused or downgraded")
	}

	h.mustRun(target...)

	var discovered control.LabMultiProbeTarget
	if err := json.Unmarshal(h.out.Bytes(), &discovered); err != nil {
		t.Fatal(err)
	}

	if discovered.TunnelGeneration != a.tunnelGeneration || discovered.Policy != control.LabMultiProbeV2Op {
		t.Fatalf("CLI target: %+v", discovered)
	}

	signs := h.keys.signs
	h.mustRun(target...)

	if h.keys.signs != signs {
		t.Fatal("target discovery signed something")
	}

	h.mustRun("-approve", "-wsl-distro", "Ubuntu-A", "delete-lab", p, labNS)
}

// ReserveEgressCandidate simulates consuming the last verified attempt once, to test the CLI
// orchestration; the real signature checks and monotonic deadline are the helper's (Step 31A tests).
func (f *fakeRuntime) ReserveEgressCandidate(
	_ context.Context,
	profileID, namespace string,
	capability control.LabCapability,
) (control.LabCandidateInfo, error) {
	f.calls = append(f.calls, control.LabReserveEgressCandidateOp)
	f.candidateCalls = append(f.candidateCalls, capability)

	if f.candidateErr != nil {
		return control.LabCandidateInfo{}, f.candidateErr
	}

	probe := f.lastMultiProbe
	if probe == nil {
		return control.LabCandidateInfo{}, labruntime.Errorf(labruntime.CodeEvidenceUnavailable, "no verified evidence")
	}

	if f.tunnelProfile != profileID || f.labs[profileID] != namespace || probe.TunnelGeneration != f.tunnelGeneration {
		return control.LabCandidateInfo{}, labruntime.Errorf(labruntime.CodeAuthorizationDenied, "stale generation")
	}

	policy := f.multiPolicy()

	expected, err := control.NewLabReserveEgressCandidateIntent(profileID, namespace, policy.IdentIPv4, f.tunnelGeneration,
		probe.AttemptNonce)
	if err != nil || capability.Claims.Intent != expected || capability.Claims.HelperID != f.info.HelperID ||
		capability.Claims.Nonce == probe.AttemptNonce {
		return control.LabCandidateInfo{}, labruntime.Errorf(labruntime.CodeAuthorizationDenied, "candidate intent mismatch")
	}

	f.lastMultiProbe = nil

	return control.LabCandidateInfo{
		LabMultiProbeTarget: control.LabMultiProbeTarget{
			ProfileID:           profileID,
			Namespace:           namespace,
			TunnelGeneration:    f.tunnelGeneration,
			LabMultiProbePolicy: policy,
		},
		EvidenceNonce:    probe.AttemptNonce,
		ReservationNonce: capability.Claims.Nonce,
		IPv4:             probe.IPv4,
		ObservedAt:       probe.ObservedAt,
		ExpiresAt:        probe.ObservedAt.Add(60 * time.Second),
	}, nil
}
