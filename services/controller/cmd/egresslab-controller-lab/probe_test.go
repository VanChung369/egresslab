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

func (f *fakeRuntime) ProbeEgress(
	_ context.Context,
	profileID, namespace string,
	capability control.LabCapability,
) (control.LabProbeInfo, error) {
	f.record("PermitProbe")
	f.probeCalls = append(f.probeCalls, capability)

	if f.probeErr != nil {
		return control.LabProbeInfo{}, f.probeErr
	}

	if f.tunnelProfile != profileID || f.labs[profileID] != namespace {
		return control.LabProbeInfo{}, labruntime.Errorf(labruntime.CodeLabFaulted, "no configured tunnel")
	}

	now := time.Unix(1795500000, 0).UTC()
	if f.probeStale {
		now = now.Add(-10 * time.Minute)
	}

	return control.LabProbeInfo{
		ProfileID:   profileID,
		Namespace:   namespace,
		IPv4:        netip.MustParseAddr("8.8.4.4"),
		ObservedAt:  now,
		HandshakeAt: now.Add(-time.Second),
		Source:      control.LabProbeSource,
	}, nil
}

func TestControllerProbeLifecycle(t *testing.T) {
	h := newHarness(t)
	a := h.runtimes["Ubuntu-A"]
	p := h.profile.ID

	a.stage = control.LabStageInfo{ProfileID: p, StageID: cliTestStage, Compatible: true}

	probe := func(distro string) []string {
		return []string{"-approve", "-wsl-distro", distro, "probe-egress", p, labNS}
	}

	h.mustRun("-approve", "-wsl-distro", "Ubuntu-A", "trust-runtime")
	h.mustRun("-approve", "-wsl-distro", "Ubuntu-B", "trust-runtime")
	h.mustRun("-approve", "-wsl-distro", "Ubuntu-A", "create-lab", p)

	// A sealed lab is refused before anything is signed.
	h.requireCode(labruntime.CodeLabFaulted, probe("Ubuntu-A")...)

	h.mustRun("-approve", "-wsl-distro", "Ubuntu-A", "connect-tunnel", p, labNS, cliTestStage)

	if err := h.run("-wsl-distro", "Ubuntu-A", "probe-egress", p, labNS); err == nil ||
		!strings.Contains(err.Error(), "requires -approve") {
		t.Fatal("probe accepted without approval")
	}

	h.requireCode(labruntime.CodeOwnershipMismatch, probe("Ubuntu-B")...)

	a.info.HelperID = epoch2
	h.requireCode(labruntime.CodeOwnershipMismatch, probe("Ubuntu-A")...)
	a.info.HelperID = epoch1

	if len(a.probeCalls) != 0 {
		t.Fatal("refused probe reached the runtime")
	}

	bindingBefore, _ := h.binding()

	h.mustRun(probe("Ubuntu-A")...)

	var result struct {
		control.LabProbeInfo
		NetworkReady bool `json:"network_ready"`
	}

	if err := json.Unmarshal(h.out.Bytes(), &result); err != nil {
		t.Fatal(err)
	}

	if result.IPv4.String() != "8.8.4.4" || result.NetworkReady || result.ProfileID != p || len(a.probeCalls) != 1 {
		t.Fatalf("invalid probe output: %s", h.out.String())
	}

	claims := a.probeCalls[0].Claims
	if claims.Intent.Operation != "PermitProbe" || claims.Intent.ProbeIPv4 != control.LabProbeIPv4 ||
		claims.Intent.Namespace != labNS || claims.HelperID != epoch1 {
		t.Fatal("invalid signed probe")
	}

	if bindingAfter, _ := h.binding(); bindingAfter != bindingBefore {
		t.Fatal("probe modified the runtime binding")
	}

	a.probeStale = true
	h.requireCode(labruntime.CodeStateUncertain, probe("Ubuntu-A")...)
	a.probeStale = false

	a.probeErr = labruntime.Errorf(labruntime.CodeRuntimeUnavailable, "connection lost")
	h.requireCode(labruntime.CodeStateUncertain, probe("Ubuntu-A")...)

	// A helper refusal keeps its own code.
	a.probeErr = labruntime.Errorf(labruntime.CodeLabFaulted, "lab is faulted")
	h.requireCode(labruntime.CodeLabFaulted, probe("Ubuntu-A")...)
	a.probeErr = nil

	if len(a.probeCalls) != 4 {
		t.Fatalf("probe was retried: %d calls", len(a.probeCalls))
	}

	if bindingAfter, _ := h.binding(); bindingAfter != bindingBefore {
		t.Fatal("a failed probe modified the runtime binding")
	}

	h.mustRun("-approve", "-wsl-distro", "Ubuntu-A", "delete-lab", p, labNS)
}

func TestProbeEgressArguments(t *testing.T) {
	h := newHarness(t)

	for _, args := range [][]string{
		{"-approve", "probe-egress", h.profile.ID},
		{"-approve", "probe-egress", h.profile.ID, "egresslab-lab-x"},
		{"-approve", "probe-egress", h.profile.ID, labNS, "1.1.1.1"},
	} {
		if err := h.run(args...); err == nil || !strings.Contains(err.Error(), "usage") {
			t.Errorf("%q: %v", args, err)
		}
	}

	if h.reached != 0 {
		t.Fatal("invalid arguments reached a runtime")
	}
}
