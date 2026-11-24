package main

import (
	"strings"
	"testing"

	"github.com/VanChung369/egresslab/services/controller/internal/control"
	"github.com/VanChung369/egresslab/services/controller/internal/labruntime"
)

const cliTestStage = "wgstage_0123456789abcdef0123456789abcdef"

func TestControllerTunnelLifecycle(t *testing.T) {
	h := newHarness(t)
	a := h.runtimes["Ubuntu-A"]
	p := h.profile.ID
	a.stage = control.LabStageInfo{ProfileID: p, StageID: cliTestStage, Compatible: true}

	connect := func(distro, stage string) []string {
		return []string{"-approve", "-wsl-distro", distro, "connect-tunnel", p, labNS, stage}
	}

	h.mustRun("-approve", "-wsl-distro", "Ubuntu-A", "trust-runtime")
	h.mustRun("-approve", "-wsl-distro", "Ubuntu-B", "trust-runtime")
	h.mustRun("-approve", "-wsl-distro", "Ubuntu-A", "create-lab", p)

	h.mustRun("-wsl-distro", "Ubuntu-A", "stage-info", p)
	if !strings.Contains(h.out.String(), cliTestStage) {
		t.Fatal("stage metadata missing")
	}

	h.requireCode(labruntime.CodeOwnershipMismatch, "-wsl-distro", "Ubuntu-B", "stage-info", p)

	if err := h.run("-wsl-distro", "Ubuntu-A", "connect-tunnel", p, labNS, cliTestStage); err == nil ||
		!strings.Contains(err.Error(), "requires -approve") {
		t.Fatalf("connection without approval: %v", err)
	}

	h.requireCode(labruntime.CodeOwnershipMismatch, connect("Ubuntu-B", cliTestStage)...)
	h.requireCode(labruntime.CodeStageNotFound, connect("Ubuntu-A", "wgstage_ffffffffffffffffffffffffffffffff")...)

	a.info.HelperID = epoch2
	h.requireCode(labruntime.CodeOwnershipMismatch, connect("Ubuntu-A", cliTestStage)...)
	a.info.HelperID = epoch1

	a.stage.Compatible = false
	h.requireCode(labruntime.CodeInvalidRequest, connect("Ubuntu-A", cliTestStage)...)
	a.stage.Compatible = true

	fingerprint := a.info.PublicKeySHA256
	a.info.PublicKeySHA256 = strings.Repeat("0", 64)
	h.requireCode(labruntime.CodeRuntimeUntrusted, connect("Ubuntu-A", cliTestStage)...)
	h.requireCode(labruntime.CodeRuntimeUntrusted, "-wsl-distro", "Ubuntu-A", "stage-info", p)
	h.requireCode(labruntime.CodeRuntimeUntrusted, "-approve", "-wsl-distro", "Ubuntu-A", "create-lab", p)
	a.info.PublicKeySHA256 = fingerprint

	if len(a.created) != 1 {
		t.Fatal("CreateLab signed for an unpinned key")
	}

	if len(a.tunnelCalls) != 0 {
		t.Fatal("a refused request reached the tunnel backend")
	}

	h.mustRun(connect("Ubuntu-A", cliTestStage)...)

	if a.tunnelProfile != p || len(a.tunnelCalls) != 1 {
		t.Fatal("tunnel connection failed")
	}

	claims := a.tunnelCalls[0].Claims
	if claims.Intent.StageID != cliTestStage || claims.Intent.Namespace != labNS || claims.HelperID != epoch1 {
		t.Fatal("incorrect capability binding")
	}

	// A connected lab is refused before anything is signed.
	h.requireCode(labruntime.CodeLabBusy, connect("Ubuntu-A", cliTestStage)...)
	if len(a.tunnelCalls) != 1 {
		t.Fatal("a second capability was signed")
	}

	h.mustRun("-wsl-distro", "Ubuntu-A", "verify-lab", p, labNS)
	if !strings.Contains(h.out.String(), control.LabTunnelConfigured) {
		t.Fatal("configured tunnel state missing")
	}

	h.mustRun("-wsl-distro", "Ubuntu-A", "list-labs")
	if !strings.Contains(h.out.String(), control.LabTunnelConfigured) {
		t.Fatal("list-labs lost the tunnel state")
	}

	if err := h.run("-wsl-distro", "Ubuntu-A", "disconnect", p, labNS); err == nil || !strings.Contains(err.Error(), "requires -approve") {
		t.Fatalf("disconnect without approval: %v", err)
	}

	h.mustRun("-approve", "-wsl-distro", "Ubuntu-A", "disconnect", p, labNS)

	if a.tunnelProfile != "" || a.labs[p] != labNS {
		t.Fatal("disconnect removed the namespace")
	}

	if b, ok := h.binding(); !ok || b.Namespace != labNS || b.HelperEpoch != epoch1 {
		t.Fatal("disconnect lost ownership")
	}

	// A lost response is reported as uncertain and never retried.
	a.tunnelErr = labruntime.Errorf(labruntime.CodeRuntimeUnavailable, "connection reset")
	h.requireCode(labruntime.CodeStateUncertain, connect("Ubuntu-A", cliTestStage)...)

	if len(a.tunnelCalls) != 2 {
		t.Fatal("unexpected automatic retry")
	}

	// A definite refusal keeps its code.
	a.tunnelErr = labruntime.Errorf(labruntime.CodeLabBusy, "tunnel slot held")
	h.requireCode(labruntime.CodeLabBusy, connect("Ubuntu-A", cliTestStage)...)
	a.tunnelErr = nil

	h.mustRun("-approve", "-wsl-distro", "Ubuntu-A", "delete-lab", p, labNS)
}

// Cleanup needs no signing key: a broken key store must not strand a tunnel.
func TestTunnelCleanupWithoutKeys(t *testing.T) {
	h := newHarness(t)
	a := h.runtimes["Ubuntu-A"]
	p := h.profile.ID
	a.stage = control.LabStageInfo{ProfileID: p, StageID: cliTestStage, Compatible: true}

	h.mustRun("-approve", "-wsl-distro", "Ubuntu-A", "trust-runtime")
	h.mustRun("-approve", "-wsl-distro", "Ubuntu-A", "create-lab", p)
	h.mustRun("-approve", "-wsl-distro", "Ubuntu-A", "connect-tunnel", p, labNS, cliTestStage)

	h.keys.private = nil // as if the key store could not be read

	h.mustRun("-approve", "-wsl-distro", "Ubuntu-A", "disconnect", p, labNS)

	if err := h.run("-approve", "-wsl-distro", "Ubuntu-A", "connect-tunnel", p, labNS, cliTestStage); err == nil || len(a.tunnelCalls) != 1 {
		t.Fatalf("connected without a signing key: %v", err)
	}

	h.mustRun("-approve", "-wsl-distro", "Ubuntu-A", "delete-lab", p, labNS)

	if a.tunnelProfile != "" || len(a.labs) != 0 {
		t.Fatal("cleanup incomplete")
	}
}

// After the controller key is replaced, signing stops until the operator trusts the runtime again;
// the profile keeps its binding.
func TestKeyReplacementNeedsTrustAgain(t *testing.T) {
	h := newHarness(t)
	a := h.runtimes["Ubuntu-A"]
	p := h.profile.ID
	a.stage = control.LabStageInfo{ProfileID: p, StageID: cliTestStage, Compatible: true}

	h.mustRun("-approve", "-wsl-distro", "Ubuntu-A", "trust-runtime")
	h.mustRun("-approve", "-wsl-distro", "Ubuntu-A", "create-lab", p)

	h.keys.private = nil
	if err := h.keys.Initialize(); err != nil {
		t.Fatal(err)
	}

	public, _ := h.keys.PublicKey()
	a.info.PublicKeySHA256 = control.LabPublicKeySHA256(public)

	h.requireCode(labruntime.CodeRuntimeUntrusted, "-approve", "-wsl-distro", "Ubuntu-A", "connect-tunnel", p, labNS, cliTestStage)

	h.mustRun("-approve", "-wsl-distro", "Ubuntu-A", "trust-runtime")
	if !strings.Contains(h.out.String(), a.info.PublicKeySHA256) {
		t.Fatal("trust-runtime kept the old key")
	}

	if b, ok := h.binding(); !ok || b.Namespace != labNS {
		t.Fatal("trusting again dropped the binding")
	}

	h.mustRun("-approve", "-wsl-distro", "Ubuntu-A", "connect-tunnel", p, labNS, cliTestStage)
}
