// Command egresslab-controller-lab signs CreateLab, ConnectTunnel, PermitProbe, PermitMultiProbeV2,
// ReserveEgressCandidateV1, PrepareEgressLeaseV1 and RevokeEgressLeaseV1 capabilities with the
// controller key and drives the helper's sealed lab, tunnel and diagnostic probes through the host's
// Linux runtime (WSL2, Lima or native Linux).
// It also provisions and uses the per-user egress reservation authority, and releases its holds. The helper stays the
// source of truth for lab and tunnel state. It is a lab tool: -approve is an operator confirmation,
// not user authentication.
package main

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/VanChung369/egresslab/services/controller/internal/control"
	"github.com/VanChung369/egresslab/services/controller/internal/keystore"
	"github.com/VanChung369/egresslab/services/controller/internal/labruntime"
)

type deps struct {
	openKeys   func(dataDir string) (keystore.KeyStore, error)
	newRuntime func(kind string, opts labruntime.Options) (labruntime.RuntimeProvider, error)
	now        func() time.Time
	stdout     io.Writer

	// reservationRoot is injected for tests only; there is no flag for it.
	reservationRoot func() (string, error)
}

var approvalRequired = map[string]bool{
	"create-lab": true, "delete-lab": true, "trust-runtime": true, "untrust-runtime": true, "unbind-profile": true,
	"connect-tunnel": true, "disconnect": true, "probe-egress": true, "probe-egress-multi": true,
	"init-reservations": true, "reserve-egress": true, "release-egress": true,
}

func main() {
	d := deps{
		openKeys:        keystore.Open,
		newRuntime:      labruntime.New,
		now:             time.Now,
		stdout:          os.Stdout,
		reservationRoot: defaultReservationRoot,
	}

	if err := run(os.Args[1:], d); err != nil {
		fmt.Fprintln(os.Stderr, "controller-lab:", err)
		os.Exit(1)
	}
}

type session struct {
	d        deps
	dataDir  string
	provider labruntime.RuntimeProvider
	ctx      context.Context
}

func run(argv []string, d deps) error {
	reportBrokenStdout()

	flags := flag.NewFlagSet("egresslab-controller-lab", flag.ContinueOnError)
	kind := flags.String("runtime", "auto", "network runtime: auto, wsl, lima, native or remote")
	distro := flags.String("wsl-distro", "", "WSL distribution (required to trust a WSL runtime)")
	instance := flags.String("lima-instance", "", "Lima instance (default: egresslab)")
	approve := flags.Bool("approve", false, "approve a lab, tunnel, runtime or reservation mutation")

	if err := flags.Parse(argv); err != nil {
		return err
	}

	args := flags.Args()
	if len(args) == 0 {
		return usageError()
	}

	dataDir, err := dataDirectory()
	if err != nil {
		return err
	}

	s := &session{d: d, dataDir: dataDir}

	if approvalRequired[args[0]] && !*approve {
		return fmt.Errorf("%s requires -approve", args[0])
	}

	switch args[0] {
	case "init-key", "public-key":
		if len(args) != 1 {
			return usageError()
		}
		return s.printPublicKey(args[0] == "init-key")

	case "runtimes":
		if len(args) != 1 {
			return usageError()
		}
		state, err := control.LoadRuntimeState(dataDir)
		if err != nil {
			return err
		}
		return s.print(state)

	// Local: neither reaches a runtime or the helper.
	case "init-reservations":
		if len(args) != 1 {
			return usageError()
		}
		return s.initReservations()

	case "list-reservations":
		if len(args) != 1 {
			return usageError()
		}
		return s.listReservations()
	}

	if err := checkArgs(args); err != nil {
		return err
	}

	if s.provider, err = d.newRuntime(*kind, labruntime.Options{WSLDistro: *distro, LimaInstance: *instance}); err != nil {
		return err
	}

	// Several helper calls in a row; a ConnectTunnel alone may take up to 135 s with its rollback.
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Second)
	defer cancel()
	s.ctx = ctx

	var result any

	switch args[0] {
	case "runtime-status":
		result, err = s.runtimeStatus()
	case "helper-info":
		result, err = s.provider.Transport().HelperInfo(ctx)
	case "list-labs":
		var labs []control.LabInfo
		labs, err = s.provider.Transport().ListLabs(ctx)
		result = struct {
			Labs []control.LabInfo `json:"labs"`
		}{append([]control.LabInfo{}, labs...)}
	case "trust-runtime":
		result, err = s.trustRuntime()
	case "untrust-runtime":
		result, err = s.untrustRuntime(args[1])
	case "create-lab":
		result, err = s.createLab(args[1])
	case "verify-lab", "delete-lab", "disconnect":
		result, err = s.existingLab(args[1], args[2], args[0])
	case "stage-info":
		result, err = s.stageInfo(args[1])
	case "connect-tunnel":
		result, err = s.connectTunnel(args[1], args[2], args[3])
	case "unbind-profile":
		result, err = s.unbindProfile(args[1])
	case "probe-egress":
		var observation control.LabProbeInfo
		observation, err = s.probeEgress(args[1], args[2])
		result = struct {
			control.LabProbeInfo
			NetworkReady bool `json:"network_ready"`
		}{LabProbeInfo: observation}
	case "multi-probe-policy":
		result, err = s.provider.Transport().MultiProbePolicy(ctx)
	case "multi-probe-target":
		result, err = s.provider.Transport().MultiProbeTarget(ctx, args[1], args[2])
	case "probe-egress-multi":
		var observation control.LabMultiProbeInfo
		observation, err = s.probeEgressMulti(args[1], args[2])
		result = struct {
			control.LabMultiProbeInfo
			NetworkReady bool `json:"network_ready"`
		}{LabMultiProbeInfo: observation}
	case "reserve-egress":
		result, err = s.reserveEgress(args[1], args[2])
	case "release-egress":
		result, err = s.releaseEgress(args[1])
	}

	if err != nil {
		return err
	}

	// The hold, or its release, is durable before the receipt is written; a lost receipt must not
	// read as a refusal, and nothing is rolled back.
	if err := s.print(result); err != nil {
		switch args[0] {
		case "reserve-egress":
			return labruntime.Errorf(labruntime.CodeStateUncertain,
				"reservation committed but its receipt was not written; run list-reservations: "+err.Error())
		case "release-egress":
			return labruntime.Errorf(labruntime.CodeStateUncertain,
				"release committed but its receipt was not written; run list-reservations: "+err.Error())
		}

		return err
	}

	return nil
}

func checkArgs(args []string) error {
	switch args[0] {
	case "runtime-status", "helper-info", "list-labs", "trust-runtime", "multi-probe-policy":
		if len(args) == 1 {
			return nil
		}
	case "create-lab", "unbind-profile", "stage-info":
		if len(args) == 2 && control.ValidProfileID(args[1]) {
			return nil
		}
	case "untrust-runtime":
		if len(args) == 2 && control.ValidRuntimeID(args[1]) {
			return nil
		}
	case "verify-lab", "delete-lab", "disconnect", "probe-egress", "probe-egress-multi", "multi-probe-target",
		"reserve-egress":
		if len(args) == 3 && control.ValidProfileID(args[1]) && control.ValidLabNamespace(args[2]) {
			return nil
		}
	case "release-egress":
		if len(args) == 2 && control.ValidReservationID(args[1]) {
			return nil
		}
	case "connect-tunnel":
		if len(args) == 4 && control.ValidProfileID(args[1]) && control.ValidLabNamespace(args[2]) && control.ValidStageID(args[3]) {
			return nil
		}
	}

	return usageError()
}

func (s *session) print(value any) error {
	encoder := json.NewEncoder(s.d.stdout)
	encoder.SetIndent("", "  ")

	return encoder.Encode(value)
}

func (s *session) printPublicKey(initialize bool) error {
	keys, err := s.d.openKeys(s.dataDir)
	if err != nil {
		return err
	}

	if initialize {
		if err := keys.Initialize(); err != nil {
			return err
		}
	}

	public, err := keys.PublicKey()
	if err != nil {
		return err
	}

	_, err = fmt.Fprintln(s.d.stdout, hex.EncodeToString(public))

	return err
}

func (s *session) runtimeStatus() (any, error) {
	status, err := s.provider.Status(s.ctx)
	if err != nil {
		return nil, err
	}

	report := struct {
		labruntime.Status
		Capabilities *labruntime.Capabilities `json:"capabilities,omitempty"`
	}{Status: status}

	if status.Reachable {
		caps, err := s.provider.Capabilities(s.ctx)
		if err != nil {
			return nil, err
		}
		report.Capabilities = &caps
	}

	return report, nil
}

func (s *session) trustRuntime() (control.TrustedRuntime, error) {
	if s.provider.Kind() == "wsl" && s.provider.Target() == "" {
		return control.TrustedRuntime{}, labruntime.Errorf(labruntime.CodeInvalidRequest,
			"trust-runtime needs -wsl-distro: the default WSL distribution can change")
	}

	info, err := s.provider.Transport().HelperInfo(s.ctx)
	if err != nil {
		return control.TrustedRuntime{}, err
	}

	keys, err := s.d.openKeys(s.dataDir)
	if err != nil {
		return control.TrustedRuntime{}, err
	}

	public, err := keys.PublicKey()
	if err != nil {
		return control.TrustedRuntime{}, err
	}

	fingerprint := control.LabPublicKeySHA256(public)

	if !info.AuthorizationConfigured || info.PublicKeySHA256 != fingerprint {
		return control.TrustedRuntime{}, labruntime.Errorf(labruntime.CodeRuntimeUntrusted,
			"the helper does not hold this controller's public key")
	}

	if info.RuntimeID == "" {
		return control.TrustedRuntime{}, labruntime.Errorf(labruntime.CodeRuntimeUntrusted,
			"the helper reports no runtime ID (it needs /etc/machine-id)")
	}

	state, err := control.LoadRuntimeState(s.dataDir)
	if err != nil {
		return control.TrustedRuntime{}, err
	}

	rt := control.TrustedRuntime{
		ID:              info.RuntimeID,
		Provider:        s.provider.Kind(),
		Target:          s.provider.Target(),
		PublicKeySHA256: fingerprint,
		TrustedAt:       s.d.now().UTC(),
	}

	if err := state.Trust(rt); err != nil {
		return control.TrustedRuntime{}, labruntime.Errorf(labruntime.CodeRuntimeUntrusted, err.Error())
	}

	trusted, _ := state.RuntimeFor(rt.Provider, rt.Target)

	return trusted, state.Save()
}

func (s *session) untrustRuntime(id string) (any, error) {
	state, err := control.LoadRuntimeState(s.dataDir)
	if err != nil {
		return nil, err
	}

	if err := state.Untrust(id); err != nil {
		return nil, labruntime.Errorf(labruntime.CodeInvalidRequest, err.Error())
	}

	return state, state.Save()
}

// currentRuntime checks that the runtime reached now is the trusted one for this provider target.
func (s *session) currentRuntime(state *control.RuntimeState) (control.TrustedRuntime, control.LabHelperInfo, error) {
	rt, ok := state.RuntimeFor(s.provider.Kind(), s.provider.Target())
	if !ok {
		hint := "run trust-runtime first"
		if s.provider.Kind() == "wsl" && s.provider.Target() == "" {
			hint = "name the distribution with -wsl-distro"
		}

		return control.TrustedRuntime{}, control.LabHelperInfo{}, labruntime.Errorf(labruntime.CodeRuntimeUntrusted,
			fmt.Sprintf("%s is not a trusted runtime; %s", s.provider.Name(), hint))
	}

	info, err := s.provider.Transport().HelperInfo(s.ctx)
	if err != nil {
		return control.TrustedRuntime{}, control.LabHelperInfo{}, err
	}

	if info.RuntimeID != rt.ID {
		return control.TrustedRuntime{}, control.LabHelperInfo{}, labruntime.Errorf(labruntime.CodeRuntimeUntrusted,
			fmt.Sprintf("%s reports runtime %q, but %s is trusted there", s.provider.Name(), info.RuntimeID, rt.ID))
	}

	return rt, info, nil
}

func (s *session) createLab(profileID string) (control.LabInfo, error) {
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

	binding, bound := state.Binding(profile.ID)

	if bound && binding.RuntimeID != rt.ID {
		return control.LabInfo{}, labruntime.Errorf(labruntime.CodeOwnershipMismatch,
			fmt.Sprintf("profile is bound to runtime %s; run unbind-profile there first", binding.RuntimeID))
	}

	// A record from an earlier helper process is stale: a normal stop deleted that lab, and a
	// crash left an orphan that the helper's recovery gate refuses until it is cleaned up.
	if bound && binding.Namespace != "" && binding.HelperEpoch == info.HelperID {
		return control.LabInfo{}, labruntime.Errorf(labruntime.CodeLabExists,
			fmt.Sprintf("profile already has lab %s; delete-lab first", binding.Namespace))
	}

	keys, err := s.d.openKeys(s.dataDir)
	if err != nil {
		return control.LabInfo{}, err
	}

	capability, err := control.MintCreateLab(keys, profile, info, s.d.now())
	if err != nil {
		return control.LabInfo{}, err
	}

	// The profile is bound before the kernel changes, so an uncertain result can only ever be
	// a lab on this runtime.
	if err := state.SetBinding(control.RuntimeBinding{ProfileID: profile.ID, RuntimeID: rt.ID, UpdatedAt: s.d.now().UTC()}); err != nil {
		return control.LabInfo{}, err
	}

	if err := state.Save(); err != nil {
		return control.LabInfo{}, err
	}

	lab, err := s.provider.Transport().CreateLab(s.ctx, profile.ID, capability)
	if err != nil {
		switch labruntime.ErrorCode(err) {
		case labruntime.CodeRuntimeUnavailable, labruntime.CodeInternal, labruntime.CodeStateUncertain:
			return control.LabInfo{}, labruntime.Errorf(labruntime.CodeStateUncertain,
				"CreateLab result uncertain; run list-labs before retrying: "+err.Error())
		}

		return control.LabInfo{}, err
	}

	record := control.RuntimeBinding{ProfileID: profile.ID, RuntimeID: rt.ID, Namespace: lab.Namespace,
		HelperEpoch: info.HelperID, UpdatedAt: s.d.now().UTC()}

	if err = state.SetBinding(record); err == nil {
		err = state.Save()
	}

	if err != nil {
		return lab, fmt.Errorf("lab %s created but its record was not saved (delete-lab still works): %w", lab.Namespace, err)
	}

	return lab, nil
}

// existingLab verifies, disconnects or deletes; none of them needs the signing key. Without a
// current record (an uncertain create, or a record from an earlier helper process) the helper's
// own registry decides, so cleanup never depends on controller state.
func (s *session) existingLab(profileID, namespace, operation string) (control.LabInfo, error) {
	remove := operation == "delete-lab"

	state, err := control.LoadRuntimeState(s.dataDir)
	if err != nil {
		return control.LabInfo{}, err
	}

	rt, info, err := s.currentRuntime(state)
	if err != nil {
		return control.LabInfo{}, err
	}

	// An unbound profile (for example after untrust-runtime) is judged by the helper alone.
	binding, bound := state.Binding(profileID)
	if !bound {
		binding = control.RuntimeBinding{ProfileID: profileID, RuntimeID: rt.ID}
	}

	if binding.RuntimeID != rt.ID {
		return control.LabInfo{}, labruntime.Errorf(labruntime.CodeOwnershipMismatch,
			fmt.Sprintf("profile is bound to runtime %s, not %s", binding.RuntimeID, rt.ID))
	}

	current := binding.Namespace != "" && binding.HelperEpoch == info.HelperID
	if current && binding.Namespace != namespace {
		return control.LabInfo{}, labruntime.Errorf(labruntime.CodeOwnershipMismatch,
			fmt.Sprintf("profile's lab is %s", binding.Namespace))
	}

	transport := s.provider.Transport()

	var lab control.LabInfo

	switch operation {
	case "delete-lab":
		lab, err = transport.DeleteLab(s.ctx, profileID, namespace)
	case "disconnect":
		lab, err = transport.Disconnect(s.ctx, profileID, namespace)
	case "verify-lab":
		lab, err = transport.VerifyLab(s.ctx, profileID, namespace)
	default:
		return control.LabInfo{}, labruntime.Errorf(labruntime.CodeInvalidRequest, "invalid lab operation")
	}

	if err != nil {
		return control.LabInfo{}, err
	}

	// Disconnect keeps the namespace and never creates or releases a binding.
	if (remove || operation == "disconnect") && !bound {
		return lab, nil
	}

	binding.Namespace, binding.HelperEpoch, binding.UpdatedAt = "", "", s.d.now().UTC()
	if !remove {
		binding.Namespace, binding.HelperEpoch = namespace, info.HelperID
	}

	if err = state.SetBinding(binding); err == nil {
		err = state.Save()
	}

	if err != nil {
		return lab, fmt.Errorf("lab %s: the helper succeeded but the controller record was not saved: %w", namespace, err)
	}

	return lab, nil
}

// unbindProfile releases a profile from its runtime once that runtime's helper owns no lab for it.
// If the runtime is gone for good, untrust-runtime removes its bindings instead.
func (s *session) unbindProfile(profileID string) (any, error) {
	state, err := control.LoadRuntimeState(s.dataDir)
	if err != nil {
		return nil, err
	}

	binding, bound := state.Binding(profileID)
	if !bound {
		return nil, labruntime.Errorf(labruntime.CodeLabNotFound, "profile is not bound to a runtime")
	}

	rt, _, err := s.currentRuntime(state)
	if err != nil {
		return nil, err
	}

	if binding.RuntimeID != rt.ID {
		return nil, labruntime.Errorf(labruntime.CodeOwnershipMismatch,
			fmt.Sprintf("profile is bound to runtime %s; reach that runtime, or untrust it", binding.RuntimeID))
	}

	labs, err := s.provider.Transport().ListLabs(s.ctx)
	if err != nil && labruntime.ErrorCode(err) != labruntime.CodeOperationDisabled {
		return nil, err
	}

	for _, lab := range labs {
		if lab.ProfileID == profileID {
			return nil, labruntime.Errorf(labruntime.CodeLabExists, fmt.Sprintf("the helper still owns lab %s; delete-lab first", lab.Namespace))
		}
	}

	state.RemoveBinding(profileID)

	return state, state.Save()
}

func dataDirectory() (string, error) {
	root := os.Getenv("EGRESSLAB_DATA_DIR")
	if root == "" {
		config, err := os.UserConfigDir()
		if err != nil {
			return "", err
		}

		root = filepath.Join(config, "EgressLab")
	}

	return filepath.Abs(root)
}

// defaultReservationRoot is the one per-user reservation authority. It is independent of
// EGRESSLAB_DATA_DIR and of the runtime: another data directory must not select another authority.
func defaultReservationRoot() (string, error) {
	config, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}

	if !filepath.IsAbs(config) {
		return "", errors.New("configuration directory must be absolute")
	}

	return filepath.Join(config, "EgressLab"), nil
}

func loadProfile(dataDir, id string) (control.RoutingProfile, error) {
	store, err := control.NewStore(filepath.Join(dataDir, "state.json"))
	if err != nil {
		return control.RoutingProfile{}, err
	}

	for _, profile := range store.Profiles() {
		if profile.ID == id {
			return profile, nil
		}
	}

	return control.RoutingProfile{}, errors.New("profile not found in controller state")
}

func usageError() error {
	return errors.New("usage: egresslab-controller-lab [-runtime auto|wsl|lima|native] [-wsl-distro NAME] [-lima-instance NAME] [-approve] COMMAND\n" +
		"  init-key | public-key | runtimes | runtime-status | helper-info | list-labs | multi-probe-policy\n" +
		"  init-reservations | list-reservations\n" +
		"  trust-runtime | untrust-runtime RUNTIME_ID | unbind-profile PROFILE_ID\n" +
		"  create-lab PROFILE_ID | verify-lab PROFILE_ID NAMESPACE | delete-lab PROFILE_ID NAMESPACE\n" +
		"  stage-info PROFILE_ID | connect-tunnel PROFILE_ID NAMESPACE STAGE_ID | disconnect PROFILE_ID NAMESPACE\n" +
		"  probe-egress PROFILE_ID NAMESPACE | probe-egress-multi PROFILE_ID NAMESPACE\n" +
		"  multi-probe-target PROFILE_ID NAMESPACE | reserve-egress PROFILE_ID NAMESPACE\n" +
		"  release-egress RESERVATION_ID")
}
