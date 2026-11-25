package labruntime

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/VanChung369/egresslab/services/controller/internal/control"
)

const (
	testProfile   = "profile_0123456789abcdef"
	testNamespace = "egresslab-lab-0123456789abcdef"
	testHelperID  = "helper_0123456789abcdef0123456789abcdef"
	testStageID   = "wgstage_0123456789abcdef0123456789abcdef"

	transportTestGeneration = "tunnelgen_0123456789abcdef0123456789abcdef"
	transportTestNonce      = "00112233445566778899aabbccddeeff"
)

var testFingerprint = strings.Repeat("ab", 32)

// TestFakeHelperctl is not a test: fakeLauncher runs the test binary as egresslab-helperctl.
func TestFakeHelperctl(t *testing.T) {
	mode := os.Getenv("EGRESSLAB_FAKE_HELPERCTL")
	if mode == "" {
		return
	}

	args := os.Args
	for i, arg := range args {
		if arg == "--" {
			args = args[i+1:]
			break
		}
	}

	// Like the real helperctl: a coded failure document on stdout, the message on stderr.
	failWith := func(code, msg string) {
		fmt.Printf("{\n  \"version\": 1,\n  \"operation\": \"\",\n  \"ok\": false,\n  \"network_ready\": false,\n  \"code\": %q,\n  \"error\": %q\n}\n", code, msg)
		fmt.Fprintln(os.Stderr, "helperctl:", msg)
		os.Exit(1)
	}
	fail := func(msg string) { failWith(CodeInvalidRequest, msg) }

	switch mode {
	case "denied":
		failWith(CodeAuthorizationDenied, "authorization denied")
	case "unknown-code":
		failWith("SOMETHING_NEW", "new failure")
	case "crash":
		fmt.Fprintln(os.Stderr, "wsl: the distribution is not installed")
		os.Exit(1)
	}

	respond := func(op string, extra string) {
		fmt.Printf("{\n  \"version\": 1,\n  \"operation\": %q,\n  \"ok\": true,\n  \"network_ready\": false%s\n}\n", op, extra)
		os.Exit(0)
	}

	lab := func(state string) string {
		return fmt.Sprintf(",\n  \"lab\": {\"profile_id\": %q, \"namespace\": %q, \"state\": %q}", testProfile, testNamespace, state)
	}

	switch args[0] {
	case "ping":
		respond("Ping", "")
	case "helper-info":
		respond("HelperInfo", fmt.Sprintf(",\n  \"helper_info\": {\"authorization_configured\": true, \"helper_id\": %q, \"public_key_sha256\": %q}",
			testHelperID, testFingerprint))
	case "list-labs":
		if mode == "no-lifecycle" {
			failWith(CodeOperationDisabled, "operation not enabled")
		}
		respond("ListLabs", fmt.Sprintf(",\n  \"labs\": [{\"profile_id\": %q, \"namespace\": %q, \"state\": \"sealed\"}]", testProfile, testNamespace))
	case "create-lab":
		var capability control.LabCapability
		data, _ := io.ReadAll(os.Stdin)
		if json.Unmarshal(data, &capability) != nil || capability.Claims.Intent.ProfileID != args[1] {
			fail("invalid capability JSON")
		}
		if mode == "garbage" {
			fmt.Print("not json")
			os.Exit(0)
		}
		respond("CreateLab", lab("sealed"))
	case "verify-lab":
		if mode == "tunnel" {
			respond("VerifyLab", lab(control.LabTunnelConfigured))
		}
		respond("VerifyLab", lab("sealed"))
	case "delete-lab":
		respond("DeleteLab", lab("deleted"))
	case "stage-info":
		switch mode {
		case "missing-stage":
			failWith(CodeStageNotFound, "WireGuard stage not found")
		case "foreign-stage":
			respond("StageInfo", fmt.Sprintf(",\n  \"stage\": {\"profile_id\": \"profile_ffffffffffffffff\", \"stage_id\": %q, \"vpn_lab_compatible\": true}", testStageID))
		case "no-stage-metadata":
			respond("StageInfo", "")
		}
		respond("StageInfo", fmt.Sprintf(",\n  \"stage\": {\"profile_id\": %q, \"stage_id\": %q, \"vpn_lab_compatible\": true}", testProfile, testStageID))
	case "connect-tunnel":
		var capability control.LabCapability
		data, err := io.ReadAll(os.Stdin)
		if err != nil || json.Unmarshal(data, &capability) != nil || len(args) != 4 ||
			capability.Claims.Intent != (control.LabIntent{Operation: "ConnectTunnel", ProfileID: args[1], Namespace: args[2], StageID: args[3]}) {
			fail("invalid tunnel capability")
		}
		if mode == "stage-on-connect" {
			respond("ConnectTunnel", lab(control.LabTunnelConfigured)+fmt.Sprintf(",\n  \"stage\": {\"profile_id\": %q, \"stage_id\": %q, \"vpn_lab_compatible\": true}", testProfile, testStageID))
		}
		respond("ConnectTunnel", lab(control.LabTunnelConfigured))
	case "probe-egress":
		var capability control.LabCapability
		data, err := io.ReadAll(os.Stdin)
		if err != nil || len(args) != 3 || json.Unmarshal(data, &capability) != nil ||
			capability.Claims.Intent != (control.LabIntent{Operation: "PermitProbe", ProfileID: args[1], Namespace: args[2],
				ProbeIPv4: control.LabProbeIPv4}) {
			fail("invalid probe capability")
		}

		switch mode {
		case "probe-disabled":
			failWith(CodeOperationDisabled, "operation not enabled")
		case "probe-no-result":
			respond("PermitProbe", "")
		}

		profile, ip, extra := testProfile, "8.8.4.4", ""
		switch mode {
		case "probe-mismatch":
			profile = "profile_ffffffffffffffff"
		case "probe-private":
			ip = "10.0.0.1"
		case "probe-with-lab":
			extra = lab(control.LabTunnelConfigured)
		}

		respond("PermitProbe", extra+fmt.Sprintf(",\n  \"probe\": {\"profile_id\": %q, \"namespace\": %q, \"ipv4\": %q, "+
			"\"observed_at\": \"2026-11-25T06:00:00Z\", \"handshake_at\": \"2026-11-25T05:59:59Z\", "+
			"\"source\": \"cloudflare_trace\"}", profile, testNamespace, ip))

	case "multi-probe-policy":
		policy := control.LabMultiProbePolicy{
			Policy:          control.LabMultiProbeV2Op,
			IdentIPv4:       "9.9.9.9",
			HelperID:        testHelperID,
			RuntimeID:       "runtime_0123456789abcdef0123456789abcdef",
			PublicKeySHA256: testFingerprint,
		}

		switch mode {
		case "multi-disabled":
			failWith(CodeOperationDisabled, "operation not enabled")
		case "multi-invalid-policy":
			policy.IdentIPv4 = "10.0.0.1"
		case "multi-unsupported-policy":
			policy.Policy = "PermitMultiProbeV3"
		case "multi-failure-with-null-policy":
			fmt.Printf(`{"version":1,"operation":"","ok":false,"network_ready":false,"code":%q,"error":"x",`+
				`"multi_probe_policy":null}`, CodeOperationDisabled)
			os.Exit(1)
		case "multi-failure-with-policy":
			raw, _ := json.Marshal(policy)
			fmt.Printf(`{"version":1,"operation":"","ok":false,"network_ready":false,"code":%q,"error":"x",`+
				`"multi_probe_policy":%s}`, CodeOperationDisabled, raw)
			os.Exit(1)
		}

		raw, _ := json.Marshal(policy)
		respond(control.LabMultiProbePolicyOp, `,"multi_probe_policy":`+string(raw))
	case "multi-probe-target":
		data, err := io.ReadAll(os.Stdin)
		if err != nil || len(data) != 0 || len(args) != 3 || args[1] != testProfile || args[2] != testNamespace {
			fail("invalid target discovery")
		}

		target := control.LabMultiProbeTarget{
			ProfileID:        testProfile,
			Namespace:        testNamespace,
			TunnelGeneration: transportTestGeneration,
			LabMultiProbePolicy: control.LabMultiProbePolicy{
				Policy:          control.LabMultiProbeV2Op,
				IdentIPv4:       "9.9.9.9",
				HelperID:        testHelperID,
				RuntimeID:       "runtime_0123456789abcdef0123456789abcdef",
				PublicKeySHA256: testFingerprint,
			},
		}

		extra := ""

		switch mode {
		case "multi-disabled":
			failWith(CodeOperationDisabled, "operation not enabled")
		case "multi-target-v1":
			target.Policy = control.LabMultiProbeOp
		case "multi-target-missing-generation":
			target.TunnelGeneration = ""
		case "multi-target-foreign-profile":
			target.ProfileID = "profile_ffffffffffffffff"
		case "multi-target-foreign-namespace":
			target.Namespace = "egresslab-lab-ffffffffffffffff"
		case "multi-target-missing":
			respond(control.LabMultiProbeTargetOp, "")
		case "multi-target-with-lab":
			extra = lab(control.LabTunnelConfigured)
		case "multi-target-failure-with-null":
			fmt.Printf(`{"version":1,"operation":"","ok":false,"network_ready":false,"code":%q,"error":"x",`+
				`"multi_probe_target":null}`, CodeOperationDisabled)
			os.Exit(1)
		}

		raw, _ := json.Marshal(target)
		respond(control.LabMultiProbeTargetOp, extra+`,"multi_probe_target":`+string(raw))
	case "probe-egress-multi":
		var capability control.LabCapability
		data, err := io.ReadAll(os.Stdin)
		if err != nil || len(args) != 3 || json.Unmarshal(data, &capability) != nil ||
			capability.Claims.Intent != (control.LabIntent{Operation: control.LabMultiProbeV2Op, ProfileID: args[1],
				Namespace: args[2], ProbeIPv4: "9.9.9.9", TunnelGeneration: transportTestGeneration}) ||
			capability.Claims.Nonce != transportTestNonce {
			fail("invalid generation-bound capability")
		}

		switch mode {
		case "multi-disabled":
			failWith(CodeOperationDisabled, "operation not enabled")
		case "multi-missing-result":
			respond(control.LabMultiProbeV2Op, "")
		}

		now := time.Unix(1795500000, 0).UTC()
		ip := netip.MustParseAddr("8.8.4.4")
		info := control.LabMultiProbeInfo{
			ProfileID:   testProfile,
			Namespace:   testNamespace,
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
			TunnelGeneration: transportTestGeneration,
			AttemptNonce:     transportTestNonce,
		}

		op := control.LabMultiProbeV2Op

		switch mode {
		case "multi-wrong-generation":
			info.TunnelGeneration = "tunnelgen_ffffffffffffffffffffffffffffffff"
		case "multi-wrong-nonce":
			info.AttemptNonce = strings.Repeat("f", 32)
		case "multi-v1-evidence":
			info.TunnelGeneration, info.AttemptNonce = "", ""
		case "multi-v1-response":
			info.TunnelGeneration, info.AttemptNonce = "", ""
			op = control.LabMultiProbeOp
		case "multi-wrong-pin":
			info.Sources[1].DestinationIPv4 = netip.MustParseAddr("8.8.8.8")
		case "multi-mismatch":
			info.Sources[1].IPv4 = netip.MustParseAddr("8.8.8.8")
		case "multi-foreign-profile":
			info.ProfileID = "profile_ffffffffffffffff"
		case "multi-failure-with-null":
			fmt.Printf(`{"version":1,"operation":"","ok":false,"network_ready":false,"code":%q,"error":"x",`+
				`"multi_probe":null}`, CodeLabFaulted)
			os.Exit(1)
		case "multi-failure-with-evidence":
			raw, _ := json.Marshal(info)
			fmt.Printf(`{"version":1,"operation":"","ok":false,"network_ready":false,"code":%q,"error":"x",`+
				`"multi_probe":%s}`, CodeLabFaulted, raw)
			os.Exit(1)
		}

		raw, _ := json.Marshal(info)
		extra := ""
		if mode == "multi-with-lab" {
			extra = lab(control.LabTunnelConfigured)
		}

		respond(op, extra+`,"multi_probe":`+string(raw))
	case "disconnect":
		if mode == "faulted" {
			respond("Disconnect", lab(control.LabFaulted))
		}
		respond("Disconnect", lab("sealed"))
	}

	fail("unexpected arguments")
}

type fakeLauncher struct {
	mode  string
	calls [][]string
}

func (f *fakeLauncher) kind() string   { return "fake" }
func (f *fakeLauncher) target() string { return "" }
func (f *fakeLauncher) name() string   { return "fake" }
func (f *fakeLauncher) detect() error  { return nil }

func (f *fakeLauncher) command(ctx context.Context, args ...string) (*exec.Cmd, error) {
	f.calls = append(f.calls, args)

	cmd := exec.CommandContext(ctx, os.Args[0], append([]string{"-test.run=^TestFakeHelperctl$", "--"}, args...)...)
	cmd.Env = append(os.Environ(), "EGRESSLAB_FAKE_HELPERCTL="+f.mode)

	return cmd, nil
}

func capabilityFor(profile string) control.LabCapability {
	return control.LabCapability{
		Claims: control.LabClaims{Version: 1, Intent: control.LabIntent{Operation: "CreateLab", ProfileID: profile}},
	}
}

func TestCommandTransport(t *testing.T) {
	ctx := context.Background()
	p := newCommandProvider(&fakeLauncher{mode: "ok"})
	tr := p.Transport()

	info, err := tr.HelperInfo(ctx)
	if err != nil || info.HelperID != testHelperID || info.PublicKeySHA256 != testFingerprint {
		t.Fatalf("helper info: %+v %v", info, err)
	}

	labs, err := tr.ListLabs(ctx)
	if err != nil || len(labs) != 1 || labs[0].Namespace != testNamespace {
		t.Fatalf("list: %+v %v", labs, err)
	}

	created, err := tr.CreateLab(ctx, testProfile, capabilityFor(testProfile))
	if err != nil || created.State != control.LabSealed {
		t.Fatalf("create: %+v %v", created, err)
	}

	if lab, err := tr.VerifyLab(ctx, testProfile, testNamespace); err != nil || lab.State != control.LabSealed {
		t.Fatalf("verify: %+v %v", lab, err)
	}

	if lab, err := tr.DeleteLab(ctx, testProfile, testNamespace); err != nil || lab.State != control.LabDeleted {
		t.Fatalf("delete: %+v %v", lab, err)
	}

	if status, err := p.Status(ctx); err != nil || !status.Reachable {
		t.Fatalf("status: %+v %v", status, err)
	}

	if caps, err := p.Capabilities(ctx); err != nil || !caps.AuthorizationConfigured || !caps.LabLifecycle {
		t.Fatalf("capabilities: %+v %v", caps, err)
	}
}

func TestCommandTransportFailures(t *testing.T) {
	ctx := context.Background()

	denied := newCommandProvider(&fakeLauncher{mode: "denied"})
	if _, err := denied.Transport().CreateLab(ctx, testProfile, capabilityFor(testProfile)); ErrorCode(err) != CodeAuthorizationDenied ||
		err.Error() != "AUTHORIZATION_DENIED: authorization denied" {
		t.Fatalf("denied: %v", err)
	}

	crash := newCommandProvider(&fakeLauncher{mode: "crash"})
	if _, err := crash.Transport().HelperInfo(ctx); ErrorCode(err) != CodeRuntimeUnavailable ||
		!strings.HasSuffix(err.Error(), ": wsl: the distribution is not installed") {
		t.Fatalf("runtime failure: %v", err)
	}

	unknown := newCommandProvider(&fakeLauncher{mode: "unknown-code"})
	if _, err := unknown.Transport().HelperInfo(ctx); ErrorCode(err) != CodeInternal {
		t.Fatalf("unknown code: %v", err)
	}

	if status, err := denied.Status(ctx); err != nil || status.Reachable {
		t.Fatalf("unreachable status: %+v %v", status, err)
	}

	garbage := newCommandProvider(&fakeLauncher{mode: "garbage"})
	if _, err := garbage.Transport().CreateLab(ctx, testProfile, capabilityFor(testProfile)); ErrorCode(err) != CodeInternal ||
		!strings.Contains(err.Error(), "invalid helper response") {
		t.Fatalf("garbage: %v", err)
	}

	caps, err := newCommandProvider(&fakeLauncher{mode: "no-lifecycle"}).Capabilities(ctx)
	if err != nil || !caps.AuthorizationConfigured || caps.LabLifecycle {
		t.Fatalf("lifecycle off: %+v %v", caps, err)
	}
}

func TestTransportValidatesBeforeLaunching(t *testing.T) {
	ctx := context.Background()
	fake := &fakeLauncher{mode: "ok"}
	tr := newCommandProvider(fake).Transport()

	if _, err := tr.CreateLab(ctx, "profile_x", capabilityFor("profile_x")); err == nil {
		t.Error("malformed profile accepted")
	}

	if _, err := tr.CreateLab(ctx, testProfile, capabilityFor("profile_ffffffffffffffff")); err == nil {
		t.Error("capability for another profile sent")
	}

	if _, err := tr.VerifyLab(ctx, testProfile, "../default"); err == nil {
		t.Error("malformed namespace accepted")
	}

	if _, err := tr.DeleteLab(ctx, "profile_0123456789abcdef; reboot", testNamespace); err == nil {
		t.Error("shell metacharacters accepted")
	}

	if len(fake.calls) != 0 {
		t.Fatalf("launcher called for invalid requests: %q", fake.calls)
	}
}

func TestDecodeResponse(t *testing.T) {
	info := `"helper_info": {"authorization_configured": true, "helper_id": "` + testHelperID + `", "public_key_sha256": "` + testFingerprint + `"}`
	lab := func(state string) string {
		return `"lab": {"profile_id": "` + testProfile + `", "namespace": "` + testNamespace + `", "state": "` + state + `"}`
	}
	labs := func(items ...string) string { return `"labs": [` + strings.Join(items, ",") + `]` }
	item := func(profile, namespace, state string) string {
		return `{"profile_id": "` + profile + `", "namespace": "` + namespace + `", "state": "` + state + `"}`
	}
	doc := func(op string, extra ...string) string {
		fields := append([]string{`"version": 1`, `"operation": "` + op + `"`, `"ok": true`, `"network_ready": false`}, extra...)
		return "{" + strings.Join(fields, ", ") + "}\n"
	}

	good := map[string][2]string{
		"helper info":         {"HelperInfo", doc("HelperInfo", info)},
		"helper unconfigured": {"HelperInfo", doc("HelperInfo", `"helper_info": {"authorization_configured": false}`)},
		"empty list":          {"ListLabs", doc("ListLabs")},
		"list":                {"ListLabs", doc("ListLabs", labs(item(testProfile, testNamespace, "faulted")))},
		"create":              {"CreateLab", doc("CreateLab", lab("sealed"))},
		"delete":              {"DeleteLab", doc("DeleteLab", lab("deleted"))},
	}

	for name, tt := range good {
		if _, err := decodeResponse([]byte(tt[1]), tt[0]); err != nil {
			t.Errorf("%s rejected: %v", name, err)
		}
	}

	bad := map[string][2]string{
		"other operation":      {"VerifyLab", doc("DeleteLab", lab("deleted"))},
		"network ready":        {"CreateLab", strings.Replace(doc("CreateLab", lab("sealed")), `"network_ready": false`, `"network_ready": true`, 1)},
		"not ok":               {"CreateLab", strings.Replace(doc("CreateLab"), `"ok": true`, `"ok": false`, 1)},
		"unknown field":        {"CreateLab", doc("CreateLab", lab("sealed"), `"admin": true`)},
		"trailing document":    {"CreateLab", doc("CreateLab", lab("sealed")) + doc("CreateLab", lab("sealed"))},
		"identity on create":   {"CreateLab", doc("CreateLab", lab("sealed"), info)},
		"missing identity":     {"HelperInfo", doc("HelperInfo")},
		"malformed identity":   {"HelperInfo", doc("HelperInfo", `"helper_info": {"authorization_configured": true, "helper_id": "helper_1"}`)},
		"lab on helper info":   {"HelperInfo", doc("HelperInfo", info, lab("sealed"))},
		"list on create":       {"CreateLab", doc("CreateLab", lab("sealed"), labs())},
		"missing lab":          {"VerifyLab", doc("VerifyLab")},
		"duplicate profile":    {"ListLabs", doc("ListLabs", labs(item(testProfile, testNamespace, "sealed"), item(testProfile, "egresslab-lab-ffffffffffffffff", "sealed")))},
		"deleted lab in list":  {"ListLabs", doc("ListLabs", labs(item(testProfile, testNamespace, "deleted")))},
		"malformed list entry": {"ListLabs", doc("ListLabs", labs(item("profile_x", testNamespace, "sealed")))},
		"error with ok":        {"CreateLab", doc("CreateLab", lab("sealed"), `"error": "x"`)},
		"code with ok":         {"CreateLab", doc("CreateLab", lab("sealed"), `"code": "LAB_BUSY"`)},
		"not JSON":             {"CreateLab", "helperctl: authorization denied"},
	}

	for name, tt := range bad {
		if _, err := decodeResponse([]byte(tt[1]), tt[0]); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}

func TestProviders(t *testing.T) {
	if _, err := New("remote", Options{}); !errors.Is(err, ErrNotImplemented) {
		t.Errorf("remote: %v", err)
	}

	if _, err := New("bogus", Options{}); err == nil {
		t.Error("unknown runtime accepted")
	}

	if _, err := New("lima", Options{LimaInstance: "a b"}); err == nil {
		t.Error("unsafe Lima instance accepted")
	}

	lima, err := New("lima", Options{})
	if err != nil {
		t.Fatal(err)
	}

	if err := lima.Start(context.Background()); !errors.Is(err, ErrNotImplemented) {
		t.Errorf("start: %v", err)
	}

	if err := lima.Stop(context.Background()); !errors.Is(err, ErrNotImplemented) {
		t.Errorf("stop: %v", err)
	}

	got := strings.Join(limaLauncher{instance: "egresslab"}.args("verify-lab", testProfile, testNamespace), " ")
	if got != "shell --workdir / egresslab "+HelperctlPath+" verify-lab "+testProfile+" "+testNamespace {
		t.Errorf("lima args: %s", got)
	}

	if kind, err := DefaultKind(); err != nil || kind == "" {
		t.Errorf("default kind: %q %v", kind, err)
	}
}

func TestDecodeFailure(t *testing.T) {
	failure := func(code, message string) []byte {
		data, _ := json.Marshal(helperResponse{Version: 1, Code: code, Error: message})
		return data
	}

	for name, tt := range map[string]struct {
		data []byte
		code string
		ok   bool
	}{
		"coded refusal":         {failure(CodeLabBusy, "busy"), CodeLabBusy, true},
		"unknown code":          {failure("NEW_CODE", "x"), CodeInternal, true},
		"whitespace message":    {failure(CodeLabBusy, " \n\t"), CodeLabBusy, true},
		"control characters":    {failure(CodeLabBusy, "\x1b[2J"), CodeLabBusy, true},
		"success is no failure": {[]byte(`{"version":1,"operation":"Ping","ok":true,"network_ready":false}`), "", false},
		"empty message":         {failure(CodeLabBusy, ""), "", false},
		"not JSON":              {[]byte("wsl: error"), "", false},
	} {
		err, ok := decodeFailure(tt.data)
		if ok != tt.ok || (ok && (ErrorCode(err) != tt.code || strings.TrimSpace(err.Error()) == tt.code+":")) {
			t.Errorf("%s: %v %t", name, err, ok)
		}
	}
}

func TestTunnelTransport(t *testing.T) {
	ctx := context.Background()
	launcher := &fakeLauncher{mode: "tunnel"}
	tr := newCommandProvider(launcher).Transport()

	stage, err := tr.StageInfo(ctx, testProfile)
	if err != nil || stage.StageID != testStageID || !stage.Compatible {
		t.Fatalf("stage: %+v %v", stage, err)
	}

	capability := control.LabCapability{Claims: control.LabClaims{Version: 1, Intent: control.LabIntent{
		Operation: "ConnectTunnel", ProfileID: testProfile, Namespace: testNamespace, StageID: testStageID,
	}}}

	before := len(launcher.calls)

	for _, stageID := range []string{"wgstage_ffffffffffffffffffffffffffffffff", "wgstage_x"} {
		if _, err := tr.ConnectTunnel(ctx, testProfile, testNamespace, stageID, capability); ErrorCode(err) != CodeInvalidRequest {
			t.Fatalf("stage %s: %v", stageID, err)
		}
	}

	createCapability := capabilityFor(testProfile)
	if _, err := tr.ConnectTunnel(ctx, testProfile, testNamespace, testStageID, createCapability); ErrorCode(err) != CodeInvalidRequest {
		t.Fatalf("CreateLab capability sent as ConnectTunnel: %v", err)
	}

	if len(launcher.calls) != before {
		t.Fatal("a mismatched request reached helperctl")
	}

	connected, err := tr.ConnectTunnel(ctx, testProfile, testNamespace, testStageID, capability)
	if err != nil || connected.State != control.LabTunnelConfigured {
		t.Fatalf("connect: %+v %v", connected, err)
	}

	// The capability travels on stdin, never in argv.
	last := launcher.calls[len(launcher.calls)-1]
	if strings.Join(last, " ") != "connect-tunnel "+testProfile+" "+testNamespace+" "+testStageID {
		t.Fatalf("helperctl arguments: %q", last)
	}

	verified, err := tr.VerifyLab(ctx, testProfile, testNamespace)
	if err != nil || verified.State != control.LabTunnelConfigured {
		t.Fatalf("verify: %+v %v", verified, err)
	}

	disconnected, err := tr.Disconnect(ctx, testProfile, testNamespace)
	if err != nil || disconnected.State != control.LabSealed {
		t.Fatalf("disconnect: %+v %v", disconnected, err)
	}

	faulted, err := newCommandProvider(&fakeLauncher{mode: "faulted"}).Transport().Disconnect(ctx, testProfile, testNamespace)
	if err != nil || faulted.State != control.LabFaulted {
		t.Fatalf("faulted disconnect: %+v %v", faulted, err)
	}

	if _, err := newCommandProvider(&fakeLauncher{mode: "missing-stage"}).Transport().StageInfo(ctx, testProfile); ErrorCode(err) != CodeStageNotFound {
		t.Fatalf("stage error code lost: %v", err)
	}

	for _, mode := range []string{"foreign-stage", "no-stage-metadata"} {
		if _, err := newCommandProvider(&fakeLauncher{mode: mode}).Transport().StageInfo(ctx, testProfile); err == nil {
			t.Errorf("%s accepted", mode)
		}
	}

	if _, err := newCommandProvider(&fakeLauncher{mode: "stage-on-connect"}).Transport().ConnectTunnel(ctx, testProfile, testNamespace, testStageID, capability); err == nil {
		t.Error("stage metadata accepted on ConnectTunnel")
	}
}

func TestProbeTransport(t *testing.T) {
	ctx := context.Background()

	capability := control.LabCapability{Claims: control.LabClaims{Version: 1, Intent: control.LabIntent{
		Operation: "PermitProbe", ProfileID: testProfile, Namespace: testNamespace, ProbeIPv4: control.LabProbeIPv4,
	}}}

	fake := &fakeLauncher{mode: "ok"}
	tr := newCommandProvider(fake).Transport()

	for name, intent := range map[string]control.LabIntent{
		"another destination": {Operation: "PermitProbe", ProfileID: testProfile, Namespace: testNamespace,
			ProbeIPv4: "8.8.8.8"},
		"another namespace": {Operation: "PermitProbe", ProfileID: testProfile, Namespace: "egresslab-lab-ffffffffffffffff",
			ProbeIPv4: control.LabProbeIPv4},
		"another operation": {Operation: "ConnectTunnel", ProfileID: testProfile, Namespace: testNamespace,
			ProbeIPv4: control.LabProbeIPv4},
	} {
		bad := capability
		bad.Claims.Intent = intent

		_, err := tr.ProbeEgress(ctx, testProfile, testNamespace, bad)
		if ErrorCode(err) != CodeInvalidRequest || len(fake.calls) != 0 {
			t.Fatalf("%s reached the launcher: %v", name, err)
		}
	}

	result, err := tr.ProbeEgress(ctx, testProfile, testNamespace, capability)
	if err != nil || result.IPv4.String() != "8.8.4.4" || result.Source != control.LabProbeSource || len(fake.calls) != 1 {
		t.Fatalf("probe: %+v %v", result, err)
	}

	want := []string{"probe-egress", testProfile, testNamespace}
	if args := fake.calls[0]; strings.Join(args, " ") != strings.Join(want, " ") {
		t.Fatalf("unexpected helperctl arguments: %q", args)
	}

	modes := []string{"probe-disabled", "probe-no-result", "probe-mismatch", "probe-private", "probe-with-lab"}
	for _, mode := range modes {
		f := &fakeLauncher{mode: mode}

		_, err := newCommandProvider(f).Transport().ProbeEgress(ctx, testProfile, testNamespace, capability)
		if err == nil || len(f.calls) != 1 {
			t.Fatalf("%s: invalid response accepted or retried: %v", mode, err)
		}

		if mode == "probe-disabled" && ErrorCode(err) != CodeOperationDisabled {
			t.Fatalf("operation disabled code lost: %v", err)
		}
	}
}

func TestMultiProbeTransport(t *testing.T) {
	ctx := context.Background()
	capability := control.LabCapability{Claims: control.LabClaims{Version: 1, HelperID: testHelperID,
		Nonce: transportTestNonce, Intent: control.LabIntent{Operation: control.LabMultiProbeV2Op, ProfileID: testProfile,
			Namespace: testNamespace, ProbeIPv4: "9.9.9.9", TunnelGeneration: transportTestGeneration}}}

	fake := &fakeLauncher{mode: "ok"}
	tr := newCommandProvider(fake).Transport()

	policy, err := tr.MultiProbePolicy(ctx)
	if err != nil || policy.Policy != control.LabMultiProbeV2Op || policy.IdentIPv4 != "9.9.9.9" ||
		len(fake.calls) != 1 || strings.Join(fake.calls[0], " ") != "multi-probe-policy" {
		t.Fatalf("policy discovery: %+v %v %v", policy, err, fake.calls)
	}

	for name, edit := range map[string]func(*control.LabIntent){
		"single-source operation": func(i *control.LabIntent) {
			i.Operation, i.ProbeIPv4, i.TunnelGeneration = "PermitProbe", control.LabProbeIPv4, ""
		},
		"V1 operation":       func(i *control.LabIntent) { i.Operation, i.TunnelGeneration = control.LabMultiProbeOp, "" },
		"V1 with generation": func(i *control.LabIntent) { i.Operation = control.LabMultiProbeOp },
		"missing generation": func(i *control.LabIntent) { i.TunnelGeneration = "" },
		"Cloudflare as pin":  func(i *control.LabIntent) { i.ProbeIPv4 = control.LabProbeIPv4 },
		"private pin":        func(i *control.LabIntent) { i.ProbeIPv4 = "10.0.0.1" },
		"other namespace":    func(i *control.LabIntent) { i.Namespace = "egresslab-lab-ffffffffffffffff" },
	} {
		bad := capability
		edit(&bad.Claims.Intent)

		if _, err := tr.ProbeEgressMulti(ctx, testProfile, testNamespace, bad); ErrorCode(err) != CodeInvalidRequest ||
			len(fake.calls) != 1 {
			t.Fatalf("%s reached the launcher: %v", name, err)
		}
	}

	info, err := tr.ProbeEgressMulti(ctx, testProfile, testNamespace, capability)
	if err != nil || info.IPv4.String() != "8.8.4.4" || info.TunnelGeneration != transportTestGeneration ||
		info.AttemptNonce != transportTestNonce || len(info.Sources) != 2 || len(fake.calls) != 2 {
		t.Fatalf("generation-bound result: %+v %v", info, err)
	}

	if strings.Join(fake.calls[1], " ") != strings.Join([]string{"probe-egress-multi", testProfile, testNamespace}, " ") {
		t.Fatalf("unexpected launcher arguments: %v", fake.calls[1])
	}

	for mode, code := range map[string]string{
		"multi-disabled":              CodeOperationDisabled,
		"multi-missing-result":        "",
		"multi-wrong-pin":             "",
		"multi-mismatch":              "",
		"multi-foreign-profile":       "",
		"multi-with-lab":              "",
		"multi-wrong-generation":      "",
		"multi-wrong-nonce":           "",
		"multi-v1-evidence":           "",
		"multi-v1-response":           "",
		"multi-failure-with-evidence": CodeRuntimeUnavailable,
		"multi-failure-with-null":     CodeRuntimeUnavailable,
	} {
		f := &fakeLauncher{mode: mode}

		result, err := newCommandProvider(f).Transport().ProbeEgressMulti(ctx, testProfile, testNamespace, capability)
		if err == nil || result.IPv4.IsValid() || result.Sources != nil || len(f.calls) != 1 ||
			(code != "" && ErrorCode(err) != code) {
			t.Fatalf("%s: response accepted, retried or misclassified: %v", mode, err)
		}
	}
}

func TestMultiProbeTargetTransport(t *testing.T) {
	ctx := context.Background()
	fake := &fakeLauncher{mode: "ok"}
	tr := newCommandProvider(fake).Transport()

	target, err := tr.MultiProbeTarget(ctx, testProfile, testNamespace)
	if err != nil || target.TunnelGeneration != transportTestGeneration || target.Policy != control.LabMultiProbeV2Op ||
		target.ProfileID != testProfile || target.Namespace != testNamespace || len(fake.calls) != 1 ||
		strings.Join(fake.calls[0], " ") != "multi-probe-target "+testProfile+" "+testNamespace {
		t.Fatalf("target discovery: %+v %v %v", target, err, fake.calls)
	}

	for _, args := range [][2]string{{"invalid-profile", testNamespace}, {testProfile, "../default"}} {
		if _, err := tr.MultiProbeTarget(ctx, args[0], args[1]); ErrorCode(err) != CodeInvalidRequest ||
			len(fake.calls) != 1 {
			t.Fatalf("invalid target request %v reached the launcher: %v", args, err)
		}
	}

	for mode, code := range map[string]string{
		"multi-disabled":                  CodeOperationDisabled,
		"multi-target-v1":                 CodeRuntimeUntrusted,
		"multi-target-missing-generation": CodeRuntimeUntrusted,
		"multi-target-foreign-profile":    CodeOwnershipMismatch,
		"multi-target-foreign-namespace":  CodeOwnershipMismatch,
		"multi-target-missing":            "",
		"multi-target-with-lab":           "",
		"multi-target-failure-with-null":  CodeRuntimeUnavailable,
	} {
		f := &fakeLauncher{mode: mode}

		result, err := newCommandProvider(f).Transport().MultiProbeTarget(ctx, testProfile, testNamespace)
		if err == nil || result != (control.LabMultiProbeTarget{}) || len(f.calls) != 1 ||
			(code != "" && ErrorCode(err) != code) {
			t.Fatalf("%s: target accepted, retried or misclassified: %v", mode, err)
		}
	}
}

func TestMultiProbePolicyTransportRefusals(t *testing.T) {
	for mode, code := range map[string]string{
		"multi-disabled":                 CodeOperationDisabled,
		"multi-invalid-policy":           CodeRuntimeUntrusted,
		"multi-unsupported-policy":       CodeRuntimeUntrusted,
		"multi-failure-with-policy":      CodeRuntimeUnavailable,
		"multi-failure-with-null-policy": CodeRuntimeUnavailable,
	} {
		fake := &fakeLauncher{mode: mode}

		result, err := newCommandProvider(fake).Transport().MultiProbePolicy(context.Background())
		if err == nil || result != (control.LabMultiProbePolicy{}) || len(fake.calls) != 1 ||
			(code != "" && ErrorCode(err) != code) {
			t.Fatalf("%s: policy accepted, retried or misclassified: %v", mode, err)
		}
	}
}

// decodeResponse checks the metadata itself, before any caller does.
func TestDecodeMultiProbeMetadata(t *testing.T) {
	policy := control.LabMultiProbePolicy{Policy: control.LabMultiProbeOp, IdentIPv4: "10.0.0.1", HelperID: testHelperID,
		RuntimeID: "runtime_0123456789abcdef0123456789abcdef", PublicKeySHA256: testFingerprint}
	rawPolicy, _ := json.Marshal(policy)

	now := time.Unix(1795500000, 0).UTC()
	evidence := control.LabMultiProbeInfo{ProfileID: testProfile, Namespace: testNamespace,
		IPv4: netip.MustParseAddr("8.8.4.4"), StartedAt: now, FinishedAt: now, ObservedAt: now, HandshakeAt: now}
	rawEvidence, _ := json.Marshal(evidence)

	for op, field := range map[string]string{
		control.LabMultiProbePolicyOp: `"multi_probe_policy":` + string(rawPolicy),
		control.LabMultiProbeOp:       `"multi_probe":` + string(rawEvidence),
	} {
		doc := `{"version":1,"operation":"` + op + `","ok":true,"network_ready":false,` + field + `}`
		if _, err := decodeResponse([]byte(doc), op); err == nil {
			t.Errorf("%s: invalid metadata decoded", op)
		}
	}
}

func TestDecodeGenerationProbeMetadata(t *testing.T) {
	now := time.Unix(1795500000, 0).UTC()
	ip := netip.MustParseAddr("8.8.4.4")
	evidence := control.LabMultiProbeInfo{ProfileID: testProfile, Namespace: testNamespace, IPv4: ip, StartedAt: now,
		FinishedAt: now, ObservedAt: now, HandshakeAt: now, TunnelGeneration: transportTestGeneration,
		AttemptNonce: transportTestNonce, Sources: []control.LabMultiProbeSourceInfo{
			{Source: control.LabProbeSource, DestinationIPv4: netip.MustParseAddr(control.LabProbeIPv4), IPv4: ip,
				ObservedAt: now},
			{Source: control.LabMultiProbeIdentSource, DestinationIPv4: netip.MustParseAddr("9.9.9.9"), IPv4: ip,
				ObservedAt: now},
		}}
	legacy := evidence
	legacy.TunnelGeneration, legacy.AttemptNonce = "", ""

	target := control.LabMultiProbeTarget{ProfileID: testProfile, Namespace: testNamespace,
		TunnelGeneration: transportTestGeneration, LabMultiProbePolicy: control.LabMultiProbePolicy{
			Policy: control.LabMultiProbeV2Op, IdentIPv4: "9.9.9.9", HelperID: testHelperID,
			RuntimeID: "runtime_0123456789abcdef0123456789abcdef", PublicKeySHA256: testFingerprint}}
	v1Target := target
	v1Target.Policy = control.LabMultiProbeOp

	field := func(key string, value any) string {
		raw, _ := json.Marshal(value)
		return `,"` + key + `":` + string(raw)
	}
	doc := func(op, fields string) []byte {
		return []byte(`{"version":1,"operation":"` + op + `","ok":true,"network_ready":false` + fields + `}`)
	}

	for _, tt := range []struct {
		name, op, fields string
		ok               bool
		code             string
	}{
		{"V2 evidence", control.LabMultiProbeV2Op, field("multi_probe", evidence), true, ""},
		{"V1 evidence", control.LabMultiProbeOp, field("multi_probe", legacy), true, ""},
		{"target", control.LabMultiProbeTargetOp, field("multi_probe_target", target), true, ""},
		{"V1 evidence for V2", control.LabMultiProbeV2Op, field("multi_probe", legacy), false, ""},
		{"V2 evidence for V1", control.LabMultiProbeOp, field("multi_probe", evidence), false, ""},
		{"V1 target", control.LabMultiProbeTargetOp, field("multi_probe_target", v1Target), false, CodeRuntimeUntrusted},
		{"target without metadata", control.LabMultiProbeTargetOp, "", false, ""},
		{"target with evidence", control.LabMultiProbeTargetOp,
			field("multi_probe_target", target) + field("multi_probe", evidence), false, ""},
		{"evidence with target", control.LabMultiProbeV2Op,
			field("multi_probe", evidence) + field("multi_probe_target", target), false, ""},
		{"target with policy", control.LabMultiProbeTargetOp,
			field("multi_probe_target", target) + field("multi_probe_policy", target.LabMultiProbePolicy), false, ""},
	} {
		_, err := decodeResponse(doc(tt.op, tt.fields), tt.op)
		if (err == nil) != tt.ok || (tt.code != "" && ErrorCode(err) != tt.code) {
			t.Errorf("%s: %v", tt.name, err)
		}
	}

	failure := `{"version":1,"operation":"","ok":false,"network_ready":false,"code":"LAB_FAULTED","error":"x"` +
		field("multi_probe_target", target) + `}`
	if _, ok := decodeFailure([]byte(failure)); ok {
		t.Fatal("failure document with a target accepted")
	}
}

func TestDecodeFailureRefusesFoldedMetadataKeys(t *testing.T) {
	for _, key := range []string{"Multi_Probe_Target", "MULTI_PROBE", "Lab", "ſtage", "HELPER_INFO"} {
		doc := `{"version":1,"operation":"","ok":false,"network_ready":false,"code":"AUTHORIZATION_DENIED",` +
			`"error":"x","` + key + `":null}`

		if _, err := decodeStrict([]byte(doc)); err != nil {
			t.Fatalf("%q: the decoder no longer folds field names: %v", key, err)
		}

		if err, ok := decodeFailure([]byte(doc)); ok {
			t.Errorf("%q: failure document with metadata accepted as %v", key, err)
		}
	}
}
