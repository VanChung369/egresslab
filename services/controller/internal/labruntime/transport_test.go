package labruntime

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/VanChung369/egresslab/services/controller/internal/control"
)

const (
	testProfile   = "profile_0123456789abcdef"
	testNamespace = "egresslab-lab-0123456789abcdef"
	testHelperID  = "helper_0123456789abcdef0123456789abcdef"
	testStageID   = "wgstage_0123456789abcdef0123456789abcdef"
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
