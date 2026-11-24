package labruntime

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"slices"
	"strings"
	"time"
	"unicode"

	"github.com/VanChung369/egresslab/services/controller/internal/control"
)

const (
	maxResponseBytes = 64 * 1024
	maxStderrBytes   = 4096
	maxManagedLabs   = 8
)

// Some launchers (limactl shell) may hand arguments to a guest shell, so only plain tokens pass.
var safeArg = regexp.MustCompile(`^[a-z0-9_-]{1,64}$`)

type helperResponse struct {
	Version      int                    `json:"version"`
	Operation    string                 `json:"operation"`
	OK           bool                   `json:"ok"`
	NetworkReady bool                   `json:"network_ready"`
	Code         string                 `json:"code,omitempty"`
	Error        string                 `json:"error,omitempty"`
	Info         *control.LabHelperInfo `json:"helper_info,omitempty"`
	Lab          *control.LabInfo       `json:"lab,omitempty"`
	Labs         []control.LabInfo      `json:"labs,omitempty"`
	Stage        *control.LabStageInfo  `json:"stage,omitempty"`
}

type limitedBuffer struct {
	buf   bytes.Buffer
	limit int
}

func (b *limitedBuffer) Write(p []byte) (int, error) {
	if b.buf.Len()+len(p) > b.limit {
		return 0, errors.New("helperctl output too large")
	}

	return b.buf.Write(p)
}

type commandTransport struct{ l launcher }

func (t *commandTransport) run(ctx context.Context, expected string, input []byte, args ...string) (helperResponse, error) {
	for _, arg := range args {
		if !safeArg.MatchString(arg) {
			return helperResponse{}, errors.New("unsafe helperctl argument")
		}
	}

	cmd, err := t.l.command(ctx, args...)
	if err != nil {
		return helperResponse{}, err
	}

	stdout := &limitedBuffer{limit: maxResponseBytes}
	stderr := &limitedBuffer{limit: maxStderrBytes}

	cmd.Stdin = bytes.NewReader(input)
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	cmd.WaitDelay = 2 * time.Second

	if err := cmd.Run(); err != nil {
		// helperctl prints a coded failure document; anything else means the runtime itself failed.
		if refusal, ok := decodeFailure(stdout.buf.Bytes()); ok {
			return helperResponse{}, refusal
		}

		return helperResponse{}, Errorf(CodeRuntimeUnavailable,
			fmt.Sprintf("%s: helperctl %s failed: %v%s", t.l.name(), args[0], err, stderrDetail(stderr.buf.String())))
	}

	return decodeResponse(stdout.buf.Bytes(), expected)
}

// stderrDetail keeps the first line of helperctl's error, without control characters.
func stderrDetail(stderr string) string {
	line, _, _ := strings.Cut(strings.TrimSpace(stderr), "\n")
	line = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return -1
		}
		return r
	}, line)

	if len(line) > 200 {
		line = line[:200]
	}

	if line == "" {
		return ""
	}

	return ": " + line
}

func decodeStrict(data []byte) (helperResponse, error) {
	var resp helperResponse

	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()

	if err := decoder.Decode(&resp); err != nil {
		return helperResponse{}, Errorf(CodeInternal, "invalid helper response")
	}

	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return helperResponse{}, Errorf(CodeInternal, "trailing helper response")
	}

	return resp, nil
}

// decodeFailure reads helperctl's failure document. Unknown codes become INTERNAL.
func decodeFailure(data []byte) (error, bool) {
	resp, err := decodeStrict(data)
	if err != nil || resp.Version != 1 || resp.OK || resp.NetworkReady || resp.Error == "" ||
		resp.Info != nil || resp.Lab != nil || resp.Labs != nil || resp.Stage != nil {
		return nil, false
	}

	code := resp.Code
	if !helperCodes[code] {
		code = CodeInternal
	}

	message := strings.TrimPrefix(stderrDetail(resp.Error), ": ")
	if message == "" {
		message = "helper refused the request"
	}

	return Errorf(code, message), true
}

func decodeResponse(data []byte, expected string) (helperResponse, error) {
	resp, err := decodeStrict(data)
	if err != nil {
		return helperResponse{}, err
	}

	if resp.Version != 1 || resp.Operation != expected || !resp.OK || resp.NetworkReady || resp.Error != "" || resp.Code != "" {
		return helperResponse{}, errors.New("unexpected helper response")
	}

	if (expected == "HelperInfo") != (resp.Info != nil) || (resp.Info != nil && !resp.Info.Valid()) {
		return helperResponse{}, errors.New("unexpected helper identity metadata")
	}

	if (expected == "StageInfo") != (resp.Stage != nil) || (resp.Stage != nil && !resp.Stage.Valid()) {
		return helperResponse{}, errors.New("unexpected WireGuard stage metadata")
	}

	switch expected {
	case "HelperInfo", "Ping", "StageInfo":
		if resp.Lab != nil || resp.Labs != nil {
			return helperResponse{}, errors.New("unexpected lab metadata")
		}

	case "ListLabs":
		if resp.Lab != nil || !validLabList(resp.Labs) {
			return helperResponse{}, errors.New("invalid managed lab list")
		}

	default:
		if resp.Labs != nil || resp.Lab == nil {
			return helperResponse{}, errors.New("unexpected lab metadata")
		}
	}

	return resp, nil
}

func validLabList(labs []control.LabInfo) bool {
	if len(labs) > maxManagedLabs {
		return false
	}

	profiles := make(map[string]bool)
	namespaces := make(map[string]bool)

	for _, lab := range labs {
		if !control.ValidProfileID(lab.ProfileID) ||
			!control.ValidLabNamespace(lab.Namespace) ||
			(lab.State != control.LabSealed && lab.State != control.LabFaulted && lab.State != control.LabTunnelConfigured) ||
			profiles[lab.ProfileID] ||
			namespaces[lab.Namespace] {
			return false
		}

		profiles[lab.ProfileID] = true
		namespaces[lab.Namespace] = true
	}

	return true
}

func checkLab(lab *control.LabInfo, profileID, namespace string, states ...string) (control.LabInfo, error) {
	if lab == nil ||
		lab.ProfileID != profileID ||
		!control.ValidLabNamespace(lab.Namespace) ||
		!slices.Contains(states, lab.State) ||
		(namespace != "" && lab.Namespace != namespace) {
		return control.LabInfo{}, errors.New("helper returned a mismatched lab")
	}

	return *lab, nil
}

func (t *commandTransport) ping(ctx context.Context) error {
	_, err := t.run(ctx, "Ping", nil, "ping")
	return err
}

func (t *commandTransport) HelperInfo(ctx context.Context) (control.LabHelperInfo, error) {
	resp, err := t.run(ctx, "HelperInfo", nil, "helper-info")
	if err != nil {
		return control.LabHelperInfo{}, err
	}

	return *resp.Info, nil
}

func (t *commandTransport) ListLabs(ctx context.Context) ([]control.LabInfo, error) {
	resp, err := t.run(ctx, "ListLabs", nil, "list-labs")
	if err != nil {
		return nil, err
	}

	return resp.Labs, nil
}

// CreateLab sends the capability on stdin only. It never retries: after an error the result is
// uncertain, and ListLabs shows whether the lab exists.
func (t *commandTransport) CreateLab(ctx context.Context, profileID string, capability control.LabCapability) (control.LabInfo, error) {
	if !control.ValidProfileID(profileID) || capability.Claims.Intent.ProfileID != profileID {
		return control.LabInfo{}, errors.New("invalid CreateLab request")
	}

	payload, err := json.Marshal(capability)
	if err != nil {
		return control.LabInfo{}, err
	}
	defer clear(payload)

	resp, err := t.run(ctx, "CreateLab", payload, "create-lab", profileID)
	if err != nil {
		return control.LabInfo{}, err
	}

	return checkLab(resp.Lab, profileID, "", control.LabSealed)
}

func (t *commandTransport) VerifyLab(ctx context.Context, profileID, namespace string) (control.LabInfo, error) {
	return t.existingLab(ctx, "VerifyLab", "verify-lab", profileID, namespace, control.LabSealed, control.LabTunnelConfigured)
}

func (t *commandTransport) DeleteLab(ctx context.Context, profileID, namespace string) (control.LabInfo, error) {
	return t.existingLab(ctx, "DeleteLab", "delete-lab", profileID, namespace, control.LabDeleted)
}

func (t *commandTransport) existingLab(ctx context.Context, op, command, profileID, namespace string, states ...string) (control.LabInfo, error) {
	if !control.ValidProfileID(profileID) || !control.ValidLabNamespace(namespace) {
		return control.LabInfo{}, fmt.Errorf("invalid %s request", op)
	}

	resp, err := t.run(ctx, op, nil, command, profileID, namespace)
	if err != nil {
		return control.LabInfo{}, err
	}

	return checkLab(resp.Lab, profileID, namespace, states...)
}
