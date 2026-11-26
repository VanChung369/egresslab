// Package labruntime reaches the Linux network runtime (helper plus agent) from the controller,
// whatever the host OS: WSL2 on Windows, a Lima VM on macOS, the host itself on Linux. Every
// provider runs the unprivileged egresslab-helperctl inside the runtime; only the launcher differs.
package labruntime

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"runtime"

	"github.com/VanChung369/egresslab/services/controller/internal/control"
)

// HelperctlPath is where egresslab-helperctl is installed inside every Linux runtime.
const HelperctlPath = "/usr/local/bin/egresslab-helperctl"

var ErrNotImplemented = errors.New("not implemented for this runtime")

type Status struct {
	Provider  string `json:"provider"`
	Reachable bool   `json:"reachable"`
	Detail    string `json:"detail,omitempty"`
}

type Capabilities struct {
	Provider                string `json:"provider"`
	AuthorizationConfigured bool   `json:"authorization_configured"`
	LabLifecycle            bool   `json:"lab_lifecycle"`
}

type RuntimeProvider interface {
	Name() string
	// Kind and Target identify how the runtime is reached ("wsl" and a distribution, "lima" and an
	// instance, "native" and ""). They are what a trusted runtime is pinned to.
	Kind() string
	Target() string
	Detect(ctx context.Context) error
	Start(ctx context.Context) error
	Stop(ctx context.Context) error
	Status(ctx context.Context) (Status, error)
	Capabilities(ctx context.Context) (Capabilities, error)
	Transport() HelperTransport
}

type HelperTransport interface {
	HelperInfo(ctx context.Context) (control.LabHelperInfo, error)
	ListLabs(ctx context.Context) ([]control.LabInfo, error)
	CreateLab(ctx context.Context, profileID string, capability control.LabCapability) (control.LabInfo, error)
	VerifyLab(ctx context.Context, profileID, namespace string) (control.LabInfo, error)
	DeleteLab(ctx context.Context, profileID, namespace string) (control.LabInfo, error)
	StageInfo(ctx context.Context, profileID string) (control.LabStageInfo, error)
	ConnectTunnel(ctx context.Context, profileID, namespace, stageID string, capability control.LabCapability) (control.LabInfo, error)
	Disconnect(ctx context.Context, profileID, namespace string) (control.LabInfo, error)
	ProbeEgress(ctx context.Context, profileID, namespace string, capability control.LabCapability) (control.LabProbeInfo, error)
	MultiProbePolicy(ctx context.Context) (control.LabMultiProbePolicy, error)
	MultiProbeTarget(ctx context.Context, profileID, namespace string) (control.LabMultiProbeTarget, error)
	ProbeEgressMulti(
		ctx context.Context,
		profileID, namespace string,
		capability control.LabCapability,
	) (control.LabMultiProbeInfo, error)
	ReserveEgressCandidate(
		ctx context.Context,
		profileID, namespace string,
		capability control.LabCapability,
	) (control.LabCandidateInfo, error)
	PrepareEgressLease(
		ctx context.Context,
		profileID, namespace string,
		capability control.LabCapability,
	) (control.LabPreparedLeaseInfo, error)
	RevokeEgressLease(
		ctx context.Context,
		profileID, namespace string,
		capability control.LabCapability,
	) (control.LabRevokedLeaseInfo, error)
}

type Options struct {
	WSLDistro    string // empty: the default WSL distribution
	LimaInstance string // empty: "egresslab"
}

// launcher builds the command that runs helperctl inside the runtime.
type launcher interface {
	kind() string
	target() string
	name() string
	detect() error
	command(ctx context.Context, args ...string) (*exec.Cmd, error)
}

func DefaultKind() (string, error) {
	switch runtime.GOOS {
	case "windows":
		return "wsl", nil
	case "darwin":
		return "lima", nil
	case "linux":
		return "native", nil
	default:
		return "", fmt.Errorf("no default network runtime for %s", runtime.GOOS)
	}
}

func New(kind string, opts Options) (RuntimeProvider, error) {
	if kind == "auto" {
		var err error
		if kind, err = DefaultKind(); err != nil {
			return nil, err
		}
	}

	var l launcher
	var err error

	switch kind {
	case "wsl":
		l, err = newWSL(opts.WSLDistro)
	case "lima":
		l, err = newLima(opts.LimaInstance)
	case "native":
		l, err = newNative()
	case "remote":
		return nil, fmt.Errorf("remote runtime: %w", ErrNotImplemented)
	default:
		return nil, fmt.Errorf("unknown runtime %q (auto, wsl, lima, native, remote)", kind)
	}

	if err != nil {
		return nil, err
	}

	return newCommandProvider(l), nil
}

type commandProvider struct {
	l         launcher
	transport *commandTransport
}

func newCommandProvider(l launcher) *commandProvider {
	return &commandProvider{l: l, transport: &commandTransport{l: l}}
}

func (p *commandProvider) Name() string                 { return p.l.name() }
func (p *commandProvider) Kind() string                 { return p.l.kind() }
func (p *commandProvider) Target() string               { return p.l.target() }
func (p *commandProvider) Detect(context.Context) error { return p.l.detect() }
func (p *commandProvider) Transport() HelperTransport   { return p.transport }
func (p *commandProvider) Start(ctx context.Context) error {
	return fmt.Errorf("start %s: %w", p.Name(), ErrNotImplemented)
}
func (p *commandProvider) Stop(ctx context.Context) error {
	return fmt.Errorf("stop %s: %w", p.Name(), ErrNotImplemented)
}

func (p *commandProvider) Status(ctx context.Context) (Status, error) {
	status := Status{Provider: p.Name()}

	if err := p.l.detect(); err != nil {
		status.Detail = err.Error()
		return status, nil
	}

	if err := p.transport.ping(ctx); err != nil {
		status.Detail = err.Error()
		return status, nil
	}

	status.Reachable = true

	return status, nil
}

func (p *commandProvider) Capabilities(ctx context.Context) (Capabilities, error) {
	info, err := p.transport.HelperInfo(ctx)
	if err != nil {
		return Capabilities{}, err
	}

	caps := Capabilities{Provider: p.Name(), AuthorizationConfigured: info.AuthorizationConfigured}

	if _, err := p.transport.ListLabs(ctx); err == nil {
		caps.LabLifecycle = true
	} else if ErrorCode(err) != CodeOperationDisabled {
		return Capabilities{}, err
	}

	return caps, nil
}
