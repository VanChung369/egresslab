package labruntime

import (
	"context"
	"errors"
	"os/exec"
	"regexp"
)

const defaultLimaInstance = "egresslab"

// WSL distribution and Lima instance names.
var instancePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$`)

var errLimaMissing = errors.New("limactl not found in PATH: install Lima")

// limaLauncher: "limactl shell" forwards stdin to the command (verified with Lima 2.3.0 on macOS
// 15.3.2; create-lab and connect-tunnel need it). The command line reaches the guest through ssh,
// so transport arguments stay restricted to plain tokens.
type limaLauncher struct{ instance string }

func newLima(instance string) (launcher, error) {
	if instance == "" {
		instance = defaultLimaInstance
	}

	if !instancePattern.MatchString(instance) {
		return nil, errors.New("invalid Lima instance name")
	}

	return limaLauncher{instance: instance}, nil
}

func (limaLauncher) kind() string     { return "lima" }
func (l limaLauncher) target() string { return l.instance }
func (l limaLauncher) name() string   { return "lima:" + l.instance }

func (l limaLauncher) detect() error {
	if _, err := exec.LookPath("limactl"); err != nil {
		return errLimaMissing
	}

	return nil
}

func (l limaLauncher) args(args ...string) []string {
	return append([]string{"shell", "--workdir", "/", l.instance, HelperctlPath}, args...)
}

func (l limaLauncher) command(ctx context.Context, args ...string) (*exec.Cmd, error) {
	limactl, err := exec.LookPath("limactl")
	if err != nil {
		return nil, errLimaMissing
	}

	return exec.CommandContext(ctx, limactl, l.args(args...)...), nil
}
