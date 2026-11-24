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

// limaLauncher is unverified: written from the limactl docs, not yet run on macOS. The docs do not
// say whether stdin reaches the command (create-lab needs it) or whether a guest shell re-parses
// the arguments; transport arguments are restricted to plain tokens for that reason.
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

func (l limaLauncher) name() string { return "lima:" + l.instance }

func (l limaLauncher) detect() error {
	if _, err := exec.LookPath("limactl"); err != nil {
		return errors.New("Lima is not installed (limactl not found in PATH)")
	}

	return nil
}

func (l limaLauncher) args(args ...string) []string {
	return append([]string{"shell", "--workdir", "/", l.instance, HelperctlPath}, args...)
}

func (l limaLauncher) command(ctx context.Context, args ...string) (*exec.Cmd, error) {
	limactl, err := exec.LookPath("limactl")
	if err != nil {
		return nil, errors.New("Lima is not installed (limactl not found in PATH)")
	}

	return exec.CommandContext(ctx, limactl, l.args(args...)...), nil
}
