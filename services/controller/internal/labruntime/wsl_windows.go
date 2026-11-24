//go:build windows

package labruntime

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
)

type wslLauncher struct {
	wsl    string
	distro string
}

func newWSL(distro string) (launcher, error) {
	if distro != "" && !instancePattern.MatchString(distro) {
		return nil, errors.New("invalid WSL distribution name")
	}

	root := os.Getenv("SystemRoot")
	if !filepath.IsAbs(root) {
		return nil, errors.New("invalid Windows SystemRoot")
	}

	return wslLauncher{wsl: filepath.Join(root, "System32", "wsl.exe"), distro: distro}, nil
}

func (wslLauncher) kind() string     { return "wsl" }
func (l wslLauncher) target() string { return l.distro }

func (l wslLauncher) name() string {
	if l.distro == "" {
		return "wsl"
	}

	return "wsl:" + l.distro
}

func (l wslLauncher) detect() error {
	if _, err := os.Stat(l.wsl); err != nil {
		return errors.New("WSL is not installed (wsl.exe not found)")
	}

	return nil
}

func (l wslLauncher) args(args ...string) []string {
	out := []string{}
	if l.distro != "" {
		out = append(out, "--distribution", l.distro)
	}

	// --exec runs the program directly, without a Linux shell.
	return append(append(out, "--exec", HelperctlPath), args...)
}

func (l wslLauncher) command(ctx context.Context, args ...string) (*exec.Cmd, error) {
	return exec.CommandContext(ctx, l.wsl, l.args(args...)...), nil
}
