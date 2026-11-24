//go:build linux

package labruntime

import (
	"context"
	"errors"
	"os"
	"os/exec"
)

type nativeLauncher struct{ path string }

func newNative() (launcher, error) { return nativeLauncher{path: HelperctlPath}, nil }

func (nativeLauncher) kind() string   { return "native" }
func (nativeLauncher) target() string { return "" }
func (nativeLauncher) name() string   { return "native" }

func (l nativeLauncher) detect() error {
	info, err := os.Stat(l.path)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o111 == 0 {
		return errors.New(l.path + " is not installed")
	}

	return nil
}

func (l nativeLauncher) command(ctx context.Context, args ...string) (*exec.Cmd, error) {
	return exec.CommandContext(ctx, l.path, args...), nil
}
