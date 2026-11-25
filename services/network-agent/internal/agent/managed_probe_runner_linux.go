//go:build linux

package agent

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"syscall"
	"time"
)

const managedProbeBinary = "/usr/local/bin/egresslab-probe"

// verifyProbeBinary requires a root-owned, executable regular file without setuid or setgid, in
// directories that root owns and nobody else can write, up to "/".
func verifyProbeBinary(binary string) error {
	if !filepath.IsAbs(binary) {
		return ErrManagedProbeUnavailable
	}

	for path := filepath.Clean(binary); ; path = filepath.Dir(path) {
		info, err := os.Lstat(path)
		if err != nil {
			return ErrManagedProbeUnavailable
		}

		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || stat.Uid != 0 || info.Mode().Perm()&0o022 != 0 {
			return ErrManagedProbeUnavailable
		}

		if path == filepath.Clean(binary) {
			if !info.Mode().IsRegular() || info.Mode().Perm()&0o111 == 0 ||
				info.Mode()&(os.ModeSetuid|os.ModeSetgid) != 0 {
				return ErrManagedProbeUnavailable
			}
		} else if !info.IsDir() {
			return ErrManagedProbeUnavailable
		}

		if path == "/" {
			return nil
		}
	}
}

type boundedProbeOutput struct{ buf bytes.Buffer }

func (b *boundedProbeOutput) Write(data []byte) (int, error) {
	if len(data) > maxEgressProbeBytes-b.buf.Len() {
		return 0, errors.New("probe output limit exceeded")
	}

	return b.buf.Write(data)
}

// newSystemManagedProbeRunner runs egresslab-probe in the lab namespace as probeUID:probeGID, with
// no supplementary groups, no capabilities and no_new_privs ("ip netns exec" enters the namespace,
// setpriv then drops everything). The worker takes no arguments: its URL is fixed.
func newSystemManagedProbeRunner(uid, gid int) (egressProbeRunner, error) {
	if uid <= 0 || gid <= 0 || uint64(uid) >= uint64(^uint32(0)) || uint64(gid) >= uint64(^uint32(0)) {
		return nil, ErrManagedProbeUnavailable
	}

	ipPath, err := findSystemBinary("ip")
	if err != nil {
		return nil, err
	}

	setprivPath, err := findSystemBinary("setpriv")
	if err != nil {
		return nil, err
	}

	if err := verifyProbeBinary(managedProbeBinary); err != nil {
		return nil, err
	}

	return func(ctx context.Context, namespace, url string) ([]byte, error) {
		if !labNamePattern.MatchString(namespace) || url != DefaultEgressProbeURL {
			return nil, ErrProbeDestination
		}

		if err := verifyProbeBinary(managedProbeBinary); err != nil {
			return nil, err
		}

		cmd := exec.CommandContext(ctx, ipPath,
			"netns", "exec", namespace,
			setprivPath,
			"--reuid="+strconv.Itoa(uid),
			"--regid="+strconv.Itoa(gid),
			"--clear-groups",
			"--inh-caps=-all",
			"--ambient-caps=-all",
			"--bounding-set=-all",
			"--no-new-privs",
			"--",
			managedProbeBinary,
		)

		isolateFromTerminalSignals(cmd)

		// No proxy, TLS, HOME or loader variables are inherited.
		cmd.Dir = "/"
		cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "HOME=/nonexistent", "LANG=C", "LC_ALL=C"}
		cmd.WaitDelay = time.Second

		var output boundedProbeOutput
		cmd.Stdout = &output
		cmd.Stderr = io.Discard

		if err := cmd.Run(); err != nil {
			return nil, ErrManagedProbeFailed
		}

		if err := ctx.Err(); err != nil {
			return nil, err
		}

		return output.buf.Bytes(), nil
	}, nil
}

// NewManagedProbeTunnelBackend is the explicit opt-in for the signed probe lifecycle (Step 29B.2).
// NewManagedTunnelBackend stays probe-disabled.
func NewManagedProbeTunnelBackend(
	sealed *SealedLabBackend,
	vault *WireGuardConfigVault,
	probeUID, probeGID int,
) (*ManagedTunnelBackend, error) {
	backend, err := NewManagedTunnelBackend(sealed, vault)
	if err != nil {
		return nil, err
	}

	runner, err := newSystemManagedProbeRunner(probeUID, probeGID)
	if err != nil {
		return nil, err
	}

	backend.vpn.probe = runner

	return backend, nil
}
