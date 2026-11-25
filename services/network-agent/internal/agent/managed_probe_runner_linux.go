//go:build linux

package agent

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/netip"
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

type managedProbeProcessRunner func(ctx context.Context, namespace string, workerArgs ...string) ([]byte, error)

// newSystemManagedProbeProcessRunner runs egresslab-probe in the lab namespace as probeUID:probeGID,
// with no supplementary groups, no capabilities and no_new_privs ("ip netns exec" enters the
// namespace, setpriv then drops everything). Only the trusted wrappers below choose workerArgs.
func newSystemManagedProbeProcessRunner(uid, gid int) (managedProbeProcessRunner, error) {
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

	return func(ctx context.Context, namespace string, workerArgs ...string) ([]byte, error) {
		if !labNamePattern.MatchString(namespace) {
			return nil, ErrProbeDestination
		}

		if err := ctx.Err(); err != nil {
			return nil, err
		}

		if err := verifyProbeBinary(managedProbeBinary); err != nil {
			return nil, err
		}

		args := []string{
			"netns", "exec", namespace,
			setprivPath,
			"--reuid=" + strconv.Itoa(uid),
			"--regid=" + strconv.Itoa(gid),
			"--clear-groups",
			"--inh-caps=-all",
			"--ambient-caps=-all",
			"--bounding-set=-all",
			"--no-new-privs",
			"--",
			managedProbeBinary,
		}

		cmd := exec.CommandContext(ctx, ipPath, append(args, workerArgs...)...)

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

// newSystemManagedProbeRunner is the legacy single-source runner: the worker without arguments,
// for the fixed trace URL only.
func newSystemManagedProbeRunner(uid, gid int) (egressProbeRunner, error) {
	run, err := newSystemManagedProbeProcessRunner(uid, gid)
	if err != nil {
		return nil, err
	}

	return func(ctx context.Context, namespace, url string) ([]byte, error) {
		if url != DefaultEgressProbeURL {
			return nil, ErrProbeDestination
		}

		return run(ctx, namespace)
	}, nil
}

// newSystemManagedMultiProbeRunner passes the worker one built-in source ID and its numeric pin.
func newSystemManagedMultiProbeRunner(uid, gid int) (managedMultiProbeRunner, error) {
	run, err := newSystemManagedProbeProcessRunner(uid, gid)
	if err != nil {
		return nil, err
	}

	return func(ctx context.Context, namespace string, source managedProbeHTTPSource) ([]byte, error) {
		if err := source.validate(); err != nil {
			return nil, err
		}

		return run(ctx, namespace, "--source", source.id, source.destination.String())
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

// NewManagedMultiProbeTunnelBackend is the explicit opt-in for the multi-source lifecycle. identPin
// comes from trusted local provisioning, never from the controller or an IPC request. The legacy
// single-source runner stays disabled, so a failed multi-source attempt has nothing to fall back to.
func NewManagedMultiProbeTunnelBackend(
	sealed *SealedLabBackend,
	vault *WireGuardConfigVault,
	probeUID, probeGID int,
	identPin netip.Addr,
) (*ManagedTunnelBackend, error) {
	if _, err := managedProbeHTTPSources(identPin); err != nil {
		return nil, err
	}

	backend, err := NewManagedTunnelBackend(sealed, vault)
	if err != nil {
		return nil, err
	}

	runner, err := newSystemManagedMultiProbeRunner(probeUID, probeGID)
	if err != nil {
		return nil, err
	}

	backend.multiProbe = &managedMultiProbeConfig{identPin: identPin, run: runner}

	return backend, nil
}
