//go:build linux

package main

import (
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/VanChung369/egresslab/services/network-agent/internal/helperauth"
)

const (
	multiProbePinPath     = "/etc/egresslab/multi-probe-pin"
	maxMultiProbePinBytes = 64
)

// loadMultiProbePin reads the ident.me pin of PermitMultiProbeV1 from trusted local configuration:
// a root-owned regular file in root-owned directories, read once at startup. There is no flag,
// environment variable, IPC field or DNS lookup for it; changing it means a restart, and so a new
// helper epoch.
func loadMultiProbePin() (netip.Addr, error) {
	return loadMultiProbePinOwnedBy(multiProbePinPath, 0, "/")
}

// loadMultiProbePinOwnedBy takes the owner UID and the top directory to check as parameters, so the
// accept path can be tested without root.
func loadMultiProbePinOwnedBy(path string, owner uint32, root string) (netip.Addr, error) {
	// Not cleaned: after a symlink, ".." would make the checked file differ from the one a later
	// rename of the same path installs.
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return netip.Addr{}, errors.New("multi-source policy path must be absolute and canonical")
	}

	if err := checkDirChain(filepath.Dir(path), root, owner); err != nil {
		return netip.Addr{}, fmt.Errorf("multi-source policy directory: %w", err)
	}

	before, err := os.Lstat(path)
	if err != nil {
		return netip.Addr{}, fmt.Errorf("inspect multi-source policy: %w", err)
	}

	if err := checkMultiProbePinFile(before, owner); err != nil {
		return netip.Addr{}, err
	}

	// No symlink, and no blocking on a FIFO swapped in after the check.
	file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return netip.Addr{}, err
	}
	defer file.Close()

	opened, err := file.Stat()
	if err != nil {
		return netip.Addr{}, err
	}

	if !os.SameFile(before, opened) {
		return netip.Addr{}, errors.New("multi-source policy file changed while it was being opened")
	}

	if err := checkMultiProbePinFile(opened, owner); err != nil {
		return netip.Addr{}, err
	}

	data, err := io.ReadAll(io.LimitReader(file, maxMultiProbePinBytes+1))
	if err != nil {
		return netip.Addr{}, err
	}

	return parseMultiProbePin(data)
}

// checkMultiProbePinCommand applies the startup rules to a staged pin file, so a rotation can be
// checked before it replaces the working pin. It prints nothing secret: the pin is public.
func checkMultiProbePinCommand(args []string) (netip.Addr, error) {
	if len(args) != 1 {
		return netip.Addr{}, errors.New("usage: sudo egresslab-helper check-multi-probe-pin PATH")
	}

	return loadMultiProbePinOwnedBy(args[0], 0, "/")
}

func checkMultiProbePinFile(info os.FileInfo, owner uint32) error {
	if err := checkOwned(info, owner, false); err != nil {
		return fmt.Errorf("unsafe multi-source policy file: %w", err)
	}

	if info.Size() <= 0 || info.Size() > maxMultiProbePinBytes {
		return errors.New("invalid multi-source policy file size")
	}

	return nil
}

// parseMultiProbePin accepts one canonical public IPv4 address other than 1.1.1.1, with at most one
// trailing LF and nothing else.
func parseMultiProbePin(data []byte) (netip.Addr, error) {
	if len(data) == 0 || len(data) > maxMultiProbePinBytes {
		return netip.Addr{}, errors.New("invalid multi-source policy size")
	}

	value := strings.TrimSuffix(string(data), "\n")

	if !helperauth.ValidMultiProbePin(value) {
		return netip.Addr{}, errors.New("multi-source policy requires a distinct canonical public IPv4 pin")
	}

	return netip.ParseAddr(value)
}
