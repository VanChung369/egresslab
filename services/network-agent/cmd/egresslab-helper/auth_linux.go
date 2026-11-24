//go:build linux

package main

import (
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/VanChung369/egresslab/services/network-agent/internal/helperauth"
)

const maxPublicKeyFileBytes = 128

// loadAuthVerifier loads the controller's Ed25519 public key (64 hex characters) from a
// root-owned file and pairs it with a fresh random helper ID (epoch). The helper never loads the
// controller's private key, and the operator cannot choose or reuse a helper ID. With no path,
// authorization stays disabled.
func loadAuthVerifier(path string) (*helperauth.Verifier, error) {
	return loadAuthVerifierOwnedBy(path, 0, "/")
}

// loadAuthVerifierOwnedBy is loadAuthVerifier with the owner UID and the top directory to check as
// parameters, so the accept path can be tested without root.
func loadAuthVerifierOwnedBy(path string, owner uint32, root string) (*helperauth.Verifier, error) {
	if path == "" {
		return nil, nil
	}

	if !filepath.IsAbs(path) {
		return nil, errors.New("authorization public key path must be absolute")
	}

	path = filepath.Clean(path)

	// No directory on the way to the file may let anyone else swap it.
	if err := checkDirChain(filepath.Dir(path), root, owner); err != nil {
		return nil, fmt.Errorf("authorization public key directory: %w", err)
	}

	before, err := os.Lstat(path)
	if err != nil {
		return nil, fmt.Errorf("inspect authorization public key: %w", err)
	}

	if err := checkPublicFile(before, owner); err != nil {
		return nil, err
	}

	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	opened, err := file.Stat()
	if err != nil {
		return nil, err
	}

	if !os.SameFile(before, opened) {
		return nil, errors.New("authorization public key file changed while it was being opened")
	}

	if err := checkPublicFile(opened, owner); err != nil {
		return nil, err
	}

	data, err := io.ReadAll(io.LimitReader(file, maxPublicKeyFileBytes+1))
	if err != nil {
		return nil, err
	}

	text := strings.TrimSpace(string(data))

	// Ed25519 public key: 32 bytes, 64 hex characters.
	if len(text) != 2*ed25519.PublicKeySize {
		return nil, errors.New("authorization public key must contain 64 hex characters")
	}

	raw, err := hex.DecodeString(text)
	if err != nil {
		return nil, errors.New("invalid authorization public key encoding")
	}

	// A new epoch at every start: capabilities minted for an earlier process are refused.
	helperID, err := helperauth.NewHelperID()
	if err != nil {
		return nil, err
	}

	return helperauth.NewVerifier(ed25519.PublicKey(raw), helperID)
}

func checkPublicFile(info os.FileInfo, owner uint32) error {
	if err := checkOwned(info, owner, false); err != nil || info.Size() > maxPublicKeyFileBytes {
		return fmt.Errorf("authorization public key must be a regular file owned by UID %d, not writable by group or others, at most %d bytes",
			owner, maxPublicKeyFileBytes)
	}

	return nil
}

func checkOwned(info os.FileInfo, owner uint32, wantDir bool) error {
	stat, ok := info.Sys().(*syscall.Stat_t)

	switch {
	case !ok:
		return errors.New("cannot read ownership")
	case wantDir && !info.IsDir():
		return errors.New("not a directory")
	case !wantDir && !info.Mode().IsRegular():
		return errors.New("not a regular file")
	case stat.Uid != owner:
		return fmt.Errorf("owned by UID %d, want %d", stat.Uid, owner)
	case info.Mode().Perm()&0o022 != 0:
		return errors.New("writable by group or others")
	}

	return nil
}

// checkDirChain requires dir and every directory above it, up to and including root, to be a real
// directory (a symlink is refused) owned by owner and not writable by group or others.
func checkDirChain(dir, root string, owner uint32) error {
	for current := dir; ; current = filepath.Dir(current) {
		info, err := os.Lstat(current)
		if err != nil {
			return err
		}

		if err := checkOwned(info, owner, true); err != nil {
			return fmt.Errorf("%s: %w", current, err)
		}

		if current == root {
			return nil
		}

		if filepath.Dir(current) == current {
			return fmt.Errorf("%s is not under %s", dir, root)
		}
	}
}
