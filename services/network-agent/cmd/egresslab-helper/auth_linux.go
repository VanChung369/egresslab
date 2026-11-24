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
// root-owned file. The helper never loads the controller's private key. Both options are
// required together; with neither, authorization stays disabled.
func loadAuthVerifier(path, helperID string) (*helperauth.Verifier, error) {
	return loadAuthVerifierOwnedBy(path, helperID, 0)
}

// loadAuthVerifierOwnedBy is loadAuthVerifier with the required owner UID as a parameter, so the
// accept path can be tested without root.
func loadAuthVerifierOwnedBy(path, helperID string, owner uint32) (*helperauth.Verifier, error) {
	if path == "" && helperID == "" {
		return nil, nil
	}

	if path == "" || helperID == "" {
		return nil, errors.New("-auth-public-key-file and -helper-id must be given together")
	}

	// The directory must not let anyone else swap the file.
	dir, err := os.Lstat(filepath.Dir(path))
	if err != nil {
		return nil, fmt.Errorf("inspect authorization public key directory: %w", err)
	}

	if err := checkOwned(dir, owner, true); err != nil {
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

	verifier, err := helperauth.NewVerifier(ed25519.PublicKey(raw), helperID)
	if err != nil {
		return nil, errors.New("-helper-id must be helper_<32 lowercase hex>")
	}

	return verifier, nil
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
