//go:build darwin

package keystore

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os/exec"
	"path/filepath"
	"strings"
)

// Unverified: written from the security(1) man page, not yet run on macOS.
const (
	backendName     = "macOS login Keychain"
	keychainService = "dev.egresslab.controller-signing"
	securityPath    = "/usr/bin/security"
	maxSecurityOut  = 4096
)

type keychainStore struct{ account string }

func platformStore(dataDir string) (seedStore, error) {
	if !filepath.IsAbs(dataDir) {
		return nil, errors.New("data directory must be absolute")
	}

	// One item per data directory; hex keeps the account free of spaces for "security -i".
	digest := sha256.Sum256([]byte(filepath.Clean(dataDir)))

	return keychainStore{account: "data-" + hex.EncodeToString(digest[:16])}, nil
}

type limitedBuffer struct{ bytes.Buffer }

func (b *limitedBuffer) Write(p []byte) (int, error) {
	if b.Len()+len(p) > maxSecurityOut {
		return 0, errors.New("security output too large")
	}

	return b.Buffer.Write(p)
}

func (s keychainStore) load() ([]byte, error) {
	var stdout, stderr limitedBuffer
	defer clear(stdout.Bytes())

	cmd := exec.Command(securityPath, "find-generic-password", "-a", s.account, "-s", keychainService, "-w")
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) && (exitErr.ExitCode() == 44 || strings.Contains(stderr.String(), "could not be found")) {
			return nil, ErrNoKey
		}

		return nil, fmt.Errorf("read signing key from Keychain: %w: %s", err, strings.TrimSpace(stderr.String()))
	}

	encoded := bytes.TrimSuffix(stdout.Bytes(), []byte("\n"))
	if len(encoded) != hex.EncodedLen(ed25519.SeedSize) {
		return nil, errors.New("invalid signing key in Keychain")
	}

	seed := make([]byte, ed25519.SeedSize)
	if _, err := hex.Decode(seed, encoded); err != nil {
		clear(seed)
		return nil, errors.New("invalid signing key encoding in Keychain")
	}

	return seed, nil
}

// create passes the secret on stdin ("security -i"), never in argv. Without -U, security refuses
// to replace an existing item. Interactive mode may exit 0 after a failed command, so the result
// is checked by reading the item back.
func (s keychainStore) create(seed []byte) error {
	if existing, err := s.load(); err == nil {
		clear(existing)
		return ErrKeyExists
	} else if !errors.Is(err, ErrNoKey) {
		return err
	}

	command := []byte(fmt.Sprintf("add-generic-password -a %s -s %s -w ", s.account, keychainService))
	command = hex.AppendEncode(command, seed)
	command = append(command, '\n')
	defer clear(command)

	var output limitedBuffer
	cmd := exec.Command(securityPath, "-i")
	cmd.Stdin = bytes.NewReader(command)
	cmd.Stdout = &output
	cmd.Stderr = &output

	runErr := cmd.Run()

	stored, err := s.load()
	if err != nil {
		return errors.Join(fmt.Errorf("Keychain did not store the signing key: %w", err), runErr)
	}
	defer clear(stored)

	if !bytes.Equal(stored, seed) {
		return errors.New("Keychain holds a different signing key; it was not replaced")
	}

	return nil
}
