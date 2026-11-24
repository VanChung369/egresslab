//go:build unix && !darwin

package keystore

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"syscall"
)

// A Secret Service (keyring) backend is not implemented; headless Linux has none anyway. This
// file is protected only by Unix permissions.
const (
	backendName     = "file (mode 0600)"
	keyFileName     = "controller-signing.key"
	maxKeyFileBytes = 2*ed25519.SeedSize + 1
)

type fileStore struct {
	dir  string
	path string
	uid  uint32
}

func platformStore(dataDir string) (seedStore, error) {
	if !filepath.IsAbs(dataDir) {
		return nil, errors.New("data directory must be absolute")
	}

	return fileStore{dir: dataDir, path: filepath.Join(dataDir, keyFileName), uid: uint32(os.Getuid())}, nil
}

func (s fileStore) checkOwned(info os.FileInfo, wantDir bool) error {
	stat, ok := info.Sys().(*syscall.Stat_t)

	switch {
	case !ok:
		return errors.New("cannot read ownership")
	case wantDir && !info.IsDir():
		return errors.New("not a directory")
	case !wantDir && !info.Mode().IsRegular():
		return errors.New("not a regular file")
	case stat.Uid != s.uid:
		return fmt.Errorf("owned by UID %d, want %d", stat.Uid, s.uid)
	case wantDir && info.Mode().Perm()&0o022 != 0:
		return errors.New("writable by group or others")
	case !wantDir && info.Mode().Perm()&0o077 != 0:
		return errors.New("must be mode 0600")
	}

	return nil
}

func (s fileStore) checkDir() error {
	info, err := os.Lstat(s.dir)
	if err != nil {
		return err
	}

	if err := s.checkOwned(info, true); err != nil {
		return fmt.Errorf("signing key directory %s: %w", s.dir, err)
	}

	return nil
}

func (s fileStore) create(seed []byte) error {
	if err := os.MkdirAll(s.dir, 0o700); err != nil {
		return err
	}

	if err := s.checkDir(); err != nil {
		return err
	}

	file, err := os.OpenFile(s.path, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0o600)
	if errors.Is(err, os.ErrExist) {
		return ErrKeyExists
	}
	if err != nil {
		return err
	}

	success := false
	defer func() {
		_ = file.Close()
		if !success {
			_ = os.Remove(s.path)
		}
	}()

	encoded := hex.AppendEncode(make([]byte, 0, hex.EncodedLen(len(seed))+1), seed)
	encoded = append(encoded, '\n')
	defer clear(encoded)

	if _, err := file.Write(encoded); err != nil {
		return err
	}

	if err := file.Sync(); err != nil {
		return err
	}

	if err := file.Close(); err != nil {
		return err
	}

	success = true

	return nil
}

func (s fileStore) load() ([]byte, error) {
	if err := s.checkDir(); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, ErrNoKey
		}
		return nil, err
	}

	before, err := os.Lstat(s.path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, ErrNoKey
	}
	if err != nil {
		return nil, err
	}

	if err := s.checkOwned(before, false); err != nil {
		return nil, fmt.Errorf("signing key %s: %w", s.path, err)
	}

	file, err := os.OpenFile(s.path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	opened, err := file.Stat()
	if err != nil {
		return nil, err
	}

	if !os.SameFile(before, opened) {
		return nil, errors.New("signing key changed while opening")
	}

	data, err := io.ReadAll(io.LimitReader(file, maxKeyFileBytes+1))
	if err != nil {
		return nil, err
	}
	defer clear(data)

	encoded := bytes.TrimSuffix(data, []byte("\n"))
	if len(data) > maxKeyFileBytes || len(encoded) != hex.EncodedLen(ed25519.SeedSize) {
		return nil, errors.New("invalid signing key file")
	}

	seed := make([]byte, ed25519.SeedSize)
	if _, err := hex.Decode(seed, encoded); err != nil {
		clear(seed)
		return nil, errors.New("invalid signing key encoding")
	}

	return seed, nil
}
