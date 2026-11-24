package agent

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"syscall"
)

// readPrivateFile reads a regular, non-symlink file that only its owner can access.
// It returns os.ErrNotExist (wrapped) when the file is absent.
func readPrivateFile(path string, maxBytes int64) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}

	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("%s must be a regular file, not a symlink", path)
	}

	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	opened, err := file.Stat()
	if err != nil {
		return nil, fmt.Errorf("inspect %s: %w", path, err)
	}

	if !opened.Mode().IsRegular() || !os.SameFile(info, opened) {
		return nil, fmt.Errorf("%s changed while it was being opened", path)
	}

	if runtime.GOOS != "windows" && opened.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("%s is too accessible; run chmod 600 on it", path)
	}

	data, err := io.ReadAll(io.LimitReader(file, maxBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}

	if int64(len(data)) > maxBytes {
		clear(data)
		return nil, fmt.Errorf("%s exceeds %d bytes", path, maxBytes)
	}

	return data, nil
}

// writePrivateFile atomically replaces path with data, readable only by its owner.
func writePrivateFile(path string, data []byte) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}

	tmp, err := os.CreateTemp(dir, ".egresslab-*.tmp")
	if err != nil {
		return err
	}

	name := tmp.Name()
	defer os.Remove(name)

	err = errors.Join(
		tmp.Chmod(0o600),
		writeAll(tmp, data),
		tmp.Sync(),
	)

	if closeErr := tmp.Close(); err == nil {
		err = closeErr
	}

	if err != nil {
		return err
	}

	if err := os.Rename(name, path); err != nil {
		return err
	}

	return syncDir(dir)
}

// syncDir makes a rename in dir survive a crash. Windows has no directory fsync, and a filesystem
// that cannot sync a directory is left as it is.
func syncDir(dir string) error {
	if runtime.GOOS == "windows" {
		return nil
	}

	d, err := os.Open(dir)
	if err != nil {
		return err
	}

	err = d.Sync()
	if errors.Is(err, syscall.EINVAL) || errors.Is(err, errors.ErrUnsupported) {
		err = nil
	}

	return errors.Join(err, d.Close())
}

func writeAll(w io.Writer, data []byte) error {
	_, err := w.Write(data)
	return err
}
