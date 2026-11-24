//go:build windows

package keystore

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"syscall"
	"unsafe"
)

const (
	backendName = "Windows DPAPI (current user)"

	dpapiFileName           = "controller-signing.dpapi"
	maxProtectedBytes       = 64 * 1024
	cryptProtectUIForbidden = 0x1 // never CRYPTPROTECT_LOCAL_MACHINE: other accounts could decrypt
)

type dataBlob struct {
	size uint32
	data *byte
}

type dpapiStore struct{ path string }

func platformStore(dataDir string) (seedStore, error) {
	if !filepath.IsAbs(dataDir) {
		return nil, errors.New("data directory must be absolute")
	}

	return dpapiStore{path: filepath.Join(dataDir, dpapiFileName)}, nil
}

func system32Dir() (string, error) {
	root := os.Getenv("SystemRoot")
	if !filepath.IsAbs(root) {
		return "", errors.New("invalid Windows SystemRoot")
	}

	return filepath.Join(root, "System32"), nil
}

func dpapi(data []byte, encrypt bool) ([]byte, error) {
	if len(data) == 0 || len(data) > maxProtectedBytes {
		return nil, errors.New("invalid DPAPI input size")
	}

	system32, err := system32Dir()
	if err != nil {
		return nil, err
	}

	crypt := syscall.NewLazyDLL(filepath.Join(system32, "crypt32.dll"))
	kernel := syscall.NewLazyDLL(filepath.Join(system32, "kernel32.dll"))

	operation := "CryptUnprotectData"
	if encrypt {
		operation = "CryptProtectData"
	}

	proc := crypt.NewProc(operation)
	free := kernel.NewProc("LocalFree")

	if err := proc.Find(); err != nil {
		return nil, err
	}

	if err := free.Find(); err != nil {
		return nil, err
	}

	in := dataBlob{size: uint32(len(data)), data: &data[0]}
	var out dataBlob

	result, _, callErr := proc.Call(
		uintptr(unsafe.Pointer(&in)),
		0, // description
		0, // entropy
		0, // reserved
		0, // prompt
		cryptProtectUIForbidden,
		uintptr(unsafe.Pointer(&out)),
	)
	runtime.KeepAlive(data)

	if result == 0 {
		return nil, fmt.Errorf("%s failed: %v", operation, callErr)
	}

	if out.data == nil {
		return nil, errors.New("DPAPI returned no data")
	}
	defer free.Call(uintptr(unsafe.Pointer(out.data)))

	if out.size == 0 || out.size > maxProtectedBytes {
		return nil, errors.New("invalid DPAPI output size")
	}

	buffer := unsafe.Slice(out.data, int(out.size))
	defer clear(buffer)

	return append([]byte(nil), buffer...), nil
}

func (s dpapiStore) create(seed []byte) error {
	if err := os.MkdirAll(filepath.Dir(s.path), 0o700); err != nil {
		return err
	}

	protected, err := dpapi(seed, true)
	if err != nil {
		return err
	}
	defer clear(protected)

	file, err := os.OpenFile(s.path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
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

	if _, err := file.Write(protected); err != nil {
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

func (s dpapiStore) load() ([]byte, error) {
	before, err := os.Lstat(s.path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, ErrNoKey
	}
	if err != nil {
		return nil, err
	}

	if !before.Mode().IsRegular() {
		return nil, errors.New("signing key must be a regular file")
	}

	file, err := os.Open(s.path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	opened, err := file.Stat()
	if err != nil {
		return nil, err
	}

	if !opened.Mode().IsRegular() || !os.SameFile(before, opened) {
		return nil, errors.New("signing key changed while opening")
	}

	protected, err := io.ReadAll(io.LimitReader(file, maxProtectedBytes+1))
	if err != nil {
		return nil, err
	}
	defer clear(protected)

	if len(protected) == 0 || len(protected) > maxProtectedBytes {
		return nil, errors.New("invalid protected signing key file")
	}

	seed, err := dpapi(protected, false)
	if err != nil {
		return nil, err
	}

	if len(seed) != ed25519.SeedSize {
		clear(seed)
		return nil, errors.New("invalid decrypted seed")
	}

	return seed, nil
}
