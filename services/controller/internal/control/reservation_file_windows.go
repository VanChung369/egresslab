//go:build windows

package control

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"unsafe"
)

const (
	lockfileFailImmediately = 0x00000001
	lockfileExclusiveLock   = 0x00000002

	errorLockViolation = syscall.Errno(33)
)

// openReservationFile opens the journal without FILE_SHARE_DELETE, so a cooperating process cannot
// rename or replace it while it is open, and refuses reparse points (symlinks, junctions).
func openReservationFile(path string, create bool) (*os.File, error) {
	name, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return nil, err
	}

	disposition := uint32(syscall.OPEN_EXISTING)
	if create {
		disposition = syscall.CREATE_NEW
	}

	handle, err := syscall.CreateFile(name, syscall.GENERIC_READ|syscall.GENERIC_WRITE,
		syscall.FILE_SHARE_READ|syscall.FILE_SHARE_WRITE, nil, disposition,
		syscall.FILE_ATTRIBUTE_NORMAL|syscall.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		return nil, err
	}

	var info syscall.ByHandleFileInformation
	if err := syscall.GetFileInformationByHandle(handle, &info); err != nil {
		syscall.CloseHandle(handle)
		return nil, err
	}

	if info.FileAttributes&(syscall.FILE_ATTRIBUTE_DIRECTORY|syscall.FILE_ATTRIBUTE_REPARSE_POINT) != 0 {
		syscall.CloseHandle(handle)
		return nil, errors.New("invalid reservation journal file")
	}

	file := os.NewFile(uintptr(handle), path)
	if file == nil {
		syscall.CloseHandle(handle)
		return nil, errors.New("cannot wrap reservation journal handle")
	}

	return file, nil
}

// lockReservationFile locks one byte at offset zero exclusively; Windows allows a range beyond
// EOF, so an empty new file locks too. Closing the handle releases the lock.
func lockReservationFile(file *os.File) error {
	root := os.Getenv("SystemRoot")
	if !filepath.IsAbs(root) {
		return errors.New("invalid Windows SystemRoot")
	}

	lock := syscall.NewLazyDLL(filepath.Join(root, "System32", "kernel32.dll")).NewProc("LockFileEx")
	if err := lock.Find(); err != nil {
		return err
	}

	var overlapped syscall.Overlapped

	result, _, callErr := lock.Call(file.Fd(), lockfileExclusiveLock|lockfileFailImmediately, 0, 1, 0,
		uintptr(unsafe.Pointer(&overlapped)))
	if result != 0 {
		return nil
	}

	if errors.Is(callErr, errorLockViolation) {
		return ErrReservationBusy
	}

	return fmt.Errorf("LockFileEx failed: %v", callErr)
}

// File.Sync flushes the file on Windows; there is no portable directory flush.
func syncReservationDirectory(string) error {
	return nil
}
