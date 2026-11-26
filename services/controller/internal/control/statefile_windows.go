//go:build windows

package control

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"syscall"
	"time"
	"unsafe"
)

const (
	fileRenameInfoEx           = 22
	fileRenameReplaceIfExists  = 0x1
	fileRenamePOSIXSemantics   = 0x2
	errorInvalidFunction       = syscall.Errno(1)
	errorFileNotFound          = syscall.Errno(2)
	errorAccessDenied          = syscall.Errno(5)
	errorSharingViolation      = syscall.Errno(32)
	errorNotSupported          = syscall.Errno(50)
	errorInvalidParameter      = syscall.Errno(87)
	deleteAccess               = 0x00010000
	stateFileShareReadWriteDel = syscall.FILE_SHARE_READ | syscall.FILE_SHARE_WRITE | syscall.FILE_SHARE_DELETE

	// Under %APPDATA%, a filesystem filter (most likely Defender's behavior monitoring) can refuse
	// the rename itself with ERROR_ACCESS_DENIED for seconds when saves with new content come in
	// bursts, and a read during a replace can briefly find no file; neither is a real error.
	stateFileReplaceRetry = 5 * time.Second
	stateFileReadRetry    = 250 * time.Millisecond
)

var stateFileMissingRetry = 25 * time.Millisecond

func transientStateFileError(err error) bool {
	return errors.Is(err, errorAccessDenied) || errors.Is(err, errorSharingViolation) || errors.Is(err, errorLockViolation)
}

// retryStateFile runs op until it succeeds, fails for good, or the budget for its error is spent.
func retryStateFile(op func() error, budget func(error) time.Duration) error {
	start := time.Now()
	delay := 2 * time.Millisecond

	for {
		err := op()
		if err == nil || time.Since(start) >= budget(err) {
			return err
		}

		time.Sleep(delay)
		delay = min(delay*2, 50*time.Millisecond)
	}
}

// readStateFile reads a controller state file while letting a concurrent save replace it: without
// FILE_SHARE_DELETE, any open handle makes that save fail, and a save in progress makes this open
// fail. Every CONNECT of serve-endpoint reads the state files while the API may save them.
func readStateFile(path string) ([]byte, error) {
	var data []byte

	err := retryStateFile(func() error {
		var err error
		data, err = readStateFileOnce(path)
		return err
	}, func(err error) time.Duration {
		switch {
		case transientStateFileError(err):
			return stateFileReadRetry
		case errors.Is(err, errorFileNotFound):
			return stateFileMissingRetry
		default:
			return 0
		}
	})

	return data, err
}

func readStateFileOnce(path string) ([]byte, error) {
	file, err := openStateFile(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	return io.ReadAll(file)
}

func openStateFile(path string) (*os.File, error) {
	name, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return nil, &os.PathError{Op: "open", Path: path, Err: err}
	}

	handle, err := syscall.CreateFile(name, syscall.GENERIC_READ, stateFileShareReadWriteDel, nil,
		syscall.OPEN_EXISTING, syscall.FILE_ATTRIBUTE_NORMAL, 0)
	if err != nil {
		return nil, &os.PathError{Op: "open", Path: path, Err: err}
	}

	return os.NewFile(uintptr(handle), path), nil
}

type fileRenameInfo struct {
	Flags          uint32
	RootDirectory  syscall.Handle
	FileNameLength uint32
	FileName       [1]uint16
}

// replaceStateFile renames tmp over path with POSIX semantics: the name switches to the new file
// even while readers (opened as readStateFile does) still hold the old one, which os.Rename
// (MoveFileEx) refuses with ERROR_ACCESS_DENIED. A filesystem or Windows version without POSIX
// semantics falls back to os.Rename.
func replaceStateFile(tmp, path string) error {
	target, err := filepath.Abs(path)
	if err != nil {
		return err
	}

	err = retryStateFile(func() error { return renamePOSIX(tmp, target) }, func(err error) time.Duration {
		if transientStateFileError(err) {
			return stateFileReplaceRetry
		}

		return 0
	})

	if errors.Is(err, errorInvalidParameter) || errors.Is(err, errorNotSupported) || errors.Is(err, errorInvalidFunction) {
		return os.Rename(tmp, path)
	}

	return err
}

func renamePOSIX(tmp, target string) error {
	source, err := syscall.UTF16PtrFromString(tmp)
	if err != nil {
		return err
	}

	name, err := syscall.UTF16FromString(target)
	if err != nil {
		return err
	}

	handle, err := syscall.CreateFile(source, deleteAccess|syscall.SYNCHRONIZE, stateFileShareReadWriteDel, nil,
		syscall.OPEN_EXISTING, syscall.FILE_ATTRIBUTE_NORMAL, 0)
	if err != nil {
		return &os.LinkError{Op: "rename", Old: tmp, New: target, Err: err}
	}
	defer syscall.CloseHandle(handle)

	root := os.Getenv("SystemRoot")
	if !filepath.IsAbs(root) {
		return errors.New("invalid Windows SystemRoot")
	}

	proc := syscall.NewLazyDLL(filepath.Join(root, "System32", "kernel32.dll")).NewProc("SetFileInformationByHandle")
	if err := proc.Find(); err != nil {
		return err
	}

	// The name, without its terminating NUL, follows the fixed fields; the buffer is word-aligned.
	nameOffset := unsafe.Offsetof(fileRenameInfo{}.FileName)
	size := nameOffset + uintptr(len(name))*2
	buffer := make([]uint64, (size+7)/8)
	info := (*fileRenameInfo)(unsafe.Pointer(&buffer[0]))
	info.Flags = fileRenameReplaceIfExists | fileRenamePOSIXSemantics
	info.FileNameLength = uint32((len(name) - 1) * 2)
	copy(unsafe.Slice(&info.FileName[0], len(name)), name)

	if result, _, callErr := proc.Call(uintptr(handle), fileRenameInfoEx, uintptr(unsafe.Pointer(info)), size); result == 0 {
		return &os.LinkError{Op: "rename", Old: tmp, New: target, Err: callErr}
	}

	return nil
}
