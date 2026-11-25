//go:build linux || darwin

package control

import (
	"errors"
	"os"
	"syscall"
)

func openReservationFile(path string, create bool) (*os.File, error) {
	flags := os.O_RDWR | syscall.O_NOFOLLOW | syscall.O_NONBLOCK
	if create {
		flags |= os.O_CREATE | os.O_EXCL
	}

	return os.OpenFile(path, flags, 0o600)
}

// The flock belongs to the open file description; closing the file releases it.
func lockReservationFile(file *os.File) error {
	err := syscall.Flock(int(file.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
	if errors.Is(err, syscall.EWOULDBLOCK) || errors.Is(err, syscall.EAGAIN) {
		return ErrReservationBusy
	}

	return err
}

func syncReservationDirectory(dir string) error {
	file, err := os.Open(dir)
	if err != nil {
		return err
	}

	return errors.Join(file.Sync(), file.Close())
}
