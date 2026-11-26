//go:build !windows && !linux && !darwin

package control

import "os"

// No mutex-only fallback: without an OS file lock there is no reservation authority.

func openReservationFile(string, bool) (*os.File, error) {
	return nil, ErrReservationUnavailable
}

func lockReservationFile(*os.File, bool) error {
	return ErrReservationUnavailable
}

func syncReservationDirectory(string) error {
	return ErrReservationUnavailable
}
