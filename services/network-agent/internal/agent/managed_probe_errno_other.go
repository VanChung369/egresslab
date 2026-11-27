//go:build !windows

package agent

import "syscall"

var (
	probeResetErrnos = []error{syscall.ECONNRESET}
	probeLostErrnos  = []error{syscall.ECONNREFUSED, syscall.ECONNRESET, syscall.EHOSTUNREACH, syscall.ENETUNREACH}
)
