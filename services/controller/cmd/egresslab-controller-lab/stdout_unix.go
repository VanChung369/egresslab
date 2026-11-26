//go:build !windows

package main

import (
	"os/signal"
	"syscall"
)

// reportBrokenStdout makes a write to a closed stdout fail with EPIPE instead of ending the process
// with SIGPIPE, so a committed reservation or release is still reported as uncertain.
func reportBrokenStdout() { signal.Ignore(syscall.SIGPIPE) }
