//go:build !linux

package agent

import "os/exec"

func isolateFromTerminalSignals(*exec.Cmd) {}
