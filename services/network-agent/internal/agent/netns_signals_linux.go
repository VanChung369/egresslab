package agent

import (
	"os/exec"
	"syscall"
)

func isolateFromTerminalSignals(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
}
