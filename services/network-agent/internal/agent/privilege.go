package agent

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"runtime"
	"strconv"
	"strings"
)

// The HTTP-facing agent must never hold the privileges that ip/wg/nft changes need. Privileged
// network changes stay in the sudo-run lab CLIs until a separate privileged helper with an
// authorization protocol exists (see docs/PRIVILEGED-HELPER.md).
var ErrPrivilegedAgent = errors.New("the network agent must run as an unprivileged user")

// Linux capability bits that would let a compromised HTTP handler change networking.
var forbiddenAgentCapabilities = map[uint]string{
	12: "CAP_NET_ADMIN",
	13: "CAP_NET_RAW",
	21: "CAP_SYS_ADMIN",
}

// RequireUnprivilegedAgent refuses to continue when the process is root or holds a networking
// capability. It fails closed if the capability set cannot be read on Linux.
func RequireUnprivilegedAgent() error {
	if runtime.GOOS != "linux" {
		return nil
	}

	status, err := os.ReadFile("/proc/self/status")
	if err != nil {
		return fmt.Errorf("%w: cannot read process capabilities: %v", ErrPrivilegedAgent, err)
	}

	return checkAgentPrivileges(os.Geteuid(), string(status))
}

func checkAgentPrivileges(euid int, procStatus string) error {
	if euid == 0 {
		return fmt.Errorf("%w: running as root (start it as your normal user, without sudo)", ErrPrivilegedAgent)
	}

	var capEff string

	scanner := bufio.NewScanner(strings.NewReader(procStatus))
	for scanner.Scan() {
		if value, ok := strings.CutPrefix(scanner.Text(), "CapEff:"); ok {
			capEff = strings.TrimSpace(value)
		}
	}

	mask, err := strconv.ParseUint(capEff, 16, 64)
	if capEff == "" || err != nil {
		return fmt.Errorf("%w: cannot parse effective capabilities", ErrPrivilegedAgent)
	}

	var held []string
	for bit, name := range forbiddenAgentCapabilities {
		if mask&(1<<bit) != 0 {
			held = append(held, name)
		}
	}

	if len(held) != 0 {
		return fmt.Errorf("%w: holds %s", ErrPrivilegedAgent, strings.Join(held, ", "))
	}

	return nil
}
