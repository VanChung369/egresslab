//go:build linux

// Command egresslab-probe makes one HTTPS request to the fixed Cloudflare trace URL and prints
// the body. The helper runs it inside a lab namespace through setpriv, as a dedicated user with
// no groups, no capabilities and no_new_privs; it checks that itself before any request. It takes
// no arguments and touches neither the vault, WireGuard nor the firewall.
package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/VanChung369/egresslab/services/network-agent/internal/agent"
)

func requireProbePrivileges(status string) error {
	if os.Getuid() == 0 || os.Geteuid() == 0 || os.Getgid() == 0 || os.Getegid() == 0 {
		return errors.New("probe must not run as root")
	}

	groups, err := os.Getgroups()
	if err != nil || len(groups) != 0 {
		return errors.New("probe must have no supplementary groups")
	}

	return checkProbeStatus(status)
}

// checkProbeStatus requires every capability set empty and no_new_privs in /proc/self/status.
func checkProbeStatus(status string) error {
	required := map[string]string{
		"CapInh":     "0000000000000000",
		"CapPrm":     "0000000000000000",
		"CapEff":     "0000000000000000",
		"CapBnd":     "0000000000000000",
		"CapAmb":     "0000000000000000",
		"NoNewPrivs": "1",
	}

	for _, line := range strings.Split(status, "\n") {
		key, value, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}

		expected, exists := required[key]
		if !exists {
			continue
		}

		if strings.TrimSpace(value) != expected {
			return errors.New("unexpected probe privileges")
		}

		delete(required, key)
	}

	if len(required) != 0 {
		return errors.New("incomplete probe privilege information")
	}

	return nil
}

func run() error {
	if len(os.Args) != 1 {
		return errors.New("probe accepts no arguments")
	}

	status, err := os.ReadFile("/proc/self/status")
	if err != nil {
		return errors.New("cannot inspect probe privileges")
	}

	if err := requireProbePrivileges(string(status)); err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	body, err := agent.FetchEgressTrace(ctx, agent.DefaultEgressProbeURL)
	if err != nil {
		return errors.New("HTTPS probe failed")
	}

	_, err = os.Stdout.Write(body)

	return err
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
