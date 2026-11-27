//go:build linux

// Command egresslab-probe makes one HTTPS request and prints the body. With no arguments it is the
// legacy Cloudflare trace probe; with "--source SOURCE_ID IPV4" it makes one request to a built-in
// source, pinned to the numeric address its parent chose. The helper runs it inside a lab namespace
// through setpriv, as a dedicated user with no groups, no capabilities and no_new_privs; it checks
// that itself before any request. It takes no URL, host, port, proxy or TLS setting, and touches
// neither the vault, WireGuard nor the firewall.
package main

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
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

type workerProbeRequest struct {
	legacy      bool
	sourceID    string
	destination netip.Addr
}

// parseWorkerProbeRequest only checks the shape of the arguments; FetchManagedProbeSource applies
// the full source policy.
func parseWorkerProbeRequest(args []string) (workerProbeRequest, error) {
	if len(args) == 0 {
		return workerProbeRequest{legacy: true}, nil
	}

	if len(args) != 3 || args[0] != "--source" {
		return workerProbeRequest{}, errors.New("invalid probe arguments")
	}

	if args[1] != "cloudflare_trace" && args[1] != "ident_me" {
		return workerProbeRequest{}, errors.New("unknown probe source")
	}

	destination, err := netip.ParseAddr(args[2])
	if err != nil || !destination.Is4() || destination.String() != args[2] {
		return workerProbeRequest{}, errors.New("invalid probe destination")
	}

	return workerProbeRequest{sourceID: args[1], destination: destination}, nil
}

// probeFailure reports a source failure as its fixed line; the helper maps these lines to its codes.
func probeFailure(err error) error {
	return errors.New(agent.ManagedProbeFailureLine(err))
}

func run() error {
	request, err := parseWorkerProbeRequest(os.Args[1:])
	if err != nil {
		return err
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

	var body []byte

	if request.legacy {
		body, err = agent.FetchEgressTrace(ctx, agent.DefaultEgressProbeURL)
	} else {
		body, err = agent.FetchManagedProbeSource(ctx, request.sourceID, request.destination)
	}

	if err != nil {
		return probeFailure(err)
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
