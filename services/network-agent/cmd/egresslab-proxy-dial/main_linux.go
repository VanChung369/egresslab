//go:build linux

// Command egresslab-proxy-dial opens one TCP connection inside a lab namespace and hands the socket
// to its parent over the inherited Unix socket (FD 3), then exits. The helper runs it through
// setpriv as the dedicated proxy user with no groups, no capabilities and no_new_privs, which it
// checks first. It takes only a public IPv4 address and a port the helper authorized; it has no
// listener and touches neither the vault, WireGuard nor the firewall. Failures print one fixed line.
package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/VanChung369/egresslab/services/network-agent/internal/helperauth"
)

const handoffFD = 3

func checkPrivileges(status string) error {
	if os.Getuid() == 0 || os.Geteuid() == 0 || os.Getgid() == 0 || os.Getegid() == 0 {
		return errors.New("dial must not run as root")
	}

	groups, err := os.Getgroups()
	if err != nil || len(groups) != 0 {
		return errors.New("dial must have no supplementary groups")
	}

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
			return errors.New("unexpected dial privileges")
		}

		delete(required, key)
	}

	if len(required) != 0 {
		return errors.New("incomplete dial privilege information")
	}

	return nil
}

func parseTarget(args []string) (netip.AddrPort, error) {
	if len(args) != 2 {
		return netip.AddrPort{}, errors.New("invalid dial arguments")
	}

	ip, err := netip.ParseAddr(args[0])
	if err != nil || !helperauth.ValidPublicProbeIPv4(ip) || ip.String() != args[0] {
		return netip.AddrPort{}, errors.New("invalid dial destination")
	}

	port, err := strconv.ParseUint(args[1], 10, 16)
	if err != nil || port == 0 || port == 53 || port == 853 || strconv.FormatUint(port, 10) != args[1] {
		return netip.AddrPort{}, errors.New("invalid dial destination")
	}

	return netip.AddrPortFrom(ip, uint16(port)), nil
}

func run() error {
	target, err := parseTarget(os.Args[1:])
	if err != nil {
		return err
	}

	status, err := os.ReadFile("/proc/self/status")
	if err != nil {
		return errors.New("cannot inspect dial privileges")
	}

	if err := checkPrivileges(string(status)); err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	var dialer net.Dialer

	raw, err := dialer.DialContext(ctx, "tcp4", target.String())
	switch {
	case errors.Is(err, syscall.ECONNREFUSED):
		return errors.New("destination refused")
	case err != nil:
		return errors.New("destination unreachable")
	}
	defer raw.Close()

	conn, ok := raw.(*net.TCPConn)
	if !ok {
		return errors.New("socket handoff failed")
	}

	file, err := conn.File()
	if err != nil {
		return errors.New("socket handoff failed")
	}
	defer file.Close()

	if err := syscall.Sendmsg(handoffFD, []byte{1}, syscall.UnixRights(int(file.Fd())), nil, 0); err != nil {
		return errors.New("socket handoff failed")
	}

	return nil
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
