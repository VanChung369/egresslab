//go:build linux

package agent

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/VanChung369/egresslab/services/network-agent/internal/helperauth"
)

const (
	proxyDialBinary  = "/usr/local/bin/egresslab-proxy-dial"
	proxyDialTimeout = 4 * time.Second
)

var ErrProxyDialFailed = errors.New("managed proxy dial failed")

// ProxyDialer opens one TCP connection inside namespace as the proxy user and returns the socket.
// The socket keeps the namespace's routes and firewall, and the proxy user's UID; no process stays.
type ProxyDialer func(ctx context.Context, namespace string, destination netip.AddrPort) (*net.TCPConn, error)

// NewProxyDialer verifies the worker binary and the identities once; each dial checks the binary
// again. There is no fallback to a dial by the helper itself.
func NewProxyDialer(uid, gid uint32) (ProxyDialer, error) {
	if uid == 0 || gid == 0 || uid == ^uint32(0) || gid == ^uint32(0) {
		return nil, errors.New("invalid proxy identity")
	}

	ipPath, err := findSystemBinary("ip")
	if err != nil {
		return nil, err
	}

	setprivPath, err := findSystemBinary("setpriv")
	if err != nil {
		return nil, err
	}

	if err := verifyProbeBinary(proxyDialBinary); err != nil {
		return nil, err
	}

	return func(ctx context.Context, namespace string, destination netip.AddrPort) (*net.TCPConn, error) {
		if !labNamePattern.MatchString(namespace) || !validProxyDestination(destination) {
			return nil, fmt.Errorf("%w: WORKER_INVALID_REQUEST", ErrProxyDialFailed)
		}

		if err := verifyProbeBinary(proxyDialBinary); err != nil {
			return nil, err
		}

		return dialInNamespace(ctx, ipPath, setprivPath, proxyDialBinary, namespace, uid, gid, destination)
	}, nil
}

func validProxyDestination(destination netip.AddrPort) bool {
	port := destination.Port()

	return helperauth.ValidPublicProbeIPv4(destination.Addr()) && port != 0 && port != 53 && port != 853
}

// proxyDialFailureReason maps the worker's fixed error lines to codes; its raw stderr is never logged.
func proxyDialFailureReason(stderr string) string {
	switch strings.TrimSpace(stderr) {
	case "destination refused":
		return "DESTINATION_REFUSED"
	case "destination unreachable":
		return "DESTINATION_UNREACHABLE"
	case "dial must not run as root", "dial must have no supplementary groups", "unexpected dial privileges",
		"incomplete dial privilege information":
		return "WORKER_PRIVILEGE_CHECK_FAILED"
	case "cannot inspect dial privileges":
		return "WORKER_STATUS_UNAVAILABLE"
	case "invalid dial arguments", "invalid dial destination":
		return "WORKER_INVALID_REQUEST"
	case "socket handoff failed":
		return "WORKER_HANDOFF_FAILED"
	default:
		return "WORKER_EXECUTION_FAILED"
	}
}

// dialInNamespace runs the worker in namespace through setpriv and receives exactly one TCP socket,
// connected to destination, once the worker exited successfully.
func dialInNamespace(
	ctx context.Context,
	ipPath, setprivPath, binary, namespace string,
	uid, gid uint32,
	destination netip.AddrPort,
) (*net.TCPConn, error) {
	pair, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_SEQPACKET|syscall.SOCK_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}

	parent := os.NewFile(uintptr(pair[0]), "proxy-handoff-parent")
	child := os.NewFile(uintptr(pair[1]), "proxy-handoff-child")
	defer parent.Close()
	defer child.Close()

	raw, err := net.FileConn(parent)
	if err != nil {
		return nil, err
	}
	defer raw.Close()

	unix, ok := raw.(*net.UnixConn)
	if !ok {
		return nil, errors.New("invalid handoff socket")
	}

	deadline := time.Now().Add(proxyDialTimeout)
	if end, ok := ctx.Deadline(); ok && end.Before(deadline) {
		deadline = end
	}

	if err := unix.SetReadDeadline(deadline); err != nil {
		return nil, err
	}

	workerCtx, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()

	cmd := exec.CommandContext(workerCtx, ipPath,
		"netns", "exec", namespace,
		setprivPath,
		"--reuid="+strconv.FormatUint(uint64(uid), 10),
		"--regid="+strconv.FormatUint(uint64(gid), 10),
		"--clear-groups",
		"--inh-caps=-all",
		"--ambient-caps=-all",
		"--bounding-set=-all",
		"--no-new-privs",
		"--",
		binary,
		destination.Addr().String(),
		strconv.Itoa(int(destination.Port())),
	)

	isolateFromTerminalSignals(cmd)

	// No proxy, TLS, HOME or loader variables are inherited.
	cmd.Dir = "/"
	cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "HOME=/nonexistent", "LANG=C", "LC_ALL=C"}
	cmd.ExtraFiles = []*os.File{child}
	cmd.WaitDelay = time.Second

	var stderr boundedProbeOutput
	cmd.Stderr = &stderr

	if err := cmd.Start(); err != nil {
		return nil, err
	}

	_ = child.Close()

	conn, receiveErr := receiveProxySocket(unix, destination)
	if receiveErr != nil {
		cancel()
	}

	waitErr := cmd.Wait()

	if receiveErr == nil && waitErr == nil && workerCtx.Err() == nil {
		return conn, nil
	}

	if conn != nil {
		_ = conn.Close()
	}

	if workerCtx.Err() != nil {
		return nil, errors.Join(ErrProxyDialFailed, workerCtx.Err())
	}

	if waitErr != nil {
		return nil, fmt.Errorf("%w: %s", ErrProxyDialFailed, proxyDialFailureReason(stderr.buf.String()))
	}

	return nil, fmt.Errorf("%w: WORKER_HANDOFF_FAILED: %w", ErrProxyDialFailed, receiveErr)
}

// receiveProxySocket accepts one message of one byte carrying exactly one descriptor: a TCP socket
// connected to expected. Every descriptor received is closed unless it is returned.
func receiveProxySocket(unix *net.UnixConn, expected netip.AddrPort) (*net.TCPConn, error) {
	data := make([]byte, 8)
	oob := make([]byte, syscall.CmsgSpace(16*4))

	n, oobn, flags, _, err := unix.ReadMsgUnix(data, oob)

	var fds []int

	defer func() {
		for _, fd := range fds {
			_ = syscall.Close(fd)
		}
	}()

	var messages []syscall.SocketControlMessage
	var parseErr error

	if err == nil {
		messages, parseErr = syscall.ParseSocketControlMessage(oob[:oobn])

		for i := range messages {
			rights, rightsErr := syscall.ParseUnixRights(&messages[i])
			if rightsErr != nil {
				parseErr = errors.Join(parseErr, rightsErr)
				continue
			}

			fds = append(fds, rights...)
		}
	}

	if err != nil || parseErr != nil || flags&(syscall.MSG_CTRUNC|syscall.MSG_TRUNC) != 0 || n != 1 || data[0] != 1 ||
		len(messages) != 1 || len(fds) != 1 {
		return nil, errors.New("invalid socket handoff")
	}

	fd := fds[0]
	fds = nil
	syscall.CloseOnExec(fd)

	file := os.NewFile(uintptr(fd), "managed-proxy-tcp")
	raw, err := net.FileConn(file)
	_ = file.Close()

	if err != nil {
		return nil, err
	}

	tcp, ok := raw.(*net.TCPConn)
	if !ok {
		_ = raw.Close()
		return nil, errors.New("handoff was not TCP")
	}

	remote, ok := tcp.RemoteAddr().(*net.TCPAddr)
	if !ok || remote.AddrPort() != expected {
		_ = tcp.Close()
		return nil, errors.New("handoff destination mismatch")
	}

	return tcp, nil
}
