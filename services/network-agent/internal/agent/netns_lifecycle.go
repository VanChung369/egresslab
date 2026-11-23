package agent

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"time"
)

const (
	netNSCommandTimeout = 5 * time.Second
	netNSRunDir         = "/run/netns"
)

var labNamePattern = regexp.MustCompile(`^egresslab-lab-[0-9a-f]{16}$`)

var ErrNetNSStateUncertain = errors.New("lab namespace state is uncertain")

type netNSCommand func(context.Context, ...string) ([]byte, error)

type labNameGenerator func() (string, error)

type netNSExists func(name string) (bool, error)

type NetNSLabManager struct {
	mu       sync.Mutex
	run      netNSCommand
	makeName labNameGenerator
	exists   netNSExists
	owned    map[string]struct{}
}

func NewNetNSLabManager() (*NetNSLabManager, error) {
	if runtime.GOOS != "linux" {
		return nil, ErrLinuxRequired
	}

	ipPath, err := findSystemIP()
	if err != nil {
		return nil, err
	}

	run := func(ctx context.Context, args ...string) ([]byte, error) {
		cmd := exec.CommandContext(ctx, ipPath, args...)
		isolateFromTerminalSignals(cmd)

		output, err := cmd.CombinedOutput()
		if err != nil {
			return nil, fmt.Errorf("ip command failed: %w: %s", err, strings.TrimSpace(string(output)))
		}

		return output, nil
	}

	return newNetNSLabManager(run, generateLabName, namespaceExists), nil
}

func findSystemIP() (string, error) {
	candidates := []string{
		"/usr/sbin/ip",
		"/usr/bin/ip",
		"/sbin/ip",
		"/bin/ip",
	}

	for _, candidate := range candidates {
		info, err := os.Stat(candidate)
		if err == nil && info.Mode().IsRegular() {
			return candidate, nil
		}
	}

	return "", errors.New("trusted system ip executable not found")
}

// Generate a 64-bit random identifier.
func generateLabName() (string, error) {
	var data [8]byte
	if _, err := rand.Read(data[:]); err != nil {
		return "", fmt.Errorf("generate namespace name: %w", err)
	}

	return "egresslab-lab-" + hex.EncodeToString(data[:]), nil
}

func namespaceExists(name string) (bool, error) {
	_, err := os.Lstat(filepath.Join(netNSRunDir, name))
	if err == nil {
		return true, nil
	}

	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}

	return false, err
}

func newNetNSLabManager(run netNSCommand, makeName labNameGenerator, exists netNSExists) *NetNSLabManager {
	return &NetNSLabManager{
		run:      run,
		makeName: makeName,
		exists:   exists,
		owned:    make(map[string]struct{}),
	}
}

func (m *NetNSLabManager) Create(ctx context.Context) (string, error) {
	name, err := m.makeName()
	if err != nil {
		return "", err
	}

	if !labNamePattern.MatchString(name) {
		return "", errors.New("invalid lab namespace name")
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	if _, exists := m.owned[name]; exists {
		return "", errors.New("lab namespace name already registered")
	}

	commandCtx, cancel := context.WithTimeout(ctx, netNSCommandTimeout)
	defer cancel()

	_, err = m.run(commandCtx, "netns", "add", name)
	if err == nil {
		m.owned[name] = struct{}{}
		return name, nil
	}

	createErr := fmt.Errorf("create lab namespace %s: %w", name, err)

	exists, checkErr := m.exists(name)
	if checkErr != nil {
		return "", errors.Join(
			createErr,
			fmt.Errorf("%w: cannot check whether %s exists: %w", ErrNetNSStateUncertain, name, checkErr),
		)
	}

	if exists {
		return "", errors.Join(
			createErr,
			fmt.Errorf("%w: %s exists but is not owned; inspect it before removing it manually", ErrNetNSStateUncertain, name),
		)
	}

	return "", createErr
}

func (m *NetNSLabManager) Delete(ctx context.Context, name string) error {
	if !labNamePattern.MatchString(name) {
		return errors.New("invalid lab namespace name")
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	if _, owned := m.owned[name]; !owned {
		return errors.New("refusing to delete namespace not created by this manager")
	}

	commandCtx, cancel := context.WithTimeout(ctx, netNSCommandTimeout)
	defer cancel()

	return m.deleteLocked(commandCtx, name)
}

func (m *NetNSLabManager) deleteLocked(ctx context.Context, name string) error {
	pids, err := m.run(ctx, "netns", "pids", name)
	if err != nil {
		return m.forgetIfGone(name, fmt.Errorf("inspect namespace processes: %w", err))
	}

	// Best-effort: a process can still join between "ip netns pids" and "ip netns delete".
	if len(bytes.TrimSpace(pids)) != 0 {
		return fmt.Errorf("namespace %s has processes; refusing deletion", name)
	}

	if _, err := m.run(ctx, "netns", "delete", name); err != nil {
		return m.forgetIfGone(name, fmt.Errorf("delete lab namespace %s: %w", name, err))
	}

	delete(m.owned, name)

	return nil
}

func (m *NetNSLabManager) forgetIfGone(name string, cause error) error {
	exists, err := m.exists(name)
	if err != nil {
		return errors.Join(cause, fmt.Errorf("check namespace %s: %w", name, err))
	}

	if exists {
		return cause
	}

	delete(m.owned, name)

	return nil
}
