//go:build linux

package main

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/VanChung369/egresslab/services/network-agent/internal/agent"
	"github.com/VanChung369/egresslab/services/network-agent/internal/helperipc"
)

func TestRuntimeIDFrom(t *testing.T) {
	dir := t.TempDir()
	write := func(name, content string) string {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
		return path
	}

	a := write("a", "0123456789abcdef0123456789abcdef\n")
	b := write("b", "fedcba9876543210fedcba9876543210\n")

	idA, err := runtimeIDFrom(a)
	if err != nil || !helperipc.ValidRuntimeID(idA) {
		t.Fatalf("runtime ID: %q %v", idA, err)
	}

	if again, _ := runtimeIDFrom(a); again != idA {
		t.Fatal("runtime ID is not stable")
	}

	if idB, _ := runtimeIDFrom(b); idB == idA {
		t.Fatal("two machines share a runtime ID")
	}

	if idA == "runtime_0123456789abcdef0123456789abcdef" {
		t.Fatal("raw machine-id disclosed")
	}

	for name, content := range map[string]string{
		"empty": "", "short": "0123", "uppercase": "0123456789ABCDEF0123456789ABCDEF", "not hex": "zz23456789abcdef0123456789abcdef",
	} {
		if _, err := runtimeIDFrom(write(name, content)); err == nil {
			t.Errorf("%s machine-id accepted", name)
		}
	}

	if _, err := runtimeIDFrom(filepath.Join(dir, "missing")); err == nil {
		t.Error("missing machine-id accepted")
	}
}

func TestClassifyLabError(t *testing.T) {
	tests := []struct {
		err  error
		want error
	}{
		{fmt.Errorf("x: %w", agent.ErrKernelIncompatible), helperipc.ErrLabKernelIncompatible},
		{fmt.Errorf("x: %w", agent.ErrRecoveryRequired), helperipc.ErrLabRecoveryRequired},
		{fmt.Errorf("x: %w", agent.ErrFirewallDrift), helperipc.ErrLabFirewallDrift},
		{fmt.Errorf("x: %w", agent.ErrLabNotLoopbackOnly), helperipc.ErrLabTopology},
	}

	for _, tt := range tests {
		if got := classifyLabError(tt.err); !errors.Is(got, tt.want) || !errors.Is(got, tt.err) {
			t.Errorf("%v: got %v", tt.err, got)
		}
	}

	plain := errors.New("namespace busy")
	if got := classifyLabError(plain); got != plain {
		t.Errorf("unclassified error changed: %v", got)
	}

	if classifyLabError(nil) != nil {
		t.Error("nil became an error")
	}
}

// The lifecycle finds the data-plane gate on the generation backend by its method set alone.
func TestTunnelBackendOffersTrafficWindow(t *testing.T) {
	var backend any = tunnelBackend{}

	if _, ok := backend.(interface {
		WithTrafficWindow(context.Context, string, string, netip.Addr, uint32, time.Time,
			func(context.Context) error) error
	}); !ok {
		t.Fatal("tunnel backend lost WithTrafficWindow")
	}
}

// The monitor finds the traffic overlay the same way; without it, streams would pause at every check.
func TestTunnelBackendOffersMonitorOverlay(t *testing.T) {
	var backend any = tunnelBackend{}

	if _, ok := backend.(interface {
		ProbeConfiguredMultiForGenerationWithOverlay(context.Context, string, string,
			helperipc.MonitorTrafficOverlay) (helperipc.MultiProbeObservation, error)
	}); !ok {
		t.Fatal("tunnel backend does not offer the monitor's traffic overlay")
	}
}

// Only the agent's source without an answer, with the tunnel unchanged, reaches the helper as one.
func TestAdaptProbeError(t *testing.T) {
	soft := fmt.Errorf("source ident_me: %w", agent.ErrManagedProbeSourceUnavailable)
	if err := adaptProbeError(soft); !errors.Is(err, helperipc.ErrProbeSourceUnavailable) {
		t.Fatalf("source without an answer: %v", err)
	}

	for _, err := range []error{
		errors.Join(agent.ErrManagedProbeFailed, agent.ErrManagedProbeNoAnswer),
		agent.ErrManagedProbeFailed,
		agent.ErrManagedStickyIPChanged,
	} {
		if errors.Is(adaptProbeError(err), helperipc.ErrProbeSourceUnavailable) {
			t.Fatalf("%v adapted as a source without an answer", err)
		}
	}
}
