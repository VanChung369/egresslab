package helperipc

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"
)

var errTestSourceNoAnswer = fmt.Errorf("%w: source ident_me", ErrProbeSourceUnavailable)

// unansweredSwitchingBackend gives no answer while the tunnel moves to another generation.
type unansweredSwitchingBackend struct{ *fakeGenerationProbeBackend }

func (b unansweredSwitchingBackend) ProbeConfiguredMultiForGeneration(
	context.Context,
	string, string,
) (MultiProbeObservation, error) {
	b.generation = ipcGenerationB
	return MultiProbeObservation{}, errTestSourceNoAnswer
}

// A source without an answer renews nothing and faults nothing. The check runs again after the
// recheck spacing, no traffic window opens meanwhile, and only the health's expiry cuts the tunnel.
func TestEgressMonitorSourceNoAnswer(t *testing.T) {
	ctx := context.Background()
	f, windows, _, result := newTrafficWindowFixture(t)
	p := f.labs.preparedLease
	backend := windows.fakeGenerationProbeBackend

	p.monitor.checkedAt = p.monitor.checkedAt.Add(-egressMonitorInterval)
	health := p.monitor
	calls := backend.calls

	backend.probeErr = errTestSourceNoAnswer

	if err := f.labs.monitorPreparedOnce(ctx); err != nil {
		t.Fatal(err)
	}

	if backend.calls != calls+1 || windows.cleanups != 0 || f.labs.preparedLease != p ||
		f.labs.labs.peek(f.lab.ProfileID).State != LabTunnelConfigured {
		t.Fatal("a source without an answer faulted the tunnel")
	}

	recheck := time.Until(p.monitor.recheckAt)
	if p.monitor.observedAt != health.observedAt || p.monitor.checkedAt != health.checkedAt ||
		p.monitor.expiresAt != health.expiresAt || recheck <= 0 || recheck > egressMonitorRecheck {
		t.Fatal("a source without an answer changed the health")
	}

	if err := f.labs.monitorPreparedOnce(ctx); err != nil || backend.calls != calls+1 {
		t.Fatal("checked again before the recheck")
	}

	ran := false
	run := func(context.Context) error {
		ran = true
		return nil
	}

	if err := f.labs.WithPreparedTrafficWindow(ctx, result.ReservationID, 1001, run); !errors.Is(err, errLabBusy) ||
		ran || windows.opened != 0 {
		t.Fatalf("traffic window before a check succeeded: %v", err)
	}

	p.monitor.recheckAt = time.Now().Add(-time.Millisecond)
	backend.probeErr = nil

	if err := f.labs.monitorPreparedOnce(ctx); err != nil || backend.calls != calls+2 ||
		!p.monitor.checkedAt.After(health.checkedAt) || !p.monitor.recheckAt.IsZero() {
		t.Fatalf("the recheck did not renew the health: %v", err)
	}

	p.monitor.checkedAt = p.monitor.checkedAt.Add(-egressMonitorInterval)
	backend.probeErr = errTestSourceNoAnswer

	if err := f.labs.monitorPreparedOnce(ctx); err != nil || windows.cleanups != 0 {
		t.Fatalf("second source without an answer: %v", err)
	}

	p.monitor.expiresAt = time.Now().Add(-time.Millisecond)
	p.monitor.recheckAt = time.Time{}

	if err := f.labs.monitorPreparedOnce(ctx); err == nil || f.labs.preparedLease != nil || windows.cleanups != 1 ||
		f.labs.labs.peek(f.lab.ProfileID).State != LabFaulted {
		t.Fatalf("expired health without a successful check kept the tunnel: %v", err)
	}
}

// Without an answer, a tunnel that changed generation meanwhile is still faulted.
func TestEgressMonitorSourceNoAnswerGenerationChanged(t *testing.T) {
	f, windows, _, _ := newTrafficWindowFixture(t)
	p := f.labs.preparedLease

	p.monitor.checkedAt = p.monitor.checkedAt.Add(-egressMonitorInterval)
	f.labs.generationProbes = unansweredSwitchingBackend{windows.fakeGenerationProbeBackend}

	if err := f.labs.monitorPreparedOnce(context.Background()); err == nil || f.labs.preparedLease != nil ||
		windows.cleanups != 1 || f.labs.labs.peek(f.lab.ProfileID).State != LabFaulted {
		t.Fatalf("a changed generation was kept: %v", err)
	}
}

// An on-demand probe without an answer restores the lab and asks for a new capability; with a
// changed generation, it faults the lab.
func TestGenerationProbeSourceNoAnswer(t *testing.T) {
	ctx := context.Background()
	f, backend := newGenerationProbeFixture(t)
	intent := generationProbeIntent(t, f.lab, backend.pin.String(), ipcGenerationA)

	backend.probeErr = errTestSourceNoAnswer
	req := f.mint(intent)

	if _, err := f.labs.executeMultiProbe(ctx, req, f.verifier); labCode(err) != CodeEvidenceUnavailable ||
		f.labs.labs.peek(f.lab.ProfileID).State != LabTunnelConfigured || f.tunnels.cleanups != 0 ||
		f.labs.verifiedEvidence != nil || f.labs.tunnelProfile != f.lab.ProfileID {
		t.Fatalf("a source without an answer faulted the lab: %v", err)
	}

	if _, err := f.labs.executeMultiProbe(ctx, req, f.verifier); labCode(err) != CodeAuthorizationDenied {
		t.Fatalf("the used capability probed again: %v", err)
	}

	backend.probeErr = nil

	if _, err := f.labs.executeMultiProbe(ctx, f.mint(intent), f.verifier); err != nil || f.labs.verifiedEvidence == nil {
		t.Fatalf("a new capability did not probe: %v", err)
	}

	f.labs.generationProbes = unansweredSwitchingBackend{backend}

	if _, err := f.labs.executeMultiProbe(ctx, f.mint(intent), f.verifier); labCode(err) == CodeEvidenceUnavailable ||
		f.labs.labs.peek(f.lab.ProfileID).State != LabFaulted || f.tunnels.cleanups != 1 {
		t.Fatalf("a changed generation was kept: %v", err)
	}
}

// The recheck is due at its time even when no stream makes the check due early, and before the
// routine interval.
func TestEgressMonitorRecheckDueWithoutStreams(t *testing.T) {
	f, windows, _, _ := newTrafficWindowFixture(t)
	p := f.labs.preparedLease
	backend := windows.fakeGenerationProbeBackend
	calls := backend.calls
	now := time.Now()

	if p.monitor.due(now) || f.labs.proxyPlane.Load() != nil {
		t.Fatal("the fixture's check is already due")
	}

	p.monitor.recheckAt = now.Add(-time.Millisecond)

	if err := f.labs.monitorPreparedOnce(context.Background()); err != nil || backend.calls != calls+1 {
		t.Fatalf("the recheck did not run before the routine interval: %v", err)
	}
}

// slowGenerationBackend gives no answer, and its next generation read outlasts the health.
type slowGenerationBackend struct {
	*fakeGenerationProbeBackend
	slow *time.Duration
}

func (b slowGenerationBackend) ProbeConfiguredMultiForGeneration(
	context.Context,
	string, string,
) (MultiProbeObservation, error) {
	*b.slow = 400 * time.Millisecond
	return MultiProbeObservation{}, errTestSourceNoAnswer
}

func (b slowGenerationBackend) CurrentTunnelGeneration(namespace string) (string, error) {
	time.Sleep(*b.slow)
	return b.fakeGenerationProbeBackend.CurrentTunnelGeneration(namespace)
}

// A check without an answer that ends after the health expired faults at once.
func TestEgressMonitorSourceNoAnswerPastExpiry(t *testing.T) {
	f, windows, _, _ := newTrafficWindowFixture(t)
	p := f.labs.preparedLease

	var slow time.Duration

	f.labs.generationProbes = slowGenerationBackend{windows.fakeGenerationProbeBackend, &slow}
	p.monitor.expiresAt = time.Now().Add(300 * time.Millisecond)

	if err := f.labs.monitorPreparedOnce(context.Background()); err == nil || f.labs.preparedLease != nil ||
		windows.cleanups != 1 || f.labs.labs.peek(f.lab.ProfileID).State != LabFaulted {
		t.Fatalf("a check that ended past the health kept the tunnel: %v", err)
	}
}
