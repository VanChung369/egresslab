package helperipc

import (
	"context"
	"testing"
	"time"
)

// Recorded evidence is timed on the monotonic clock, and bounded by its wall-clock age too: a wall
// clock far ahead ends it, a step back never extends it, and a step of a VM's time sync alone
// neither ends nor extends it.
func TestFreshSinceClockSteps(t *testing.T) {
	base := time.Now()
	observed := base.Round(0).Add(-10 * time.Second)
	expires := base.Add(50 * time.Second)

	for name, tt := range map[string]struct {
		observedAt time.Time // the observation's wall-clock time, as the clock now reads it
		now        time.Time
		ok         bool
	}{
		"at the record":                   {observed, base, true},
		"before the monotonic deadline":   {observed, base.Add(49 * time.Second), true},
		"at the monotonic deadline":       {observed, expires, false},
		"before the record":               {observed, base.Add(-time.Millisecond), false},
		"wall clock stepped ahead 1.1 s":  {observed.Add(-1100 * time.Millisecond), base.Add(20 * time.Second), true},
		"wall clock 10 minutes ahead":     {observed.Add(-10 * time.Minute), base.Add(time.Second), false},
		"wall clock stepped back past it": {observed.Add(15 * time.Second), base.Add(time.Second), true},
		"stepped back, at the deadline":   {observed.Add(15 * time.Second), expires, false},
	} {
		if freshSince(base, tt.observedAt, expires, tt.now) != tt.ok {
			t.Errorf("%s: want %t", name, tt.ok)
		}
	}

	if freshSince(time.Time{}, observed, expires, base) {
		t.Fatal("unrecorded evidence fresh")
	}

	health := egressMonitorHealth{observedAt: observed, checkedAt: base, expiresAt: expires}
	evidence := &verifiedMultiProbeEvidence{observedAt: observed, recordedAt: base, expiresAt: expires}

	for _, now := range []time.Time{base, expires} {
		if health.fresh(now) != freshSince(base, observed, expires, now) ||
			evidence.fresh(now) != freshSince(base, observed, expires, now) {
			t.Fatal("health or evidence judged apart from freshSince")
		}
	}
}

// A wall-clock step during a monitor check renews nothing and faults nothing, like a source without
// an answer; a step on top of an invalid observation still faults.
func TestEgressMonitorClockStepped(t *testing.T) {
	for _, tt := range []struct {
		mode    string
		step    int // the clock check that sees it: 1 around the probe, 2 from its start and 3 from its end to the renewal
		invalid func(*MultiProbeObservation)
	}{
		{mode: "around the probe", step: 1},
		{mode: "by the renewal", step: 2},
		{mode: "between the probe and the renewal", step: 3},
		{mode: "with an invalid observation", step: 1, invalid: func(o *MultiProbeObservation) { o.Sources = nil }},
		// Ten seconds before the check started: no step measured around it explains that.
		{mode: "with an observation outside the check", step: 1, invalid: func(o *MultiProbeObservation) {
			o.StartedAt = o.StartedAt.Add(-10 * time.Second)
		}},
	} {
		t.Run(tt.mode, func(t *testing.T) {
			ctx := context.Background()
			f, windows, _, _ := newTrafficWindowFixture(t)
			p := f.labs.preparedLease
			backend := windows.fakeGenerationProbeBackend

			p.monitor.checkedAt = p.monitor.checkedAt.Add(-egressMonitorInterval)
			health := p.monitor

			checks := 0
			f.labs.clockStable = func(time.Time, time.Time) bool {
				checks++
				return checks != tt.step
			}

			backend.mutate = tt.invalid

			err := f.labs.monitorPreparedOnce(ctx)

			if tt.invalid != nil {
				if err == nil || f.labs.preparedLease != nil || windows.cleanups != 1 ||
					f.labs.labs.peek(f.lab.ProfileID).State != LabFaulted {
					t.Fatalf("an invalid observation with a clock step kept the tunnel: %v", err)
				}

				return
			}

			if err != nil || checks != tt.step || windows.cleanups != 0 || f.labs.preparedLease != p ||
				f.labs.labs.peek(f.lab.ProfileID).State != LabTunnelConfigured {
				t.Fatalf("a clock step faulted the tunnel: %v", err)
			}

			recheck := time.Until(p.monitor.recheckAt)
			if p.monitor.observedAt != health.observedAt || p.monitor.checkedAt != health.checkedAt ||
				p.monitor.expiresAt != health.expiresAt || recheck <= 0 || recheck > egressMonitorRecheck {
				t.Fatal("a clock step changed the health")
			}

			// The recheck, on a steady clock, renews it.
			f.labs.clockStable = nil
			p.monitor.recheckAt = time.Now().Add(-time.Millisecond)

			if err := f.labs.monitorPreparedOnce(ctx); err != nil || !p.monitor.checkedAt.After(health.checkedAt) ||
				!p.monitor.recheckAt.IsZero() {
				t.Fatalf("the recheck did not renew the health: %v", err)
			}
		})
	}
}

// An on-demand probe across a clock step yields no evidence and restores the lab; with an
// observation that the step cannot explain, it still faults the lab.
func TestGenerationProbeClockStepped(t *testing.T) {
	ctx := context.Background()
	f, backend := newGenerationProbeFixture(t)
	intent := generationProbeIntent(t, f.lab, backend.pin.String(), ipcGenerationA)

	f.labs.clockStable = func(time.Time, time.Time) bool { return false }

	if _, err := f.labs.executeMultiProbe(ctx, f.mint(intent), f.verifier); labCode(err) != CodeEvidenceUnavailable ||
		f.labs.labs.peek(f.lab.ProfileID).State != LabTunnelConfigured || f.tunnels.cleanups != 0 ||
		f.labs.verifiedEvidence != nil || f.labs.tunnelProfile != f.lab.ProfileID {
		t.Fatalf("a clock step faulted the lab or left evidence: %v", err)
	}

	f.labs.clockStable = nil

	if _, err := f.labs.executeMultiProbe(ctx, f.mint(intent), f.verifier); err != nil || f.labs.verifiedEvidence == nil {
		t.Fatalf("the probe after a clock step: %v", err)
	}

	// Started before the capability was issued, or finished in the helper's future: no step measured
	// around the attempt explains either.
	for i, mutate := range []func(*MultiProbeObservation){
		func(o *MultiProbeObservation) { o.StartedAt = o.StartedAt.Add(-10 * time.Second) },
		func(o *MultiProbeObservation) { o.FinishedAt = o.FinishedAt.Add(10 * time.Second) },
	} {
		f, backend := newGenerationProbeFixture(t)
		intent := generationProbeIntent(t, f.lab, backend.pin.String(), ipcGenerationA)
		f.labs.clockStable = func(time.Time, time.Time) bool { return false }
		backend.mutate = mutate

		if _, err := f.labs.executeMultiProbe(ctx, f.mint(intent), f.verifier); labCode(err) == CodeEvidenceUnavailable ||
			f.labs.labs.peek(f.lab.ProfileID).State != LabFaulted || f.tunnels.cleanups != 1 {
			t.Fatalf("observation %d outside the attempt, with a clock step, kept the lab: %v", i, err)
		}
	}
}
