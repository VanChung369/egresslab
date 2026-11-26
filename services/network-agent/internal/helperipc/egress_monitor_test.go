package helperipc

import (
	"context"
	"errors"
	"log"
	"net/netip"
	"os"
	"testing"
	"time"
)

func TestEgressMonitorHealthy(t *testing.T) {
	f, backend, req := newPreparedLeaseFixture(t)

	if _, err := runPrepareLease(f, req); err != nil {
		t.Fatal(err)
	}

	p := f.labs.preparedLease
	originalInfo, originalEvidence := p.info, p.evidence

	// Not due yet.
	if err := f.labs.monitorPreparedOnce(context.Background()); err != nil {
		t.Fatal(err)
	}

	if backend.calls != 1 {
		t.Fatal("unnecessary probe")
	}

	p.monitor.checkedAt = p.monitor.checkedAt.Add(-egressMonitorInterval)
	before := p.monitor.checkedAt

	if err := f.labs.monitorPreparedOnce(context.Background()); err != nil {
		t.Fatal(err)
	}

	if backend.calls != 2 || backend.cleanups != 0 || f.labs.preparedLease != p || !p.monitor.checkedAt.After(before) ||
		!p.monitor.fresh(time.Now()) || f.labs.labs[f.lab.ProfileID].State != LabTunnelConfigured {
		t.Fatal("monitor did not renew health")
	}

	if p.info != originalInfo || p.evidence != originalEvidence {
		t.Fatal("monitor modified the original authorization")
	}

	if f.labs.verifiedEvidence != nil || f.labs.localCandidate != nil {
		t.Fatal("monitor created reservable evidence")
	}
}

// A busy lifecycle skips the check: no probe, no renewal, no fault.
func TestEgressMonitorSkipsBusyLifecycle(t *testing.T) {
	f, backend, req := newPreparedLeaseFixture(t)

	if _, err := runPrepareLease(f, req); err != nil {
		t.Fatal(err)
	}

	p := f.labs.preparedLease
	p.monitor.checkedAt = p.monitor.checkedAt.Add(-egressMonitorInterval)
	health := p.monitor

	f.labs.mu.Lock()
	err := f.labs.monitorPreparedOnce(context.Background())
	f.labs.mu.Unlock()

	if err != nil || backend.calls != 1 || p.monitor != health || f.labs.preparedLease != p ||
		f.labs.labs[f.lab.ProfileID].State != LabTunnelConfigured {
		t.Fatal("a busy lifecycle was monitored")
	}
}

func TestEgressMonitorFaults(t *testing.T) {
	for _, mode := range []string{
		"ip changed", "probe failed", "source disagreement", "wrong generation", "generation drift",
		"policy changed", "expired health", "cleanup failed",
	} {
		t.Run(mode, func(t *testing.T) {
			f, backend, req := newPreparedLeaseFixture(t)

			if _, err := runPrepareLease(f, req); err != nil {
				t.Fatal(err)
			}

			p := f.labs.preparedLease
			p.monitor.checkedAt = p.monitor.checkedAt.Add(-egressMonitorInterval)

			switch mode {
			case "ip changed":
				backend.mutate = func(o *MultiProbeObservation) {
					ip := netip.MustParseAddr("8.8.8.8")
					o.IPv4 = ip

					for i := range o.Sources {
						o.Sources[i].IPv4 = ip
					}
				}
			case "probe failed":
				backend.probeErr = errors.New("synthetic probe failure")
			case "source disagreement":
				backend.mutate = func(o *MultiProbeObservation) {
					o.Sources[1].IPv4 = netip.MustParseAddr("8.8.8.8")
				}
			case "wrong generation":
				backend.wrongGeneration = true
			case "generation drift":
				backend.generation = ipcGenerationB
			case "policy changed":
				backend.pin = netip.MustParseAddr("8.8.8.8")
			case "expired health":
				p.monitor.expiresAt = time.Now().Add(-time.Second)
			case "cleanup failed":
				backend.probeErr = errors.New("probe failed")
				backend.cleanupErr = errors.New("cleanup failed")
			}

			err := f.labs.monitorPreparedOnce(context.Background())

			if err == nil || f.labs.preparedLease != nil || f.labs.labs[f.lab.ProfileID].State != LabFaulted {
				t.Fatal("failed monitor did not fault the lab")
			}

			record := f.labs.candidateRetirements[req.Intent.ReservationNonce]
			if record == nil {
				t.Fatal("retirement history lost")
			}

			switch mode {
			case "wrong generation", "generation drift", "cleanup failed":
				if record.retired {
					t.Fatal("unproven retirement accepted")
				}

			default:
				if !record.retired {
					t.Fatal("confirmed retirement not recorded")
				}

				if _, err := runRevokeLease(f, revokeRequest(t, f, req)); err != nil {
					t.Fatalf("retirement confirmation failed: %v", err)
				}
			}

			// A faulted lab is never monitored again.
			calls := backend.calls
			if err := f.labs.monitorPreparedOnce(context.Background()); err != nil || backend.calls != calls {
				t.Fatal("a faulted lab was monitored again")
			}
		})
	}
}

func TestEgressMonitorStopsAfterRelease(t *testing.T) {
	f, backend, req := newPreparedLeaseFixture(t)

	if _, err := runPrepareLease(f, req); err != nil {
		t.Fatal(err)
	}

	if _, err := runRevokeLease(f, revokeRequest(t, f, req)); err != nil {
		t.Fatal(err)
	}

	if _, err := f.execute(f.connectRequest()); err != nil {
		t.Fatal(err)
	}

	calls, cleanups := backend.calls, backend.cleanups

	if err := f.labs.monitorPreparedOnce(context.Background()); err != nil {
		t.Fatal(err)
	}

	if backend.calls != calls || backend.cleanups != cleanups || f.labs.preparedLease != nil ||
		f.labs.labs[f.lab.ProfileID].State != LabTunnelConfigured {
		t.Fatal("an old monitor affected a new generation")
	}
}

type stalledLogWriter struct{ release chan struct{} }

func (w stalledLogWriter) Write(p []byte) (int, error) {
	<-w.release
	return len(p), nil
}

// A stalled log sink drops monitor lines instead of blocking the caller.
func TestEgressMonitorLogNeverBlocks(t *testing.T) {
	release := make(chan struct{})
	log.SetOutput(stalledLogWriter{release: release})

	defer func() {
		close(release)
		log.SetOutput(os.Stderr)
	}()

	done := make(chan struct{})

	go func() {
		defer close(done)

		for i := 0; i < 4*monitorLogQueue; i++ {
			logMonitor("synthetic monitor line %d", i)
		}
	}()

	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("monitor logging blocked")
	}
}
