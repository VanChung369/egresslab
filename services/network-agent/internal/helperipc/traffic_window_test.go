package helperipc

import (
	"context"
	"errors"
	"net/netip"
	"testing"
	"time"
)

type fakeTrafficWindowBackend struct {
	*fakeGenerationProbeBackend

	opened      int
	healthUntil time.Time
	err         error
}

func (b *fakeTrafficWindowBackend) WithTrafficWindow(
	ctx context.Context,
	namespace, generation string,
	expectedIP netip.Addr,
	uid uint32,
	healthUntil time.Time,
	run func(context.Context) error,
) error {
	b.opened++
	b.healthUntil = healthUntil

	if generation != b.generation || expectedIP.String() != "8.8.4.4" || uid != 1001 || !time.Now().Before(healthUntil) {
		return errLabInvalid
	}

	if b.err != nil {
		return b.err
	}

	return run(ctx)
}

func newTrafficWindowFixture(t *testing.T) (*tunnelFixture, *fakeTrafficWindowBackend, Request, PreparedLeaseInfo) {
	t.Helper()

	f, backend, req := newPreparedLeaseFixture(t)

	result, err := runPrepareLease(f, req)
	if err != nil {
		t.Fatal(err)
	}

	windows := &fakeTrafficWindowBackend{fakeGenerationProbeBackend: backend}
	f.labs.generationProbes = windows

	return f, windows, req, result
}

func TestPreparedTrafficWindow(t *testing.T) {
	f, windows, _, result := newTrafficWindowFixture(t)
	p := f.labs.preparedLease
	info, evidence, health := p.info, p.evidence, p.monitor

	called := false
	run := func(context.Context) error {
		called = true
		return nil
	}

	if err := f.labs.WithPreparedTrafficWindow(context.Background(), result.ReservationID, 1001, run); err != nil ||
		!called || windows.opened != 1 {
		t.Fatalf("valid traffic window refused: %v", err)
	}

	if f.labs.preparedLease != p || p.info != info || p.evidence != evidence || p.monitor != health ||
		windows.healthUntil.After(health.checkedAt.Add(egressMonitorInterval)) ||
		f.labs.labs[f.lab.ProfileID].State != LabTunnelConfigured {
		t.Fatal("traffic window changed the lease or outlived the next monitor check")
	}

	called = false
	p.monitor.expiresAt = time.Now().Add(-time.Second)

	err := f.labs.WithPreparedTrafficWindow(context.Background(), result.ReservationID, 1001, run)
	if err == nil || called || windows.opened != 1 || f.labs.preparedLease != nil || windows.cleanups != 1 ||
		f.labs.labs[f.lab.ProfileID].State != LabFaulted {
		t.Fatal("expired monitoring health allowed traffic")
	}
}

func TestPreparedTrafficWindowRefusals(t *testing.T) {
	run := func(context.Context) error {
		t.Fatal("worker ran without a window")
		return nil
	}

	for _, mode := range []string{
		"wrong reservation", "root UID", "busy lifecycle", "monitor due", "next check too close", "renewal due soon",
		"backend too late",
	} {
		t.Run(mode, func(t *testing.T) {
			f, windows, _, result := newTrafficWindowFixture(t)
			p := f.labs.preparedLease
			id, uid := result.ReservationID, uint32(1001)

			var want error

			switch mode {
			case "wrong reservation":
				id, want = "reservation_ffffffffffffffffffffffffffffffff", errLabAuthorization
			case "root UID":
				uid, want = 0, errLabInvalid
			case "busy lifecycle":
				want = errLabBusy
				f.labs.mu.Lock()
				defer f.labs.mu.Unlock()
			case "monitor due":
				p.monitor.checkedAt = p.monitor.checkedAt.Add(-egressMonitorInterval)
				want = errLabBusy
			case "next check too close":
				p.monitor.checkedAt = p.monitor.checkedAt.Add(-9 * time.Second)
				want = errLabBusy
			case "renewal due soon":
				// Not due yet, but the monitor renews 30 s before the health expires.
				p.monitor.expiresAt = time.Now().Add(egressMonitorBudget + 5*time.Second)
				want = errLabBusy
			case "backend too late":
				windows.err = ErrTrafficWindowTooLate
				want = errLabBusy
			}

			err := f.labs.WithPreparedTrafficWindow(context.Background(), id, uid, run)
			opened := 0
			if mode == "backend too late" {
				opened = 1
			}

			if !errors.Is(err, want) || windows.opened != opened || windows.cleanups != 0 || f.labs.preparedLease != p ||
				f.labs.labs[f.lab.ProfileID].State != LabTunnelConfigured {
				t.Fatalf("unexpected refusal: %v", err)
			}
		})
	}
}

func TestPreparedTrafficWindowFaults(t *testing.T) {
	for _, mode := range []string{"generation drift", "window failed", "cleanup failed"} {
		t.Run(mode, func(t *testing.T) {
			f, windows, req, result := newTrafficWindowFixture(t)

			switch mode {
			case "generation drift":
				windows.generation = ipcGenerationB
			case "window failed":
				windows.err = errors.New("synthetic gate failure")
			case "cleanup failed":
				f.labs.preparedLease.monitor.expiresAt = time.Now().Add(-time.Second)
				windows.cleanupErr = errors.New("cleanup failed")
			}

			err := f.labs.WithPreparedTrafficWindow(context.Background(), result.ReservationID, 1001,
				func(context.Context) error { return nil })

			if err == nil || f.labs.preparedLease != nil || f.labs.labs[f.lab.ProfileID].State != LabFaulted {
				t.Fatal("failed window did not fault the lab")
			}

			record := f.labs.candidateRetirements[req.Intent.ReservationNonce]
			if record == nil || record.retired != (mode == "window failed") {
				t.Fatal("incorrect retirement after a failed window")
			}

			if (mode == "window failed") != (windows.opened == 1) {
				t.Fatal("window opened when it must not")
			}
		})
	}
}
