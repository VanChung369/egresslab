package helperipc

import (
	"context"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// overlayProbeBackend records the overlays the monitor offers.
type overlayProbeBackend struct {
	*fakeGenerationProbeBackend

	overlays []MonitorTrafficOverlay
	plain    int
}

func (b *overlayProbeBackend) ProbeConfiguredMultiForGeneration(ctx context.Context, namespace, generation string) (
	MultiProbeObservation, error) {
	b.plain++
	return b.fakeGenerationProbeBackend.ProbeConfiguredMultiForGeneration(ctx, namespace, generation)
}

func (b *overlayProbeBackend) ProbeConfiguredMultiForGenerationWithOverlay(ctx context.Context, namespace,
	generation string, overlay MonitorTrafficOverlay) (MultiProbeObservation, error) {
	b.overlays = append(b.overlays, overlay)
	return b.fakeGenerationProbeBackend.ProbeConfiguredMultiForGeneration(ctx, namespace, generation)
}

func TestEgressMonitorTrafficOverlay(t *testing.T) {
	const proxyUID = 998

	for _, mode := range []string{
		"streaming", "no plane", "no stream", "cancelled plane", "other reservation", "no UID", "plain backend",
	} {
		t.Run(mode, func(t *testing.T) {
			f, backend, req := newPreparedLeaseFixture(t)

			if _, err := runPrepareLease(f, req); err != nil {
				t.Fatal(err)
			}

			probes := &overlayProbeBackend{fakeGenerationProbeBackend: backend}
			if mode != "plain backend" {
				f.labs.generationProbes = probes
			}

			p := f.labs.preparedLease
			p.monitor.checkedAt = p.monitor.checkedAt.Add(-egressMonitorInterval)
			admittedOn := p.monitor.expiresAt

			plane := newProxyPlane(context.Background(), p.info.ProfileID, p.info.ReservationID)
			plane.uid = proxyUID
			plane.streams[testProxyStream(t)] = struct{}{}

			switch mode {
			case "no stream":
				clear(plane.streams)
			case "cancelled plane":
				plane.cancel()
			case "other reservation":
				plane.reservationID = "reservation_ffffffffffffffffffffffffffffffff"
			case "no UID":
				plane.uid = 0
			}

			if mode != "no plane" {
				f.labs.proxyPlane.Store(plane)
			}

			calls := backend.calls

			if err := f.labs.monitorPreparedOnce(context.Background()); err != nil {
				t.Fatal(err)
			}

			if backend.calls != calls+1 || !p.monitor.fresh(time.Now()) || p.monitor.expiresAt.Equal(admittedOn) {
				t.Fatal("monitor did not renew health")
			}

			if mode != "streaming" {
				if len(probes.overlays) != 0 {
					t.Fatalf("overlay offered without running streams of this reservation: %+v", probes.overlays)
				}

				return
			}

			if len(probes.overlays) != 1 || probes.plain != 0 {
				t.Fatalf("overlay not offered: %d overlays, %d plain probes", len(probes.overlays), probes.plain)
			}

			overlay := probes.overlays[0]

			// The UID is the keeper's, the health the one the streams were admitted on.
			if overlay.UID != proxyUID || !overlay.HealthUntil.Equal(admittedOn) || overlay.Alive == nil || !overlay.Alive() {
				t.Fatalf("unexpected overlay: %+v", overlay)
			}

			plane.close(errLabAuthorization)

			if overlay.Alive() {
				t.Fatal("overlay still alive after its plane closed")
			}
		})
	}
}

// With streams running, the check is due as soon as the keeper can open no more windows, not at the
// routine interval: the overlay then follows the last window without a gap.
func TestEgressMonitorDueWhenWindowsEnd(t *testing.T) {
	for _, streaming := range []bool{false, true} {
		t.Run(map[bool]string{false: "no streams", true: "streams"}[streaming], func(t *testing.T) {
			f, backend, req := newPreparedLeaseFixture(t)

			if _, err := runPrepareLease(f, req); err != nil {
				t.Fatal(err)
			}

			probes := &overlayProbeBackend{fakeGenerationProbeBackend: backend}
			f.labs.generationProbes = probes

			p := f.labs.preparedLease
			now := time.Now()

			// Not due by the interval for 15 s, but a window would need more health than is left
			// before renewBy.
			p.monitor.checkedAt = now.Add(-egressMonitorInterval + 15*time.Second)
			p.monitor.expiresAt = now.Add(egressMonitorBudget + trafficWindowMinHealth - time.Second)

			if !p.monitor.fresh(now) || p.monitor.due(now) {
				t.Fatal("unexpected fixture health")
			}

			if streaming {
				plane := newProxyPlane(context.Background(), p.info.ProfileID, p.info.ReservationID)
				plane.uid = 998
				plane.streams[testProxyStream(t)] = struct{}{}
				f.labs.proxyPlane.Store(plane)
			}

			calls := backend.calls

			if err := f.labs.monitorPreparedOnce(context.Background()); err != nil {
				t.Fatal(err)
			}

			if checked := backend.calls == calls+1; checked != streaming {
				t.Fatalf("check ran: %v, with streams: %v", checked, streaming)
			}

			if streaming && len(probes.overlays) != 1 {
				t.Fatal("early check without the overlay")
			}
		})
	}
}

// A check that itself ended after the windows' end does not run again at once: no window could have
// opened, and a slow check repeated back to back would probe without pause.
func TestEgressMonitorNotDueAgainAfterSlowCheck(t *testing.T) {
	f, backend, req := newPreparedLeaseFixture(t)

	if _, err := runPrepareLease(f, req); err != nil {
		t.Fatal(err)
	}

	p := f.labs.preparedLease
	now := time.Now()

	// A check that took 18 s: it ended 2 s after the last moment a window could open.
	p.monitor.expiresAt = now.Add(egressMonitorBudget + trafficWindowMinHealth - 2*time.Second)
	p.monitor.checkedAt = now.Add(-time.Second)

	plane := newProxyPlane(context.Background(), p.info.ProfileID, p.info.ReservationID)
	plane.uid = 998
	plane.streams[testProxyStream(t)] = struct{}{}
	f.labs.proxyPlane.Store(plane)

	calls := backend.calls

	if err := f.labs.monitorPreparedOnce(context.Background()); err != nil || backend.calls != calls {
		t.Fatalf("slow check repeated at once: %v", err)
	}
}

// A release waiting for the lock is not kept waiting by a check that starts meanwhile.
func TestEgressMonitorYieldsToWaitingRelease(t *testing.T) {
	f, backend, req := newPreparedLeaseFixture(t)

	if _, err := runPrepareLease(f, req); err != nil {
		t.Fatal(err)
	}

	p := f.labs.preparedLease
	p.monitor.checkedAt = p.monitor.checkedAt.Add(-egressMonitorInterval)
	calls := backend.calls

	f.labs.proxyHalt.Add(1)
	err := f.labs.monitorPreparedOnce(context.Background())
	f.labs.proxyHalt.Add(-1)

	if err != nil || backend.calls != calls {
		t.Fatalf("check started while a release waited: %v", err)
	}

	if err := f.labs.monitorPreparedOnce(context.Background()); err != nil || backend.calls != calls+1 {
		t.Fatalf("check not resumed after the release: %v", err)
	}
}

// A monitor that sees another address faults the lab and closes the running streams; the durable
// hold is the controller's.
func TestEgressMonitorDriftClosesStreams(t *testing.T) {
	f, backend, req := newPreparedLeaseFixture(t)

	if _, err := runPrepareLease(f, req); err != nil {
		t.Fatal(err)
	}

	probes := &overlayProbeBackend{fakeGenerationProbeBackend: backend}
	f.labs.generationProbes = probes

	p := f.labs.preparedLease
	p.monitor.checkedAt = p.monitor.checkedAt.Add(-egressMonitorInterval)

	plane := newProxyPlane(context.Background(), p.info.ProfileID, p.info.ReservationID)
	plane.uid = 998
	plane.streams[testProxyStream(t)] = struct{}{}
	f.labs.proxyPlane.Store(plane)

	backend.mutate = func(o *MultiProbeObservation) {
		ip := netip.MustParseAddr("8.8.8.8")
		o.IPv4 = ip

		for i := range o.Sources {
			o.Sources[i].IPv4 = ip
		}
	}

	if err := f.labs.monitorPreparedOnce(context.Background()); err == nil {
		t.Fatal("drift accepted")
	}

	if len(probes.overlays) != 1 || f.labs.preparedLease != nil || f.labs.labs.peek(f.lab.ProfileID).State != LabFaulted ||
		f.labs.proxyPlane.Load() != nil || plane.ctx.Err() == nil || plane.streaming() {
		t.Fatal("drift left the streams or the lab running")
	}
}

// testProxyStream is an admitted stream over real sockets, so that closing it closes something.
func testProxyStream(t *testing.T) *proxyStreamState {
	t.Helper()

	tcp, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer tcp.Close()

	target, err := net.DialTCP("tcp4", nil, tcp.Addr().(*net.TCPAddr))
	if err != nil {
		t.Fatal(err)
	}

	destination, err := tcp.AcceptTCP()
	if err != nil {
		t.Fatal(err)
	}

	dir, err := os.MkdirTemp("", "egl")
	if err != nil {
		t.Fatal(err)
	}

	unix, err := net.ListenUnix("unix", &net.UnixAddr{Name: filepath.Join(dir, "s"), Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close()

	client, err := net.DialUnix("unix", nil, unix.Addr().(*net.UnixAddr))
	if err != nil {
		t.Fatal(err)
	}

	server, err := unix.AcceptUnix()
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())

	t.Cleanup(func() {
		cancel()
		_ = destination.Close()
		_ = server.Close()
		_ = client.Close()
		_ = target.Close()
		_ = os.RemoveAll(dir)
	})

	return &proxyStreamState{ctx: ctx, cancel: cancel, client: server, target: target}
}
