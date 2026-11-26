package helperipc

import (
	"context"
	"errors"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/VanChung369/egresslab/services/network-agent/internal/helperauth"
)

const (
	egressMonitorInterval = 20 * time.Second
	egressMonitorBudget   = 30 * time.Second
	egressMonitorTick     = time.Second

	monitorLogQueue = 32
)

var (
	monitorLogs   = make(chan string, monitorLogQueue)
	monitorLogger sync.Once
)

// logDetached never blocks its caller: a stalled log sink drops lines instead of stopping the
// monitor, a traffic window or the helper's shutdown.
func logDetached(format string, args ...any) {
	monitorLogger.Do(func() {
		go func() {
			for line := range monitorLogs {
				log.Print(line)
			}
		}()
	})

	select {
	case monitorLogs <- fmt.Sprintf(format, args...):
	default:
	}
}

// egressMonitorHealth belongs to the prepared lease's generation. It never renews the original
// evidence or authorization.
type egressMonitorHealth struct {
	observedAt time.Time
	checkedAt  time.Time
	expiresAt  time.Time
}

func (h egressMonitorHealth) fresh(now time.Time) bool {
	if h.checkedAt.IsZero() || !evidenceClockStable(h.checkedAt, now) || !now.Before(h.expiresAt) {
		return false
	}

	age := now.Sub(h.observedAt)

	return age >= 0 && age < verifiedProbeEvidenceTTL
}

// renewBy is the last moment a renewal can start with its whole probe budget before the health
// expires.
func (h egressMonitorHealth) renewBy() time.Time {
	return h.expiresAt.Add(-egressMonitorBudget)
}

// nextDue: one interval after the last check, or earlier at renewBy.
func (h egressMonitorHealth) nextDue() time.Time {
	next := h.checkedAt.Add(egressMonitorInterval)
	if renewal := h.renewBy(); renewal.Before(next) {
		next = renewal
	}

	return next
}

func (h egressMonitorHealth) due(now time.Time) bool {
	return !now.Before(h.nextDue())
}

// MonitorTrafficOverlay lets the proxy streams that the traffic gate admitted keep flowing while a
// monitor check probes (agent.MonitorTrafficOverlay). It admits no new connection.
type MonitorTrafficOverlay struct {
	UID         uint32
	HealthUntil time.Time
	Alive       func() bool
}

type monitorOverlayBackend interface {
	ProbeConfiguredMultiForGenerationWithOverlay(ctx context.Context, namespace, generation string,
		overlay MonitorTrafficOverlay) (MultiProbeObservation, error)
}

// monitorOverlayLocked is offered only for running streams of the monitored reservation, on the
// health they were admitted on, with the UID the keeper got from the helper's configuration. The
// caller holds l.mu.
func (l *LabLifecycle) monitorOverlayLocked(p *preparedEgressLease, now time.Time) (MonitorTrafficOverlay, bool) {
	plane := l.proxyPlane.Load()

	if plane == nil || plane.reservationID != p.info.ReservationID || plane.profileID != p.info.ProfileID ||
		plane.uid == 0 || plane.uid == ^uint32(0) || !plane.streaming() || !p.monitor.fresh(now) {
		return MonitorTrafficOverlay{}, false
	}

	return MonitorTrafficOverlay{UID: plane.uid, HealthUntil: p.monitor.expiresAt, Alive: plane.streaming}, true
}

// monitorDueLocked: while proxy streams of the reservation run, the check is due as soon as no
// traffic window may open any more (trafficWindowMinHealth before renewBy), so that the overlay
// follows the last window instead of leaving the streams without a gate until the routine interval;
// a pause of several seconds sets TCP's retransmission back off further. The caller holds l.mu.
// A check that itself ended past that point leaves no window to follow, and goes by the routine
// schedule.
func (l *LabLifecycle) monitorDueLocked(p *preparedEgressLease, now time.Time) bool {
	if p.monitor.due(now) {
		return true
	}

	windowsEnd := p.monitor.renewBy().Add(-trafficWindowMinHealth)
	plane := l.proxyPlane.Load()

	return plane != nil && plane.reservationID == p.info.ReservationID && plane.streaming() &&
		p.monitor.checkedAt.Before(windowsEnd) && !now.Before(windowsEnd)
}

// probeMonitoredGenerationLocked runs the monitor's probe, with the overlay when there is one and the
// backend supports it. The caller holds l.mu.
func (l *LabLifecycle) probeMonitoredGenerationLocked(ctx context.Context, p *preparedEgressLease, namespace,
	generation string) (MultiProbeObservation, error) {
	if overlay, ok := l.monitorOverlayLocked(p, time.Now()); ok {
		if backend, supported := l.generationProbes.(monitorOverlayBackend); supported {
			return backend.ProbeConfiguredMultiForGenerationWithOverlay(ctx, namespace, generation, overlay)
		}
	}

	return l.generationProbes.ProbeConfiguredMultiForGeneration(ctx, namespace, generation)
}

// faultMonitoredTunnelLocked faults the lab and removes its tunnel. Only a confirmed cleanup retires
// the generation; the durable hold stays with the controller. The caller must hold l.mu.
func (l *LabLifecycle) faultMonitoredTunnelLocked(lab LabInfo, cause error) error {
	lab.State = LabFaulted
	l.labs[lab.ProfileID] = lab

	cleanupCtx, cancel := context.WithTimeout(context.Background(), tunnelCleanupTimeout)
	defer cancel()

	if cleanupErr := l.clearTunnelLocked(cleanupCtx, lab); cleanupErr != nil {
		return errors.Join(errLabUncertain, cause, cleanupErr)
	}

	return fmt.Errorf("%w: egress monitor: %v", errLabFaulted, cause)
}

// monitorPreparedOnce checks the prepared generation once, if due. A busy lifecycle skips the check
// and renews nothing, and so does a release waiting for the lock: a check started now would keep it
// for seconds. The log is queued off the lock.
func (l *LabLifecycle) monitorPreparedOnce(ctx context.Context) error {
	if l == nil || ctx.Err() != nil || l.proxyHalt.Load() > 0 || !l.mu.TryLock() {
		return nil
	}

	// Again under the lock: a release may have started waiting since the first look.
	if l.proxyHalt.Load() > 0 {
		l.mu.Unlock()
		return nil
	}

	renewed, err := l.monitorPreparedLocked(ctx)
	l.mu.Unlock()

	if renewed != nil {
		logDetached("Egress monitor healthy: reservation=%s generation=%s ipv4=%s",
			renewed.ReservationID, renewed.TunnelGeneration, renewed.IPv4)
	}

	return err
}

// monitorPreparedLocked: the caller holds l.mu.
func (l *LabLifecycle) monitorPreparedLocked(ctx context.Context) (*PreparedLeaseInfo, error) {
	p := l.preparedLease

	if l.closed || p == nil || ctx.Err() != nil {
		return nil, nil
	}

	lab, exists := l.labs[p.info.ProfileID]

	// Ownership is inconsistent: drop the authorization, but clean up no arbitrary namespace.
	if !exists || lab.Namespace != p.info.Namespace || l.tunnelProfile != p.info.ProfileID {
		l.blockCreation = true
		l.invalidateEvidenceLocked(p.info.ProfileID)

		return nil, errLabUncertain
	}

	fail := func(err error) (*PreparedLeaseInfo, error) {
		return nil, l.faultMonitoredTunnelLocked(lab, err)
	}

	if l.blockCreation || lab.State != LabTunnelConfigured || l.generationProbes == nil || l.multiProbes == nil ||
		!p.info.valid() {
		return fail(errLabUncertain)
	}

	now := time.Now()

	if !p.monitor.fresh(now) {
		return fail(errors.New("monitor health expired"))
	}

	if !l.monitorDueLocked(p, now) {
		return nil, nil
	}

	generation, err := l.currentGenerationLocked(lab.Namespace)
	if err != nil {
		return fail(err)
	}

	if generation != p.info.TunnelGeneration || l.candidateGenerationContradicted {
		return fail(errors.New("tunnel generation changed"))
	}

	pin, err := l.multiProbes.MultiProbePolicyPin()
	if err != nil {
		return fail(err)
	}

	if pin.String() != p.info.IdentIPv4 {
		return fail(errors.New("probe policy changed"))
	}

	expected, err := helperauth.NewGenerationProbeIntent(p.info.ProfileID, p.info.Namespace, p.info.IdentIPv4,
		p.info.TunnelGeneration)
	if err != nil {
		return fail(err)
	}

	startedAt := time.Now()

	// A renewal must complete before the previous health expires.
	deadline := startedAt.Add(egressMonitorBudget)
	if p.monitor.expiresAt.Before(deadline) {
		deadline = p.monitor.expiresAt
	}

	if !p.monitor.fresh(startedAt) || !startedAt.Before(deadline) {
		return fail(errors.New("monitor deadline expired"))
	}

	probeCtx, cancel := context.WithDeadline(ctx, deadline)
	observation, err := l.probeMonitoredGenerationLocked(probeCtx, p, lab.Namespace, expected.TunnelGeneration)
	probeErr := probeCtx.Err()
	cancel()

	finishedAt := time.Now()

	if err != nil {
		return fail(err)
	}

	if probeErr != nil {
		return fail(probeErr)
	}

	if observation.TunnelGeneration != expected.TunnelGeneration {
		if observation.TunnelGeneration != "" {
			l.candidateGenerationContradicted = true
		}

		return fail(errors.New("observation generation mismatch"))
	}

	if observation.IPv4 != p.info.IPv4 {
		return fail(errors.New("reserved egress IP changed"))
	}

	info := MultiProbeInfo{ProfileID: lab.ProfileID, Namespace: lab.Namespace, MultiProbeObservation: observation}

	if !validMultiProbeObservation(&info, &expected) || !multiProbeWithin(&info, startedAt, finishedAt) ||
		!evidenceClockStable(startedAt, finishedAt) {
		return fail(errors.New("invalid monitor observation"))
	}

	current, err := l.currentGenerationLocked(lab.Namespace)
	if err != nil {
		return fail(err)
	}

	if current != expected.TunnelGeneration || l.candidateGenerationContradicted {
		return fail(errors.New("generation changed during monitor"))
	}

	checkedAt := time.Now()
	age := checkedAt.Sub(observation.ObservedAt)

	if !evidenceClockStable(startedAt, checkedAt) || !p.monitor.fresh(checkedAt) || !checkedAt.Before(deadline) ||
		age < 0 || age >= verifiedProbeEvidenceTTL {
		return fail(errors.New("monitor renewal expired"))
	}

	expiresAt := startedAt.Add(verifiedProbeEvidenceTTL)
	if observedDeadline := checkedAt.Add(verifiedProbeEvidenceTTL - age); observedDeadline.Before(expiresAt) {
		expiresAt = observedDeadline
	}

	p.monitor = egressMonitorHealth{observedAt: observation.ObservedAt, checkedAt: checkedAt, expiresAt: expiresAt}

	renewed := p.info

	return &renewed, nil
}

// RunEgressMonitor runs until ctx ends. Only the helper's startup owns it. It ticks every second
// but probes only when the health is due.
func (l *LabLifecycle) RunEgressMonitor(ctx context.Context) {
	ticker := time.NewTicker(egressMonitorTick)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return

		case <-ticker.C:
			if err := l.monitorPreparedOnce(ctx); err != nil {
				logDetached("Egress monitor fault: %v", err)
			}
		}
	}
}
