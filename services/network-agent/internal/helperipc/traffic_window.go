package helperipc

import (
	"context"
	"errors"
	"net/netip"
	"time"
)

// trafficWindowMinHealth covers the kernel timeout, the close budget and the backend's checks
// before the gate opens.
const trafficWindowMinHealth = 14 * time.Second

// ErrTrafficWindowTooLate: the backend found too little health left before it opened anything.
var ErrTrafficWindowTooLate = errors.New("too little monitoring health left for a traffic window")

type trafficWindowBackend interface {
	WithTrafficWindow(
		ctx context.Context,
		namespace, generation string,
		expectedIP netip.Addr,
		uid uint32,
		healthUntil time.Time,
		run func(context.Context) error,
	) error
}

// WithPreparedTrafficWindow opens the kernel-timed data-plane gate for the prepared reservation's
// exact generation and address, only on fresh monitoring health, and never past the next monitor
// check. It is reserved for the trusted data plane: uid comes from local provisioning, never from
// an application or IPC request. A failed window faults the tunnel; the durable hold stays.
func (l *LabLifecycle) WithPreparedTrafficWindow(
	ctx context.Context,
	reservationID string,
	uid uint32,
	run func(context.Context) error,
) error {
	if l == nil || ctx.Err() != nil || uid == 0 || uid == ^uint32(0) || run == nil {
		return errLabInvalid
	}

	if !l.mu.TryLock() {
		return errLabBusy
	}
	defer l.mu.Unlock()

	p := l.preparedLease

	if l.closed || p == nil || p.info.ReservationID != reservationID {
		return errLabAuthorization
	}

	lab, exists := l.labs[p.info.ProfileID]

	if !exists || lab.Namespace != p.info.Namespace || l.tunnelProfile != p.info.ProfileID {
		l.blockCreation = true
		l.invalidateEvidenceLocked(p.info.ProfileID)

		return errLabUncertain
	}

	if l.blockCreation || lab.State != LabTunnelConfigured || !p.info.valid() {
		return l.faultMonitoredTunnelLocked(lab, errLabUncertain)
	}

	now := time.Now()

	if !p.monitor.fresh(now) {
		return l.faultMonitoredTunnelLocked(lab, errEvidenceUnavailable)
	}

	// The monitor goes first.
	if p.monitor.due(now) {
		return errLabBusy
	}

	backend, ok := l.generationProbes.(trafficWindowBackend)
	if !ok {
		return errLabUnavailable
	}

	generation, err := l.currentGenerationLocked(lab.Namespace)
	if err != nil || generation != p.info.TunnelGeneration || l.candidateGenerationContradicted {
		return l.faultMonitoredTunnelLocked(lab, errLabUncertain)
	}

	// Never occupy the lifecycle past the next monitor check, as the monitor computes it.
	healthUntil := p.monitor.nextDue()

	if healthUntil.Sub(now) <= trafficWindowMinHealth {
		return errLabBusy
	}

	err = backend.WithTrafficWindow(ctx, lab.Namespace, p.info.TunnelGeneration, p.info.IPv4, uid, healthUntil, run)

	// Refused before anything was opened: the monitor goes first, the tunnel stays.
	if errors.Is(err, ErrTrafficWindowTooLate) {
		return errLabBusy
	}

	if err != nil {
		return l.faultMonitoredTunnelLocked(lab, err)
	}

	return nil
}
