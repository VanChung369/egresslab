package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"sync/atomic"
	"time"

	"github.com/VanChung369/egresslab/services/controller/internal/control"
	"github.com/VanChung369/egresslab/services/controller/internal/labruntime"
)

// recoveryPolicy is what the operator approved, with -approve -recover, for one serve-endpoint
// process: how many automatic attempts it may make in total, and whether the address must stay the
// same. Nothing else is recovered automatically.
type recoveryPolicy struct {
	enabled  bool
	sameIP   bool
	attempts int
}

const recoveryMaxAttempts = 20

// Spacing of the supervisor; variables so that tests can shorten them.
var (
	recoveryPoll       = 5 * time.Second
	recoveryBackoff    = 30 * time.Second
	recoveryMaxBackoff = 5 * time.Minute
	recoveryProbes     = 4 // probe attempts per new tunnel while a source gives no answer
	recoveryProbeGap   = 5 * time.Second
	recoveryUnreadable = 3           // consecutive unreadable polls before the endpoint stops
	recoveryReleases   = 6           // release attempts while the journal is busy or the release unconfirmed
	recoveryReleaseGap = time.Second // doubled after each, so the helper's tunnel cleanup can finish
	recoveryOpTimeout  = 300 * time.Second
	errAddressChanged  = errors.New("the recovered route has another address")

	// releaseHold is releaseEgress; tests stand in for a busy journal.
	releaseHold         = (*session).releaseEgress
	errRecoveryExceeded = errors.New("automatic recovery attempts exhausted")
)

func logRecovery(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "serve-endpoint: recovery: "+format+"\n", args...)
}

// superviseEndpoint watches the served route and replaces it after a fault. It returns only when the
// endpoint must stop: ctx ended (nil), or anything it may not recover from automatically.
func (s *session) superviseEndpoint(ctx context.Context, endpointID string, authority *control.ReservationAuthority,
	current *atomic.Pointer[endpointLive], policy recoveryPolicy) error {
	used := 0
	unreadable := 0

	tick := time.NewTicker(recoveryPoll)
	defer tick.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-tick.C:
		}

		live := current.Load()

		state, err := s.routeState(ctx, live.plan)

		var terminal *recoveryStop
		if errors.As(err, &terminal) {
			return err
		}

		if err != nil {
			if ctx.Err() != nil {
				return nil
			}

			if unreadable++; unreadable >= recoveryUnreadable {
				return fmt.Errorf("route unreadable: %w", err)
			}

			continue
		}

		unreadable = 0

		switch state {
		case control.LabTunnelConfigured:
			continue
		case control.LabFaulted:
		default:
			return fmt.Errorf("lab is %s: automatic recovery only follows a fault", state)
		}

		// Nothing new is admitted until the route is replaced; the helper already closed the streams.
		current.Store(nil)

		// With no attempt left, nothing is released or deleted: the operator decides.
		if used >= policy.attempts {
			logRecovery("lab faulted; no attempt left, the faulted hold and lab are left as they are")
			return errRecoveryExceeded
		}

		logRecovery("lab faulted; new connections are refused until the route is replaced")

		next, err := s.recoverEndpoint(ctx, endpointID, authority, live, policy, &used)
		if err != nil {
			logRecovery("stopped: %v", err)
			return err
		}

		current.Store(next)
		logRecovery("route replaced: reservation %s, same address %t, attempts used %d of %d",
			next.plan.ReservationID, next.hold.IPv4 == live.hold.IPv4, used, policy.attempts)
	}
}

// recoveryStop is a reading the endpoint may not recover from.
type recoveryStop struct{ err error }

func (e *recoveryStop) Error() string { return e.err.Error() }
func (e *recoveryStop) Unwrap() error { return e.err }

// routeState reads the served lab's state from the helper that prepared its hold. Another helper
// epoch, runtime or key, or a missing lab, stops the endpoint; a failed read may be transient.
func (s *session) routeState(ctx context.Context, plan endpointPlan) (string, error) {
	transport := s.provider.Transport()

	readCtx, cancel := context.WithTimeout(ctx, proxySetupTimeout)
	defer cancel()

	info, err := transport.HelperInfo(readCtx)
	if err != nil {
		return "", err
	}

	if !info.Valid() || !info.AuthorizationConfigured || info.RuntimeID != plan.Owner.RuntimeID ||
		info.HelperID != plan.Owner.HelperEpoch || info.PublicKeySHA256 != plan.PublicKeySHA256 {
		return "", &recoveryStop{labruntime.Errorf(labruntime.CodeRuntimeUntrusted,
			"the helper that prepared the reservation is gone; release it with recover-egress after a reboot")}
	}

	labs, err := transport.ListLabs(readCtx)
	if err != nil {
		return "", err
	}

	for _, lab := range labs {
		if lab.ProfileID == plan.ProfileID {
			if lab.Namespace != plan.Owner.Namespace {
				return "", &recoveryStop{labruntime.Errorf(labruntime.CodeOwnershipMismatch, "the profile's lab changed")}
			}

			return lab.State, nil
		}
	}

	return "", &recoveryStop{labruntime.Errorf(labruntime.CodeLabNotFound, "the served lab is gone")}
}

// operation is a session for one recovery step, with the CLI's own bound.
func (s *session) operation(ctx context.Context) (*session, context.CancelFunc) {
	opCtx, cancel := context.WithTimeout(ctx, recoveryOpTimeout)
	op := *s
	op.ctx = opCtx

	return &op, cancel
}

// recoverEndpoint releases the faulted hold, then builds and reserves a new route as the policy
// allows. Any release failure, uncertain state or exhausted budget stops it, leaving what it holds.
func (s *session) recoverEndpoint(ctx context.Context, endpointID string, authority *control.ReservationAuthority,
	faulted *endpointLive, policy recoveryPolicy, used *int) (*endpointLive, error) {
	profileID := faulted.plan.ProfileID

	released, err := s.releaseFaulted(ctx, faulted.plan.ReservationID)
	if err != nil {
		return nil, fmt.Errorf("release of the faulted hold: %w", err)
	}

	if !released.RevokedLease.GenerationRetired {
		return nil, errors.New("the faulted hold was released without a retired generation")
	}

	logRecovery("faulted hold released")

	op, cancel := s.operation(ctx)
	_, err = op.existingLab(profileID, faulted.plan.Owner.Namespace, "delete-lab")
	cancel()

	if err != nil {
		return nil, fmt.Errorf("delete the faulted lab: %w", err)
	}

	backoff := recoveryBackoff

	for {
		if *used >= policy.attempts {
			return nil, errRecoveryExceeded
		}

		*used++

		next, namespace, err := s.recoveryAttempt(ctx, endpointID, authority, faulted, policy)
		if err == nil {
			return next, nil
		}

		if recoveryTerminal(err) || ctx.Err() != nil {
			return nil, err
		}

		logRecovery("attempt %d of %d failed: %v", *used, policy.attempts, err)

		// At once, not after the backoff: the lab this attempt left must not outlive it.
		if namespace != "" {
			if err := s.dropLeftover(ctx, authority, profileID, namespace); err != nil {
				return nil, err
			}
		}

		timer := time.NewTimer(backoff)

		select {
		case <-ctx.Done():
			timer.Stop()
			return nil, ctx.Err()
		case <-timer.C:
		}

		if backoff *= 2; backoff > recoveryMaxBackoff {
			backoff = recoveryMaxBackoff
		}
	}
}

// releaseAgain: release outcomes that release-egress documents as "confirm with a new release". A
// busy journal comes from another reader of it; an unconfirmed revocation from the helper still
// cleaning up the tunnel it faulted (it reports the fault first); an unconfirmed release from a
// durable write after a confirmed retirement. The helper confirms only a generation really retired.
var releaseAgain = map[string]bool{
	codeReservationBusy: true, codeReservationReleaseUnconfirmed: true, codeLeaseRevocationUnconfirmed: true,
}

// dropLeftover deletes a lab a failed attempt left, unless a hold for the profile appeared meanwhile:
// that lab may then carry someone else's reservation.
func (s *session) dropLeftover(ctx context.Context, authority *control.ReservationAuthority, profileID, namespace string) error {
	holds, err := authority.List()
	if err != nil {
		return &recoveryStop{fmt.Errorf("list holds before deleting a lab: %w", err)}
	}

	for _, hold := range holds {
		if hold.Owner.ProfileID == profileID {
			return &recoveryStop{fmt.Errorf("a hold for the profile exists (%s); its lab is left", hold.ID)}
		}
	}

	op, cancel := s.operation(ctx)
	defer cancel()

	if _, err := op.existingLab(profileID, namespace, "delete-lab"); err != nil {
		return &recoveryStop{fmt.Errorf("delete lab: %w", err)}
	}

	return nil
}

// releaseFaulted releases the faulted hold, asking again for the outcomes in releaseAgain.
func (s *session) releaseFaulted(ctx context.Context, reservationID string) (reservationReleaseCommandResult, error) {
	for i := 1; ; i++ {
		op, cancel := s.operation(ctx)
		released, err := releaseHold(op, reservationID, false)
		cancel()

		code := labruntime.ErrorCode(err)
		if err == nil || !releaseAgain[code] || i >= recoveryReleases {
			return released, err
		}

		logRecovery("release attempt %d unconfirmed (%s); asking again", i, code)

		timer := time.NewTimer(recoveryReleaseGap << (i - 1))

		select {
		case <-ctx.Done():
			timer.Stop()
			return reservationReleaseCommandResult{}, ctx.Err()
		case <-timer.C:
		}
	}
}

// recoveryTerminal: outcomes after which nothing may be retried automatically.
func recoveryTerminal(err error) bool {
	var stop *recoveryStop
	if errors.As(err, &stop) {
		return true
	}

	switch labruntime.ErrorCode(err) {
	case labruntime.CodeStateUncertain, labruntime.CodeRuntimeUntrusted, labruntime.CodeOwnershipMismatch,
		labruntime.CodeAuthorizationDenied, labruntime.CodeLabLimit, codeLeasePreparationUnconfirmed, codeReservationJournalCorrupt,
		codeReservationAuthorityMismatch, codeReservationUnavailable, codeReservationLimit, codeReservationHeld,
		codeReservationReleaseUnconfirmed, codeLeaseRevocationUnconfirmed:
		return true
	}

	return false
}

// recoveryAttempt creates, connects and probes a new tunnel, applies the address policy before any
// hold is made, then reserves it. It returns the namespace it leaves behind on failure.
func (s *session) recoveryAttempt(ctx context.Context, endpointID string, authority *control.ReservationAuthority,
	faulted *endpointLive, policy recoveryPolicy) (*endpointLive, string, error) {
	profileID := faulted.plan.ProfileID

	if err := s.attemptPreflight(ctx, endpointID, faulted); err != nil {
		return nil, "", err
	}

	op, cancel := s.operation(ctx)
	defer cancel()

	lab, err := op.createLab(profileID)
	if err != nil {
		return nil, "", fmt.Errorf("create lab: %w", err)
	}

	namespace := lab.Namespace

	stage, err := op.stageInfo(profileID)
	if err != nil {
		return nil, namespace, fmt.Errorf("stage: %w", err)
	}

	if _, err := op.connectTunnel(profileID, namespace, stage.StageID); err != nil {
		return nil, namespace, fmt.Errorf("connect tunnel: %w", err)
	}

	var probe control.LabMultiProbeInfo

	for i := 1; ; i++ {
		probe, err = op.probeEgressMulti(profileID, namespace)
		if err == nil {
			break
		}

		if labruntime.ErrorCode(err) != labruntime.CodeEvidenceUnavailable || i >= recoveryProbes {
			return nil, namespace, fmt.Errorf("probe: %w", err)
		}

		timer := time.NewTimer(recoveryProbeGap)

		select {
		case <-ctx.Done():
			timer.Stop()
			return nil, namespace, ctx.Err()
		case <-timer.C:
		}
	}

	// Before any hold: a different address costs no reservation.
	if policy.sameIP && probe.IPv4 != faulted.hold.IPv4 {
		return nil, namespace, errAddressChanged
	}

	// Another reader of the journal can make it busy; a new reserve runs its own verification, and the
	// helper drops the earlier attempt's evidence.
	var reserved reservationCommandResult

	for i := 1; ; i++ {
		reserved, err = op.reserveEgress(profileID, namespace)
		if err == nil {
			break
		}

		if labruntime.ErrorCode(err) != codeReservationBusy || i >= recoveryReleases {
			return nil, namespace, fmt.Errorf("reserve: %w", err)
		}

		timer := time.NewTimer(recoveryReleaseGap)

		select {
		case <-ctx.Done():
			timer.Stop()
			return nil, namespace, ctx.Err()
		case <-timer.C:
		}
	}

	logRecovery("new hold %s prepared", reserved.Reservation.ID)

	if policy.sameIP && reserved.Reservation.IPv4 != faulted.hold.IPv4 {
		if _, err := op.releaseEgress(reserved.Reservation.ID, false); err != nil {
			return nil, namespace, &recoveryStop{fmt.Errorf("release of a hold with another address: %w", err)}
		}

		return nil, namespace, errAddressChanged
	}

	plan, err := readEndpointPlan(s.dataDir, endpointID, authority)
	if err != nil {
		return nil, namespace, &recoveryStop{fmt.Errorf("read the recovered route: %w", err)}
	}

	if plan.ReservationID != reserved.Reservation.ID || plan.Owner.HelperEpoch != faulted.plan.Owner.HelperEpoch {
		return nil, namespace, &recoveryStop{errors.New("the recovered route names another hold or helper")}
	}

	if err := s.requirePreparingHelper(ctx, plan); err != nil {
		return nil, namespace, &recoveryStop{err}
	}

	live, err := s.endpointLive(endpointID, plan, authority)
	if err != nil {
		return nil, namespace, &recoveryStop{err}
	}

	return live, "", nil
}

// attemptPreflight: the endpoint, its runtime's trust and the helper epoch must still be those the
// recovery was approved for; anything else stops it before a lab is made.
func (s *session) attemptPreflight(ctx context.Context, endpointID string, faulted *endpointLive) error {
	route, err := readEndpointRoute(s.dataDir, endpointID)
	if err != nil {
		return &recoveryStop{fmt.Errorf("endpoint: %w", err)}
	}

	if route.ProfileID != faulted.plan.ProfileID || route.RuntimeID != faulted.plan.RuntimeID ||
		route.Provider != faulted.plan.Provider || route.Target != faulted.plan.Target ||
		route.PublicKeySHA256 != faulted.plan.PublicKeySHA256 {
		return &recoveryStop{errors.New("the endpoint or its runtime changed")}
	}

	readCtx, cancel := context.WithTimeout(ctx, proxySetupTimeout)
	info, err := s.provider.Transport().HelperInfo(readCtx)
	cancel()

	if err != nil {
		return fmt.Errorf("helper: %w", err)
	}

	if !info.Valid() || !info.AuthorizationConfigured || info.RuntimeID != faulted.plan.Owner.RuntimeID ||
		info.HelperID != faulted.plan.Owner.HelperEpoch || info.PublicKeySHA256 != faulted.plan.PublicKeySHA256 {
		return &recoveryStop{labruntime.Errorf(labruntime.CodeRuntimeUntrusted, "the helper changed during the recovery")}
	}

	return nil
}
