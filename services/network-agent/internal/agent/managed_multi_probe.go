package agent

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"time"
)

type managedMultiProbeRunner func(ctx context.Context, namespace string, source managedProbeHTTPSource) ([]byte, error)

type managedMultiProbeConfig struct {
	identPin netip.Addr
	run      managedMultiProbeRunner
	clock    managedProbeClock
}

// maxManagedClockStep is how far wall-clock time may move apart from monotonic time during one
// attempt; NTP slewing stays far below it.
const maxManagedClockStep = time.Second

// managedProbeClock reads wall-clock time and monotonic time, elapsed since an arbitrary origin.
type managedProbeClock func() (wall time.Time, monotonic time.Duration)

func systemManagedProbeClock() managedProbeClock {
	origin := time.Now()

	return func() (time.Time, time.Duration) {
		now := time.Now()
		return now.UTC(), now.Sub(origin)
	}
}

// managedClockStep refuses a reading whose wall-clock progress since the start of the attempt
// differs from its monotonic progress by more than maxManagedClockStep.
func managedClockStep(startWall time.Time, startMono time.Duration, wall time.Time, mono time.Duration) error {
	step := wall.Sub(startWall) - (mono - startMono)
	if step > maxManagedClockStep || step < -maxManagedClockStep {
		return fmt.Errorf("%w: wall clock stepped during the attempt", ErrInvalidObservation)
	}

	return nil
}

// ManagedProbeSourceObservation is one source's part of a managed verification attempt.
type ManagedProbeSourceObservation struct {
	Source          string     `json:"source"`
	DestinationIPv4 netip.Addr `json:"destination_ipv4"`
	IPv4            netip.Addr `json:"ipv4"`
	ObservedAt      time.Time  `json:"observed_at"`
}

// ManagedMultiProbeObservation is unanimous diagnostic evidence from every mandatory source.
// ObservedAt is the oldest source observation. It authorizes no lease and no application traffic.
type ManagedMultiProbeObservation struct {
	TunnelGeneration string `json:"tunnel_generation"`

	IPv4        netip.Addr `json:"ipv4"`
	StartedAt   time.Time  `json:"started_at"`
	FinishedAt  time.Time  `json:"finished_at"`
	ObservedAt  time.Time  `json:"observed_at"`
	HandshakeAt time.Time  `json:"handshake_at"`

	Sources []ManagedProbeSourceObservation `json:"sources"`

	NetworkReady bool `json:"network_ready"`
}

// MultiProbePolicyPin returns the ident.me pin of the configured source policy. The policy is fixed
// when the backend is built and never comes from an IPC request.
func (b *ManagedTunnelBackend) MultiProbePolicyPin() (netip.Addr, error) {
	if b == nil || b.sealed == nil || b.sealed.manager == nil {
		return netip.Addr{}, ErrManagedProbeUnavailable
	}

	b.sealed.manager.mu.Lock()
	defer b.sealed.manager.mu.Unlock()

	config := b.multiProbe
	if config == nil || config.run == nil {
		return netip.Addr{}, ErrManagedProbeUnavailable
	}

	if _, err := managedProbeHTTPSources(config.identPin); err != nil {
		return netip.Addr{}, err
	}

	return config.identPin, nil
}

// ProbeConfiguredMulti observes the tunnel's public IPv4 address from every mandatory source, one
// after another, through the same configured tunnel and within one 80 s deadline. manager.mu is
// held throughout, so no backend operation can change the tunnel between two observations. The
// caller must already have authorized the operation.
//
// Each source gets its own kernel-timed window, closed and verified before the next one opens; the
// tunnel and the namespace process inventory are verified before and after every window. Once the
// attempt starts, any failure discards every observation, faults the tunnel and removes it. All
// timestamps are wall-clock UTC, checked against monotonic time: a clock step fails the attempt.
func (b *ManagedTunnelBackend) ProbeConfiguredMulti(
	ctx context.Context,
	namespace string,
) (ManagedMultiProbeObservation, error) {
	return b.probeConfiguredMulti(ctx, namespace, "")
}

// ProbeConfiguredMultiForGeneration is ProbeConfiguredMulti for exactly one tunnel generation,
// checked under the same lock as the attempt itself, so the tunnel cannot change in between. A
// mismatch is refused before anything starts and leaves the tunnel as it is.
func (b *ManagedTunnelBackend) ProbeConfiguredMultiForGeneration(
	ctx context.Context,
	namespace, generation string,
) (ManagedMultiProbeObservation, error) {
	if generation == "" {
		return ManagedMultiProbeObservation{}, ErrManagedTunnelGenerationMismatch
	}

	return b.probeConfiguredMulti(ctx, namespace, generation)
}

func (b *ManagedTunnelBackend) probeConfiguredMulti(
	ctx context.Context,
	namespace, expectedGeneration string,
) (observation ManagedMultiProbeObservation, resultErr error) {
	b.sealed.manager.mu.Lock()
	defer b.sealed.manager.mu.Unlock()

	config := b.multiProbe
	if config == nil || config.run == nil {
		return ManagedMultiProbeObservation{}, ErrManagedProbeUnavailable
	}

	sources, err := managedProbeHTTPSources(config.identPin)
	if err != nil {
		return ManagedMultiProbeObservation{}, err
	}

	t := b.active
	if t == nil || t.namespace != namespace {
		return ManagedMultiProbeObservation{}, ErrNoManagedTunnel
	}

	if t.faulted || t.linkRemoved {
		return ManagedMultiProbeObservation{}, ErrManagedTunnelUncertain
	}

	if expectedGeneration != "" && expectedGeneration != t.generation {
		return ManagedMultiProbeObservation{}, ErrManagedTunnelGenerationMismatch
	}

	if err := ctx.Err(); err != nil {
		return ManagedMultiProbeObservation{}, err
	}

	clock := config.clock
	if clock == nil {
		clock = systemManagedProbeClock()
	}

	startedAt, startMono := clock()
	lastWall, lastMono := startedAt, startMono

	// Each reading is checked against the start and the previous reading, and never goes backwards.
	stamp := func() (time.Time, error) {
		wall, mono := clock()
		if err := errors.Join(
			managedClockStep(startedAt, startMono, wall, mono),
			managedClockStep(lastWall, lastMono, wall, mono),
		); err != nil {
			return time.Time{}, err
		}

		if wall.Before(lastWall) {
			return time.Time{}, fmt.Errorf("%w: wall clock went backwards during the attempt", ErrInvalidObservation)
		}

		lastWall, lastMono = wall, mono

		return wall, nil
	}

	ctx, cancel := context.WithTimeout(ctx, maxManagedVerificationSpan)
	defer cancel()

	defer func() {
		if resultErr == nil {
			return
		}

		observation = ManagedMultiProbeObservation{}
		t.faulted = true
		resultErr = errors.Join(ErrManagedProbeFailed, resultErr)

		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), managedTunnelCleanupTimeout)
		defer cleanupCancel()

		if err := b.disconnectLocked(cleanupCtx, t); err != nil {
			resultErr = errors.Join(resultErr, ErrManagedTunnelUncertain, err)
		}
	}()

	if err := b.verifyConfiguredLocked(ctx, t); err != nil {
		return ManagedMultiProbeObservation{}, err
	}

	// The consensus is judged against the whole mandatory policy, not the sources that answered.
	specs := make([]managedProbeSourceSpec, 0, len(sources))
	for _, source := range sources {
		specs = append(specs, source.managedProbeSourceSpec)
	}

	samples := make([]managedProbeSample, 0, len(sources))
	evidence := make([]ManagedProbeSourceObservation, 0, len(sources))

	for _, source := range sources {
		if err := ctx.Err(); err != nil {
			return ManagedMultiProbeObservation{}, err
		}

		if err := b.requireIdleProbeNamespaceLocked(ctx, namespace); err != nil {
			return ManagedMultiProbeObservation{}, err
		}

		// The full verification looks up only 1.1.1.1; this source's own pin must go through wg0 too.
		if err := b.verifyRouteSelectionLocked(ctx, t, source.destination); err != nil {
			return ManagedMultiProbeObservation{}, err
		}

		var sample managedProbeSample

		err := b.sealed.firewall.withManagedProbeWindowForLocked(ctx, namespace, source.destination,
			func(probeCtx context.Context) error {
				body, err := config.run(probeCtx, namespace, source)
				if err != nil {
					return err
				}

				ip, err := parseManagedProbeBody(source, body)
				if err != nil {
					return err
				}

				if err := probeCtx.Err(); err != nil {
					return err
				}

				observedAt, err := stamp()
				if err != nil {
					return err
				}

				sample = managedProbeSample{sourceID: source.id, ipv4: ip, observedAt: observedAt}

				return nil
			})
		if err != nil {
			return ManagedMultiProbeObservation{}, fmt.Errorf("source %s: %w", source.id, err)
		}

		// The window is closed; the worker must be gone and the whole tunnel as staged before this
		// sample counts or another window opens.
		if err := b.requireIdleProbeNamespaceLocked(ctx, namespace); err != nil {
			return ManagedMultiProbeObservation{}, err
		}

		if err := b.verifyConfiguredLocked(ctx, t); err != nil {
			return ManagedMultiProbeObservation{}, err
		}

		samples = append(samples, sample)
		evidence = append(evidence, ManagedProbeSourceObservation{
			Source:          sample.sourceID,
			DestinationIPv4: source.destination,
			IPv4:            sample.ipv4,
			ObservedAt:      sample.observedAt,
		})
	}

	raw, err := b.vpn.runWG(ctx, namespace, nil, "show", labWGInterface, "latest-handshakes")
	if err != nil {
		return ManagedMultiProbeObservation{}, ErrManagedHandshake
	}

	finishedAt, err := stamp()
	if err != nil {
		return ManagedMultiProbeObservation{}, err
	}

	// Judged at the same checked reading as FinishedAt, so the handshake cannot postdate it.
	handshake, err := parseManagedHandshake(raw, t.peer.peerPublicKey, finishedAt)
	if err != nil {
		return ManagedMultiProbeObservation{}, err
	}

	if err := ctx.Err(); err != nil {
		return ManagedMultiProbeObservation{}, err
	}

	consensus, err := verifyManagedProbeConsensus(specs, samples, startedAt, finishedAt)
	if err != nil {
		return ManagedMultiProbeObservation{}, err
	}

	if err := ctx.Err(); err != nil {
		return ManagedMultiProbeObservation{}, err
	}

	// Last, once every window is closed and the tunnel, handshake and consensus are verified, so
	// partial evidence can never set the pin; a mismatch faults the tunnel through the defer above.
	if err := b.acceptStickyConsensusLocked(t, consensus); err != nil {
		return ManagedMultiProbeObservation{}, err
	}

	return ManagedMultiProbeObservation{
		TunnelGeneration: t.generation,
		IPv4:             consensus.ipv4,
		StartedAt:        startedAt,
		FinishedAt:       finishedAt,
		ObservedAt:       consensus.observedAt,
		HandshakeAt:      handshake,
		Sources:          evidence,
	}, nil
}
