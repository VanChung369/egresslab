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

// ErrManagedClockStepped: the wall clock moved apart from monotonic time during an attempt, so its
// timestamps prove nothing. It says nothing about the egress either: an attempt that fails for this
// reason alone yields nothing and leaves the tunnel, like a source without an answer.
var ErrManagedClockStepped = fmt.Errorf("%w: wall clock stepped during the attempt", ErrInvalidObservation)

const managedClockStepReason = "WALL_CLOCK_STEPPED"

// managedClockStep refuses a reading whose wall-clock progress since the start of the attempt
// differs from its monotonic progress by more than maxManagedClockStep.
func managedClockStep(startWall time.Time, startMono time.Duration, wall time.Time, mono time.Duration) error {
	step := wall.Sub(startWall) - (mono - startMono)
	if step > maxManagedClockStep || step < -maxManagedClockStep {
		return ErrManagedClockStepped
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
// attempt starts, any failure discards every observation, faults the tunnel and removes it; only a
// source without an answer, a clock step alone, or on a pinned generation one source's TLS handshake
// cut short while every other source answers the pin, leaves it (ErrManagedProbeSourceUnavailable).
// All timestamps are wall-clock UTC, checked against monotonic time.
func (b *ManagedTunnelBackend) ProbeConfiguredMulti(
	ctx context.Context,
	namespace string,
) (ManagedMultiProbeObservation, error) {
	return b.probeConfiguredMulti(ctx, namespace, "", nil)
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

	return b.probeConfiguredMulti(ctx, namespace, generation, nil)
}

// ProbeConfiguredMultiForGenerationWithOverlay is ProbeConfiguredMultiForGeneration for the egress
// monitor of a generation whose proxy streams are running: each window also carries the traffic
// overlay while it is eligible, so those streams keep flowing. The overlay comes from the trusted
// data plane only.
func (b *ManagedTunnelBackend) ProbeConfiguredMultiForGenerationWithOverlay(
	ctx context.Context,
	namespace, generation string,
	overlay MonitorTrafficOverlay,
) (ManagedMultiProbeObservation, error) {
	if generation == "" {
		return ManagedMultiProbeObservation{}, ErrManagedTunnelGenerationMismatch
	}

	return b.probeConfiguredMulti(ctx, namespace, generation, &overlay)
}

func (b *ManagedTunnelBackend) probeConfiguredMulti(
	ctx context.Context,
	namespace, expectedGeneration string,
	overlay *MonitorTrafficOverlay,
) (observation ManagedMultiProbeObservation, resultErr error) {
	b.sealed.manager.mu.Lock()
	defer b.sealed.manager.mu.Unlock()

	unanswered := false

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
		if managedClockStep(startedAt, startMono, wall, mono) != nil ||
			managedClockStep(lastWall, lastMono, wall, mono) != nil || wall.Before(lastWall) {
			return time.Time{}, ErrManagedClockStepped
		}

		lastWall, lastMono = wall, mono

		return wall, nil
	}

	ctx, cancel := context.WithTimeout(ctx, maxManagedVerificationSpan)
	defer cancel()

	defer func() {
		if resultErr == nil || unanswered {
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

	// A source whose handshake was cut short, which faults unless every other source answers the pin.
	var interrupted error
	var interruptedSource string

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

		var noAnswer string

		var cut error

		err := b.sealed.firewall.withMonitoredProbeWindowLocked(ctx, namespace, source.destination, overlay,
			func(probeCtx context.Context) error {
				body, err := config.run(probeCtx, namespace, source)
				if errors.Is(err, ErrManagedProbeNoAnswer) {
					noAnswer = managedProbeReasonOf(err)
					return ErrManagedProbeNoAnswer
				}

				// The worker's own failure only, nothing wrapped around it.
				if failure, ok := err.(*managedProbeSourceFailure); ok && managedProbeReasons[failure.reason].confirmable {
					cut = err
				}

				if err != nil {
					return err
				}

				ip, err := parseManagedProbeBody(source, body)
				if err != nil {
					return err
				}

				// A pinned generation that one source sees elsewhere is lost: no other source is asked.
				if t.expectedIPv4.IsValid() && ip != t.expectedIPv4 {
					return ErrManagedStickyIPChanged
				}

				// Before the clock is read, so that a step cannot hide a disagreement.
				if len(samples) > 0 && ip != samples[0].ipv4 {
					return ErrManagedProbeIPMismatch
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
		if onlyCause(err, ErrManagedClockStepped) {
			noAnswer = managedClockStepReason
			err = ErrManagedProbeNoAnswer
		}

		// The handshake was cut short and its window closed as opened. Only on a pinned generation, and
		// only once per attempt, do the other sources get to outweigh it: each must answer the pin.
		if cut != nil && onlyCause(err, cut) {
			if !t.expectedIPv4.IsValid() || interrupted != nil {
				return ManagedMultiProbeObservation{}, errors.Join(interrupted, fmt.Errorf("source %s: %w", source.id, err))
			}

			if err := b.requireIdleProbeNamespaceLocked(ctx, namespace); err != nil {
				return ManagedMultiProbeObservation{}, err
			}

			if err := b.verifyConfiguredLocked(ctx, t); err != nil {
				return ManagedMultiProbeObservation{}, err
			}

			interrupted, interruptedSource = fmt.Errorf("source %s: %w", source.id, err), source.id

			continue
		}

		// The source gave no answer, or the clock stepped, and its window closed as opened: with the
		// worker gone and the tunnel as staged, the attempt yields nothing and the tunnel stays. After
		// a handshake cut short, the pin is unconfirmed and the attempt faults.
		if onlyCause(err, ErrManagedProbeNoAnswer) {
			if interrupted != nil {
				return ManagedMultiProbeObservation{}, fmt.Errorf("%w; source %s unconfirmed (%s)", interrupted,
					source.id, noAnswer)
			}

			if err := b.requireIdleProbeNamespaceLocked(ctx, namespace); err != nil {
				return ManagedMultiProbeObservation{}, err
			}

			if err := b.verifyConfiguredLocked(ctx, t); err != nil {
				return ManagedMultiProbeObservation{}, err
			}

			if err := ctx.Err(); err != nil {
				return ManagedMultiProbeObservation{}, err
			}

			unanswered = true

			return ManagedMultiProbeObservation{}, fmt.Errorf("source %s: %w (%s)", source.id,
				ErrManagedProbeSourceUnavailable, noAnswer)
		}

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

	// Every window is closed and the tunnel was verified after the last one. Across a step, the
	// handshake's age cannot be judged, but its peer and format still can.
	finishedAt, err := stamp()
	if err != nil {
		// Across a step the handshake's age is unknown, which a cut handshake cannot be excused with.
		if interrupted != nil {
			return ManagedMultiProbeObservation{}, errors.Join(interrupted, err)
		}

		if _, err := parseManagedHandshakeSeconds(raw, t.peer.peerPublicKey); err != nil {
			return ManagedMultiProbeObservation{}, err
		}

		if err := ctx.Err(); err != nil {
			return ManagedMultiProbeObservation{}, err
		}

		unanswered = true

		return ManagedMultiProbeObservation{}, fmt.Errorf("%w (%s)", ErrManagedProbeSourceUnavailable,
			managedClockStepReason)
	}

	// Judged at the same checked reading as FinishedAt, so the handshake cannot postdate it.
	handshake, err := parseManagedHandshake(raw, t.peer.peerPublicKey, finishedAt)
	if err != nil {
		return ManagedMultiProbeObservation{}, err
	}

	if err := ctx.Err(); err != nil {
		return ManagedMultiProbeObservation{}, err
	}

	// Every other source answered the pin in its own window: the cut handshake says nothing about the
	// egress. The attempt yields nothing and renews nothing, so a cut that keeps recurring still ends
	// the monitor's health.
	if interrupted != nil {
		if len(samples) != len(sources)-1 {
			return ManagedMultiProbeObservation{}, errors.Join(interrupted, ErrManagedProbeEvidenceIncomplete)
		}

		for _, sample := range samples {
			if sample.ipv4 != t.expectedIPv4 {
				return ManagedMultiProbeObservation{}, errors.Join(interrupted, ErrManagedStickyIPChanged)
			}
		}

		unanswered = true

		return ManagedMultiProbeObservation{}, fmt.Errorf("source %s: %w (%s, pin confirmed by %d other)",
			interruptedSource, ErrManagedProbeSourceUnavailable, managedProbeReasonOf(interrupted), len(samples))
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

// onlyCause reports whether err is target, or joins nothing but target.
func onlyCause(err, target error) bool {
	if err == target {
		return true
	}

	joined, ok := err.(interface{ Unwrap() []error })
	if !ok || len(joined.Unwrap()) == 0 {
		return false
	}

	for _, cause := range joined.Unwrap() {
		if !onlyCause(cause, target) {
			return false
		}
	}

	return true
}
