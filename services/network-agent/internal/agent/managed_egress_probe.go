package agent

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"strconv"
	"strings"
	"time"
)

// maxManagedHandshakeAge is EgressLab's freshness policy; it does not prove that the handshake
// happened for this particular request.
const maxManagedHandshakeAge = 180 * time.Second

var (
	ErrManagedProbeUnavailable = errors.New("managed probe runner unavailable")
	ErrManagedProbeFailed      = errors.New("managed egress probe failed")
	ErrManagedHandshake        = errors.New("recent WireGuard handshake not verified")

	// ErrManagedProbeNoAnswer: nothing came back from a source (no connection, TLS handshake or
	// response in time, or a reset). A response that arrived and was refused is not one.
	ErrManagedProbeNoAnswer = errors.New("probe source gave no answer")

	// ErrManagedProbeSourceUnavailable: a source gave no answer, and afterwards its window was closed,
	// the worker gone and the tunnel verified as staged. The attempt yields nothing and the tunnel
	// stays.
	ErrManagedProbeSourceUnavailable = errors.New("probe source unavailable; tunnel unchanged")
)

// ManagedProbeObservation is one observation from one source. It is not a lease and does not
// authorize any application traffic.
type ManagedProbeObservation struct {
	IPv4         netip.Addr `json:"ipv4"`
	ObservedAt   time.Time  `json:"observed_at"`
	HandshakeAt  time.Time  `json:"handshake_at"`
	Source       string     `json:"source"`
	NetworkReady bool       `json:"network_ready"`
}

// parseManagedHandshake reads "wg show wg0 latest-handshakes": exactly the expected peer, with a
// handshake that happened, not in the future and at most maxManagedHandshakeAge old.
func parseManagedHandshake(output, expectedPeer string, now time.Time) (time.Time, error) {
	fields := strings.Split(strings.TrimSpace(output), "\t")
	if len(fields) != 2 || fields[0] != expectedPeer {
		return time.Time{}, ErrManagedHandshake
	}

	seconds, err := strconv.ParseInt(fields[1], 10, 64)
	if err != nil || seconds <= 0 || strconv.FormatInt(seconds, 10) != fields[1] ||
		seconds > now.Unix() || now.Unix()-seconds > int64(maxManagedHandshakeAge/time.Second) {
		return time.Time{}, ErrManagedHandshake
	}

	return time.Unix(seconds, 0).UTC(), nil
}

// requireIdleProbeNamespaceLocked requires no process in the lab namespace: nothing may share the
// probe window, and the worker must be gone once it closes. The caller must hold manager.mu.
func (b *ManagedTunnelBackend) requireIdleProbeNamespaceLocked(ctx context.Context, namespace string) error {
	if !labNamePattern.MatchString(namespace) {
		return ErrManagedProbeFailed
	}

	if _, owned := b.sealed.manager.owned[namespace]; !owned {
		return ErrManagedProbeFailed
	}

	commandCtx, cancel := context.WithTimeout(ctx, netNSCommandTimeout)
	defer cancel()

	data, err := b.sealed.manager.run(commandCtx, "netns", "pids", namespace)
	if err != nil {
		return fmt.Errorf("%w: process inventory unavailable", ErrManagedProbeFailed)
	}

	if strings.TrimSpace(string(data)) != "" {
		return ErrNetNSBusy
	}

	return nil
}

// ProbeConfigured makes one diagnostic observation of the tunnel's public IPv4 address through a
// kernel-timed firewall window. The caller must already have authorized the operation.
//
// Once the attempt starts, any failure faults and removes the tunnel and discards the result:
// the window is closed before an observation can be returned, and the tunnel, the namespace
// process inventory and a recent handshake with the expected peer are checked again afterwards.
func (b *ManagedTunnelBackend) ProbeConfigured(
	ctx context.Context,
	namespace string,
) (observation ManagedProbeObservation, resultErr error) {
	b.sealed.manager.mu.Lock()
	defer b.sealed.manager.mu.Unlock()

	// Never on a multi-source backend, even if a single-source runner were set by mistake: its
	// evidence must not bypass the generation pin.
	if b.multiProbe != nil || b.vpn.probe == nil {
		return ManagedProbeObservation{}, ErrManagedProbeUnavailable
	}

	t := b.active
	if t == nil || t.namespace != namespace {
		return ManagedProbeObservation{}, ErrNoManagedTunnel
	}

	if t.faulted || t.linkRemoved {
		return ManagedProbeObservation{}, ErrManagedTunnelUncertain
	}

	if err := ctx.Err(); err != nil {
		return ManagedProbeObservation{}, err
	}

	defer func() {
		if resultErr == nil {
			return
		}

		observation = ManagedProbeObservation{}
		t.faulted = true
		resultErr = errors.Join(ErrManagedProbeFailed, resultErr)

		cleanupCtx, cancel := context.WithTimeout(context.Background(), managedTunnelCleanupTimeout)
		defer cancel()

		if err := b.disconnectLocked(cleanupCtx, t); err != nil {
			resultErr = errors.Join(resultErr, ErrManagedTunnelUncertain, err)
		}
	}()

	// Gate 1: the full intended tunnel state, and nothing running in the lab.
	if err := b.verifyConfiguredLocked(ctx, t); err != nil {
		return ManagedProbeObservation{}, err
	}

	if err := b.requireIdleProbeNamespaceLocked(ctx, namespace); err != nil {
		return ManagedProbeObservation{}, err
	}

	var ip netip.Addr
	var observedAt time.Time

	err := b.sealed.firewall.withManagedProbeWindowLocked(ctx, namespace, func(probeCtx context.Context) error {
		body, err := b.vpn.probe(probeCtx, namespace, DefaultEgressProbeURL)
		if err != nil {
			return err
		}

		if len(body) > maxEgressProbeBytes {
			return ErrInvalidObservation
		}

		parsed, err := parseTraceIP(body)
		if err != nil {
			return err
		}

		// The same public IPv4 policy as every egress candidate.
		if ip, err = parseCandidateIPv4(parsed.String()); err != nil {
			return err
		}

		observedAt = time.Now().UTC()

		return nil
	})
	if err != nil {
		return ManagedProbeObservation{}, err
	}

	// Gate 2: the worker has exited, and the sealed firewall and the whole tunnel are as staged.
	if err := b.requireIdleProbeNamespaceLocked(ctx, namespace); err != nil {
		return ManagedProbeObservation{}, err
	}

	if err := b.verifyConfiguredLocked(ctx, t); err != nil {
		return ManagedProbeObservation{}, err
	}

	// Gate 3: a recent handshake with exactly the expected peer.
	raw, err := b.vpn.runWG(ctx, namespace, nil, "show", labWGInterface, "latest-handshakes")
	if err != nil {
		return ManagedProbeObservation{}, ErrManagedHandshake
	}

	handshake, err := parseManagedHandshake(raw, t.peer.peerPublicKey, time.Now())
	if err != nil {
		return ManagedProbeObservation{}, err
	}

	if err := ctx.Err(); err != nil {
		return ManagedProbeObservation{}, err
	}

	return ManagedProbeObservation{
		IPv4:        ip,
		ObservedAt:  observedAt,
		HandshakeAt: handshake,
		Source:      "cloudflare_trace",
	}, nil
}
