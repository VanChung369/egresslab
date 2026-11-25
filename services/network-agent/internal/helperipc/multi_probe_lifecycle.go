package helperipc

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"time"

	"github.com/VanChung369/egresslab/services/network-agent/internal/helperauth"
)

// MultiProbeSourceObservation is one mandatory source's part of the evidence.
type MultiProbeSourceObservation struct {
	Source          string     `json:"source"`
	DestinationIPv4 netip.Addr `json:"destination_ipv4"`
	IPv4            netip.Addr `json:"ipv4"`
	ObservedAt      time.Time  `json:"observed_at"`
}

// MultiProbeObservation is diagnostic consensus evidence. It activates no lease and no traffic.
type MultiProbeObservation struct {
	// Set by the generation-bound (V2) probe only, from the agent's own tunnel.
	TunnelGeneration string `json:"tunnel_generation,omitempty"`

	IPv4        netip.Addr `json:"ipv4"`
	StartedAt   time.Time  `json:"started_at"`
	FinishedAt  time.Time  `json:"finished_at"`
	ObservedAt  time.Time  `json:"observed_at"`
	HandshakeAt time.Time  `json:"handshake_at"`

	Sources []MultiProbeSourceObservation `json:"sources"`
}

type MultiProbeInfo struct {
	ProfileID string `json:"profile_id"`
	Namespace string `json:"namespace"`

	MultiProbeObservation

	// V2 only: the nonce of the capability this attempt consumed. It authorizes nothing.
	AttemptNonce string `json:"attempt_nonce,omitempty"`
}

// MultiProbeTunnelBackend: the backend that owns the tunnel also holds the source policy and runs
// the multi-source probe.
type MultiProbeTunnelBackend interface {
	TunnelBackend

	MultiProbePolicyPin() (netip.Addr, error)
	ProbeConfiguredMulti(ctx context.Context, namespace string) (MultiProbeObservation, error)
}

// NewMultiProbeLifecycle enables the multi-source probe only: the single-source probe stays
// disabled, so a failed attempt has nothing to fall back to.
func NewMultiProbeLifecycle(backend LabBackend, tunnels MultiProbeTunnelBackend) *LabLifecycle {
	l := NewTunnelLifecycle(backend, tunnels)
	l.multiProbes = tunnels

	return l
}

func validMultiProbeIntent(intent *helperauth.Intent) bool {
	if intent == nil {
		return false
	}

	var expected helperauth.Intent
	var err error

	switch intent.Operation {
	case helperauth.OpPermitMultiProbe:
		expected, err = helperauth.NewMultiProbeIntent(intent.ProfileID, intent.Namespace, intent.ProbeIPv4)
	case helperauth.OpPermitMultiProbeV2:
		expected, err = helperauth.NewGenerationProbeIntent(intent.ProfileID, intent.Namespace, intent.ProbeIPv4,
			intent.TunnelGeneration)
	default:
		return false
	}

	return err == nil && *intent == expected
}

// validMultiProbeInfo checks the evidence independently of the agent's consensus engine: exactly
// the V1 sources in execution order with their destinations, one public IPv4 address they all
// report, timestamps in order inside an interval of at most 80 s, the earliest as ObservedAt, and a
// handshake at most 180 whole seconds old at FinishedAt (the agent's own rule). V2 evidence also
// names the signed tunnel generation and an attempt nonce; V1 evidence carries neither.
func validMultiProbeInfo(info *MultiProbeInfo, intent *helperauth.Intent) bool {
	if info == nil || !validMultiProbeIntent(intent) ||
		info.ProfileID != intent.ProfileID ||
		info.Namespace != intent.Namespace ||
		!helperauth.ValidPublicProbeIPv4(info.IPv4) {
		return false
	}

	switch intent.Operation {
	case helperauth.OpPermitMultiProbe:
		if info.TunnelGeneration != "" || info.AttemptNonce != "" {
			return false
		}
	case helperauth.OpPermitMultiProbeV2:
		if info.TunnelGeneration != intent.TunnelGeneration ||
			!helperauth.ValidTunnelGeneration(info.TunnelGeneration) ||
			!helperauth.ValidCapabilityNonce(info.AttemptNonce) {
			return false
		}
	default:
		return false
	}

	if info.StartedAt.Unix() <= 0 || info.FinishedAt.Unix() <= 0 || info.ObservedAt.Unix() <= 0 ||
		info.HandshakeAt.Unix() <= 0 ||
		info.FinishedAt.Before(info.StartedAt) ||
		info.FinishedAt.Sub(info.StartedAt) > lifecycleTimeout {
		return false
	}

	if info.HandshakeAt.After(info.FinishedAt) ||
		info.FinishedAt.Unix()-info.HandshakeAt.Unix() > int64(maxProbeHandshakeAge/time.Second) {
		return false
	}

	expected := []struct{ id, destination string }{
		{helperauth.MultiProbeCloudflareSource, helperauth.MultiProbeCloudflareIPv4},
		{helperauth.MultiProbeIdentSource, intent.ProbeIPv4},
	}

	if len(info.Sources) != len(expected) {
		return false
	}

	previous := info.StartedAt

	for i, source := range info.Sources {
		if source.Source != expected[i].id ||
			source.DestinationIPv4.String() != expected[i].destination ||
			source.IPv4 != info.IPv4 ||
			source.ObservedAt.Before(previous) ||
			source.ObservedAt.After(info.FinishedAt) {
			return false
		}

		previous = source.ObservedAt
	}

	return info.ObservedAt.Equal(info.Sources[0].ObservedAt)
}

// validMultiProbeForCapability also requires the capability that names exactly this intent, and an
// attempt that started after it was issued. Expiry is not checked: the capability only had to be
// valid when the helper accepted it, and the attempt may take up to 80 s.
func validMultiProbeForCapability(
	info *MultiProbeInfo,
	intent *helperauth.Intent,
	capability *helperauth.SignedCapability,
) bool {
	if !validMultiProbeInfo(info, intent) || capability == nil || capability.Claims.Intent != *intent ||
		capability.Claims.IssuedAt <= 0 {
		return false
	}

	if intent.Operation == helperauth.OpPermitMultiProbeV2 && info.AttemptNonce != capability.Claims.Nonce {
		return false
	}

	return !info.StartedAt.Before(time.Unix(capability.Claims.IssuedAt, 0))
}

// multiProbeWithin requires evidence that started no earlier than from, with the agent's 1 s
// clock-step tolerance, and finished no later than to: the helper and its client share one clock,
// so evidence never legitimately ends in their future.
func multiProbeWithin(info *MultiProbeInfo, from, to time.Time) bool {
	return info != nil && !info.StartedAt.Before(from.Add(-time.Second)) && !info.FinishedAt.After(to)
}

// olderHelperDisabled recognizes how a helper from before Step 29C.4a refuses PermitMultiProbeV1:
// it echoed letters-only operation names, so its OPERATION_DISABLED answer names no operation. Only
// that bare refusal is mapped; anything else from it stays an invalid response.
func olderHelperDisabled(req Request, resp Response) bool {
	return req.Operation == helperauth.OpPermitMultiProbe &&
		resp.Version == Version && !resp.OK && !resp.NetworkReady &&
		resp.Operation == "" && resp.Code == CodeOperationDisabled &&
		len(resp.Items) == 0 && resp.Info == nil && resp.Lab == nil && len(resp.Labs) == 0 &&
		resp.Stage == nil && resp.Probe == nil && resp.MultiProbe == nil && resp.MultiProbePolicy == nil &&
		resp.MultiProbeTarget == nil && resp.Candidate == nil && resp.PreparedLease == nil
}

func validMultiProbeResponse(req Request, resp Response) bool {
	multi := req.Operation == helperauth.OpPermitMultiProbe || req.Operation == helperauth.OpPermitMultiProbeV2
	if !multi || !resp.OK {
		return resp.MultiProbe == nil
	}

	if resp.NetworkReady || resp.Probe != nil || req.Intent == nil || req.Intent.Operation != req.Operation {
		return false
	}

	return validMultiProbeForCapability(resp.MultiProbe, req.Intent, req.Capability)
}

// executeMultiProbe runs one signed multi-source attempt, V1 or (in a generation lifecycle) V2. The
// ident.me pin, and for V2 the tunnel generation, are read from the backend and must equal the
// signed ones: the request never chooses a destination or a tunnel. Refusals before the nonce is
// consumed leave the lab and any trusted evidence untouched; after it, the previous evidence is
// dropped at once, and any failure faults the lab and removes the tunnel. Only a V2 attempt that
// passes every check records new evidence.
func (l *LabLifecycle) executeMultiProbe(
	ctx context.Context,
	req Request,
	v *helperauth.Verifier,
) (MultiProbeInfo, error) {
	if l == nil || l.backend == nil || req.Version != Version || !validMultiProbeIntent(req.Intent) ||
		req.Operation != req.Intent.Operation {
		return MultiProbeInfo{}, errLabInvalid
	}

	if !l.multiProbeOperationEnabled(req.Operation) {
		return MultiProbeInfo{}, errLabUnavailable
	}

	if !l.mu.TryLock() {
		return MultiProbeInfo{}, errLabBusy
	}
	defer l.mu.Unlock()

	if l.closed || ctx.Err() != nil {
		return MultiProbeInfo{}, errLabUnavailable
	}

	if l.blockCreation {
		return MultiProbeInfo{}, errLabUncertain
	}

	// A prepared lease leaves through its own lifecycle, not by a new observation, even expired.
	if l.preparedLease != nil {
		return MultiProbeInfo{}, errLabBusy
	}

	requested := *req.Intent

	lab, exists := l.labs[requested.ProfileID]
	if !exists {
		return MultiProbeInfo{}, errLabNotFound
	}

	if lab.Namespace != requested.Namespace {
		return MultiProbeInfo{}, errLabOwnership
	}

	if lab.State != LabTunnelConfigured {
		return MultiProbeInfo{}, errLabFaulted
	}

	if l.tunnelProfile != lab.ProfileID {
		return MultiProbeInfo{}, errLabUncertain
	}

	pin, err := l.multiProbes.MultiProbePolicyPin()
	if err != nil {
		return MultiProbeInfo{}, fmt.Errorf("%w: multi-source policy unavailable: %v", errLabUnavailable, err)
	}

	generationBound := requested.Operation == helperauth.OpPermitMultiProbeV2

	var expected helperauth.Intent

	if generationBound {
		generation, readErr := l.generationProbes.CurrentTunnelGeneration(lab.Namespace)
		if readErr != nil {
			return MultiProbeInfo{}, errLabUncertain
		}

		// A capability for an earlier tunnel of the same lab is refused, even unused and unexpired.
		if requested.TunnelGeneration != generation {
			return MultiProbeInfo{}, errLabAuthorization
		}

		expected, err = helperauth.NewGenerationProbeIntent(lab.ProfileID, lab.Namespace, pin.String(), generation)
	} else {
		expected, err = helperauth.NewMultiProbeIntent(lab.ProfileID, lab.Namespace, pin.String())
	}

	if err != nil {
		return MultiProbeInfo{}, errLabUnavailable
	}

	if requested != expected {
		return MultiProbeInfo{}, errLabInvalid
	}

	if v == nil || req.Capability == nil {
		return MultiProbeInfo{}, errLabAuthorization
	}

	// The nonce is consumed only after the ownership, tunnel state and local policy checks.
	if err := v.VerifyAndConsume(*req.Capability, expected); err != nil {
		return MultiProbeInfo{}, fmt.Errorf("%w: %w", errLabAuthorization, err)
	}

	// Monotonic, for the evidence deadline.
	acceptedAt := time.Now()

	// An accepted attempt drops the previous evidence and candidate, even if it then fails.
	l.verifiedEvidence = nil
	l.localCandidate = nil

	// Ownership is kept, as faulted, while the attempt runs.
	faulted := lab
	faulted.State = LabFaulted
	l.labs[lab.ProfileID] = faulted

	var observation MultiProbeObservation

	if generationBound {
		// Evidence recorded after this deadline is refused anyway, so the attempt stops there; the
		// cleanups keep their own contexts. The agent checks the generation again under its own lock.
		probeCtx, cancelProbe := context.WithDeadline(ctx, acceptedAt.Add(verifiedProbeEvidenceTTL))
		defer cancelProbe()

		observation, err = l.generationProbes.ProbeConfiguredMultiForGeneration(probeCtx, lab.Namespace,
			expected.TunnelGeneration)
	} else {
		observation, err = l.multiProbes.ProbeConfiguredMulti(ctx, lab.Namespace)
	}

	info := MultiProbeInfo{ProfileID: lab.ProfileID, Namespace: lab.Namespace, MultiProbeObservation: observation}
	if generationBound {
		info.AttemptNonce = req.Capability.Claims.Nonce
	}

	if err == nil && !validMultiProbeForCapability(&info, &expected, req.Capability) {
		err = errors.New("invalid backend multi-source observation")
	}

	now := time.Now()

	if err == nil && !multiProbeWithin(&info, acceptedAt, now) {
		err = errors.New("multi-source observation outside the accepted attempt")
	}

	var verified *verifiedMultiProbeEvidence

	if err == nil && generationBound {
		verified, err = newVerifiedMultiProbeEvidence(info, *req.Capability, acceptedAt, now)
	}

	if err == nil {
		err = ctx.Err()
	}

	if err != nil {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), tunnelCleanupTimeout)
		defer cancel()

		// CleanupStage returns nil when the backend has already removed its tunnel.
		if cleanupErr := l.clearTunnelLocked(cleanupCtx, faulted); cleanupErr != nil {
			return MultiProbeInfo{}, errors.Join(errLabUncertain, err, cleanupErr)
		}

		// Only DeleteLab clears a faulted lab. The cause is not wrapped, so it cannot change the code.
		return MultiProbeInfo{}, fmt.Errorf("%w: multi-source probe failed: %v", errLabFaulted, err)
	}

	// Every source was verified and the backend resealed the firewall.
	l.labs[lab.ProfileID] = lab
	l.verifiedEvidence = verified

	return info, nil
}

// ProbeEgressMulti asks the helper for one signed multi-source attempt. The capability names the
// ident.me pin, but only the helper's own policy can authorize it. There is no URL, host or port.
func ProbeEgressMulti(
	ctx context.Context,
	socketPath, profileID, namespace string,
	capability helperauth.SignedCapability,
) (Response, error) {
	intent, err := helperauth.NewMultiProbeIntent(profileID, namespace, capability.Claims.Intent.ProbeIPv4)
	if err != nil || capability.Claims.Intent != intent {
		return Response{}, &Error{Code: CodeInvalidRequest, Message: "invalid multi-source capability intent"}
	}

	return callRequest(ctx, socketPath, Request{
		Version:    Version,
		Operation:  intent.Operation,
		Intent:     &intent,
		Capability: &capability,
	})
}
