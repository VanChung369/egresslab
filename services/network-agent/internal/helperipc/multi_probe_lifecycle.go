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

	expected, err := helperauth.NewMultiProbeIntent(intent.ProfileID, intent.Namespace, intent.ProbeIPv4)

	return err == nil && *intent == expected
}

// validMultiProbeInfo checks the evidence independently of the agent's consensus engine: exactly
// the V1 sources in execution order with their destinations, one public IPv4 address they all
// report, timestamps in order inside an interval of at most 80 s, the earliest as ObservedAt, and a
// handshake at most 180 whole seconds old at FinishedAt (the agent's own rule).
func validMultiProbeInfo(info *MultiProbeInfo, intent *helperauth.Intent) bool {
	if info == nil || !validMultiProbeIntent(intent) ||
		info.ProfileID != intent.ProfileID ||
		info.Namespace != intent.Namespace ||
		!helperauth.ValidPublicProbeIPv4(info.IPv4) {
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
		resp.Stage == nil && resp.Probe == nil && resp.MultiProbe == nil
}

func validMultiProbeResponse(req Request, resp Response) bool {
	if req.Operation != helperauth.OpPermitMultiProbe || !resp.OK {
		return resp.MultiProbe == nil
	}

	if resp.NetworkReady || resp.Probe != nil {
		return false
	}

	return validMultiProbeForCapability(resp.MultiProbe, req.Intent, req.Capability)
}

// executeMultiProbe runs one signed multi-source attempt. The ident.me pin is read from the
// backend's trusted policy and must equal the signed one: a valid signature for another pin is
// refused, and the request never chooses a destination. Refusals before the nonce is consumed leave
// the lab untouched; after it, any failure faults the lab and removes the tunnel.
func (l *LabLifecycle) executeMultiProbe(
	ctx context.Context,
	req Request,
	v *helperauth.Verifier,
) (MultiProbeInfo, error) {
	if l == nil || l.backend == nil || req.Version != Version || req.Operation != helperauth.OpPermitMultiProbe ||
		!validMultiProbeIntent(req.Intent) {
		return MultiProbeInfo{}, errLabInvalid
	}

	if l.multiProbes == nil {
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

	expected, err := helperauth.NewMultiProbeIntent(lab.ProfileID, lab.Namespace, pin.String())
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

	acceptedAt := time.Now().UTC()

	// Ownership is kept, as faulted, while the attempt runs.
	faulted := lab
	faulted.State = LabFaulted
	l.labs[lab.ProfileID] = faulted

	observation, err := l.multiProbes.ProbeConfiguredMulti(ctx, lab.Namespace)

	info := MultiProbeInfo{ProfileID: lab.ProfileID, Namespace: lab.Namespace, MultiProbeObservation: observation}

	if err == nil && !validMultiProbeForCapability(&info, &expected, req.Capability) {
		err = errors.New("invalid backend multi-source observation")
	}

	if err == nil && !multiProbeWithin(&info, acceptedAt, time.Now()) {
		err = errors.New("multi-source observation outside the accepted attempt")
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
