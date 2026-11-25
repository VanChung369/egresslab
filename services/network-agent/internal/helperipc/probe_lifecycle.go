package helperipc

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"time"

	"github.com/VanChung369/egresslab/services/network-agent/internal/helperauth"
)

const (
	ProbeDestinationIPv4 = "1.1.1.1"
	ProbeSource          = "cloudflare_trace"

	// Worst case, not a normal probe, single- or multi-source: the operation context (80 s), then
	// the firewall window close (20 s), the backend's tunnel rollback (40 s) and the lifecycle's
	// cleanup (40 s), each with its own deadline, plus a margin.
	probeResponseTimeout = 185 * time.Second

	maxProbeHandshakeAge = 180 * time.Second
)

// ProbeObservation is diagnostic evidence from one source, not an egress lease.
type ProbeObservation struct {
	IPv4        netip.Addr `json:"ipv4"`
	ObservedAt  time.Time  `json:"observed_at"`
	HandshakeAt time.Time  `json:"handshake_at"`
	Source      string     `json:"source"`
}

type ProbeInfo struct {
	ProfileID string `json:"profile_id"`
	Namespace string `json:"namespace"`

	ProbeObservation
}

// ProbeTunnelBackend: the backend that owns the tunnel also runs its probe.
type ProbeTunnelBackend interface {
	TunnelBackend

	ProbeConfigured(ctx context.Context, namespace string) (ProbeObservation, error)
}

func NewProbeLifecycle(backend LabBackend, tunnels ProbeTunnelBackend) *LabLifecycle {
	l := NewTunnelLifecycle(backend, tunnels)
	l.probes = tunnels

	return l
}

// validProbeIntent pins the destination: helperauth accepts any unicast IPv4 for PermitProbe,
// the helper only the fixed trace endpoint.
func validProbeIntent(in *helperauth.Intent) bool {
	return in != nil &&
		in.Operation == helperauth.OpPermitProbe &&
		helperauth.ValidProfileID(in.ProfileID) &&
		helperauth.ValidLabNamespace(in.Namespace) &&
		in.StageID == "" &&
		in.TunnelGeneration == "" &&
		in.ProbeIPv4 == ProbeDestinationIPv4
}

// validProbeInfo checks the structure, identity, source and timestamps of an observation. The full
// public-IPv4 policy is the backend's (parseCandidateIPv4).
func validProbeInfo(info *ProbeInfo, intent *helperauth.Intent) bool {
	if info == nil || !validProbeIntent(intent) {
		return false
	}

	return info.ProfileID == intent.ProfileID &&
		info.Namespace == intent.Namespace &&
		info.IPv4.Is4() &&
		info.IPv4.IsGlobalUnicast() &&
		!info.IPv4.IsPrivate() &&
		info.Source == ProbeSource &&
		info.ObservedAt.Unix() > 0 &&
		info.HandshakeAt.Unix() > 0 &&
		!info.HandshakeAt.Before(info.ObservedAt.Add(-maxProbeHandshakeAge)) &&
		!info.HandshakeAt.After(info.ObservedAt.Add(lifecycleTimeout))
}

func validProbeResponse(req Request, resp Response) bool {
	if req.Operation != helperauth.OpPermitProbe || !resp.OK {
		return resp.Probe == nil
	}

	return validProbeInfo(resp.Probe, req.Intent)
}

func operationResponseTimeout(operation string) time.Duration {
	if operation == helperauth.OpPermitProbe || operation == helperauth.OpPermitMultiProbe ||
		operation == helperauth.OpPermitMultiProbeV2 {
		return probeResponseTimeout
	}

	if isLifecycleOp(operation) {
		return lifecycleResponseTimeout
	}

	return 0
}

// executeProbe runs one signed probe from start to finish: the backend opens the firewall window,
// runs the worker, closes the window and verifies the kernel before it answers. Nothing is left
// open for the caller, and nothing is retried. It shares the lifecycle mutex and ownership registry
// with execute; it is separate only because it returns a ProbeInfo.
func (l *LabLifecycle) executeProbe(ctx context.Context, req Request, v *helperauth.Verifier) (ProbeInfo, error) {
	if l == nil || l.backend == nil || req.Version != Version || req.Operation != helperauth.OpPermitProbe ||
		!validProbeIntent(req.Intent) {
		return ProbeInfo{}, errLabInvalid
	}

	// A multi-source lifecycle never falls back to one source.
	if l.probes == nil || l.multiProbes != nil {
		return ProbeInfo{}, errLabUnavailable
	}

	if !l.mu.TryLock() {
		return ProbeInfo{}, errLabBusy
	}
	defer l.mu.Unlock()

	if l.closed || ctx.Err() != nil {
		return ProbeInfo{}, errLabUnavailable
	}

	if l.blockCreation {
		return ProbeInfo{}, errLabUncertain
	}

	intent := *req.Intent

	lab, exists := l.labs[intent.ProfileID]
	if !exists {
		return ProbeInfo{}, errLabNotFound
	}

	if lab.Namespace != intent.Namespace {
		return ProbeInfo{}, errLabOwnership
	}

	if lab.State != LabTunnelConfigured {
		return ProbeInfo{}, errLabFaulted
	}

	if l.tunnelProfile != lab.ProfileID {
		return ProbeInfo{}, errLabUncertain
	}

	if v == nil || req.Capability == nil {
		return ProbeInfo{}, errLabAuthorization
	}

	// The nonce is consumed only after the operation, ownership and tunnel state checks.
	if err := v.VerifyAndConsume(*req.Capability, intent); err != nil {
		return ProbeInfo{}, fmt.Errorf("%w: %w", errLabAuthorization, err)
	}

	// Ownership is kept, as faulted, while the probe runs.
	faulted := lab
	faulted.State = LabFaulted
	l.labs[lab.ProfileID] = faulted

	observation, err := l.probes.ProbeConfigured(ctx, lab.Namespace)

	info := ProbeInfo{ProfileID: lab.ProfileID, Namespace: lab.Namespace, ProbeObservation: observation}

	if err == nil && !validProbeInfo(&info, &intent) {
		err = errors.New("invalid backend probe observation")
	}

	if err == nil {
		err = ctx.Err()
	}

	if err != nil {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), tunnelCleanupTimeout)
		defer cancel()

		// CleanupStage returns nil when the backend has already removed its tunnel.
		if cleanupErr := l.clearTunnelLocked(cleanupCtx, faulted); cleanupErr != nil {
			return ProbeInfo{}, errors.Join(errLabUncertain, err, cleanupErr)
		}

		// A clean rollback does not restore a faulted lab: only DeleteLab clears it. The cause is
		// not wrapped, so it cannot change the code.
		return ProbeInfo{}, fmt.Errorf("%w: probe failed: %v", errLabFaulted, err)
	}

	// The backend closed its window and verified the tunnel again.
	l.labs[lab.ProfileID] = lab

	return info, nil
}

// ProbeEgress asks the helper for one signed diagnostic probe of the fixed destination.
func ProbeEgress(
	ctx context.Context,
	socketPath, profileID, namespace string,
	capability helperauth.SignedCapability,
) (Response, error) {
	intent := helperauth.Intent{
		Operation: helperauth.OpPermitProbe,
		ProfileID: profileID,
		Namespace: namespace,
		ProbeIPv4: ProbeDestinationIPv4,
	}

	return callRequest(ctx, socketPath, Request{
		Version:    Version,
		Operation:  intent.Operation,
		Intent:     &intent,
		Capability: &capability,
	})
}
