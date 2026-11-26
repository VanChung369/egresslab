package agent

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"time"
)

const (
	probeExecutionTimeout = 12 * time.Second
	probeCleanupTimeout   = 20 * time.Second
)

var ErrProbeCleanup = errors.New("managed probe cleanup not confirmed")

// The caller must hold manager.mu.
func (f *LabFirewall) readProbeRulesetLocked(ctx context.Context, namespace string) ([]byte, error) {
	if f.list == nil {
		return nil, ErrProbePolicyDrift
	}

	commandCtx, cancel := context.WithTimeout(ctx, netNSCommandTimeout)
	defer cancel()

	return f.list(commandCtx, namespace)
}

// closeProbeWindowForLocked removes only the verified permits and the reserved set of destination's
// window, and the monitor's traffic overlay of overlayUID when not 0, in one transaction, and
// requires the sealed policy afterwards. A window for another address is not removed. The firewall
// is never rebuilt around a live tunnel. The caller must hold manager.mu.
func (f *LabFirewall) closeProbeWindowForLocked(ctx context.Context, namespace string, destination netip.Addr,
	overlayUID uint32) error {
	if _, err := parseCandidateIPv4(destination.String()); err != nil {
		return ErrProbePolicyDrift
	}

	data, err := f.readProbeRulesetLocked(ctx, namespace)
	if err != nil {
		return err
	}

	// The opening transaction may have failed without changing anything.
	if verifySealedPolicy(data) == nil {
		return f.requireSealedPolicyLocked(ctx, namespace)
	}

	var script string

	if overlayUID == 0 {
		handles, err := verifyManagedProbePolicyFor(data, false, destination)
		if err != nil {
			return err
		}

		script = fmt.Sprintf("delete rule inet %[1]s input handle %[2]d\n"+
			"delete rule inet %[1]s output handle %[3]d\n"+
			"delete set inet %[1]s %[4]s\n",
			labNFTTable, handles.input, handles.output, managedProbeSet)
	} else {
		probe, traffic, err := verifyMonitorOverlay(data, overlayUID, destination, false, false)
		if err != nil {
			return err
		}

		script = fmt.Sprintf("delete rule inet %[1]s input handle %[2]d\n"+
			"delete rule inet %[1]s output handle %[3]d\n"+
			"delete rule inet %[1]s input handle %[4]d\n"+
			"delete rule inet %[1]s output handle %[5]d\n"+
			"delete set inet %[1]s %[6]s\n"+
			"delete set inet %[1]s %[7]s\n",
			labNFTTable, probe.input, probe.output, traffic.input, traffic.output, managedProbeSet, managedTrafficSet)
	}

	if err := f.apply(ctx, namespace, script); err != nil {
		return err
	}

	return f.requireSealedPolicyLocked(ctx, namespace)
}

// withManagedProbeWindowLocked is the single-source window of the 29B probe, for 1.1.1.1.
func (f *LabFirewall) withManagedProbeWindowLocked(
	ctx context.Context,
	namespace string,
	probe func(context.Context) error,
) error {
	return f.withManagedProbeWindowForLocked(ctx, namespace, netip.MustParseAddr(managedProbeIP), probe)
}

// withManagedProbeWindowForLocked opens a kernel-timed window for destination:443 over wg0, runs
// probe with a bounded context, and always closes the window with its own context. The window is
// never recorded as a session script or baseline, so a Reconcile cannot bring it back. An
// unconfirmed close marks the namespace drifted; the caller must then fault the tunnel, discard the
// result and open no further window.
//
// The caller must hold manager.mu, must have verified the managed tunnel itself and must take
// destination only from trusted, authorized source policy; probe must not take manager.mu.
func (f *LabFirewall) withManagedProbeWindowForLocked(
	ctx context.Context,
	namespace string,
	destination netip.Addr,
	probe func(context.Context) error,
) error {
	return f.withMonitoredProbeWindowLocked(ctx, namespace, destination, nil, probe)
}

// withMonitoredProbeWindowLocked is withManagedProbeWindowForLocked with the monitor's traffic
// overlay, when it is eligible as the window opens: both go in in one transaction, the overlay
// first, and come out together. Its element expires on its own after the gate's kernel timeout,
// which may pause the streams before the probe ends; it is never renewed within the window.
func (f *LabFirewall) withMonitoredProbeWindowLocked(
	ctx context.Context,
	namespace string,
	destination netip.Addr,
	overlay *MonitorTrafficOverlay,
	probe func(context.Context) error,
) (resultErr error) {
	if !labNamePattern.MatchString(namespace) || probe == nil {
		return ErrProbePolicyDrift
	}

	script, err := managedProbeRulesFor(destination)
	if err != nil {
		return err
	}

	if err := f.requireSealedPolicyLocked(ctx, namespace); err != nil {
		return err
	}

	if err := ctx.Err(); err != nil {
		return err
	}

	var overlayUID uint32

	openCtx := ctx
	openDeadline := time.Time{}

	if overlay.eligible(time.Now()) {
		traffic, err := managedMonitorTrafficRules(overlay.UID)
		if err != nil {
			return err
		}

		script = traffic + script
		overlayUID = overlay.UID

		openDeadline = overlay.HealthUntil.Add(-trafficGateTTL - trafficGateCloseBudget)

		var cancelOpen context.CancelFunc

		openCtx, cancelOpen = context.WithDeadline(ctx, openDeadline)
		defer cancelOpen()
	}

	verify := func(data []byte, trafficActive bool) error {
		if overlayUID == 0 {
			_, err := verifyManagedProbePolicyFor(data, true, destination)
			return err
		}

		_, _, err := verifyMonitorOverlay(data, overlayUID, destination, true, trafficActive)

		return err
	}

	// Registered before the firewall is touched.
	defer func() {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), probeCleanupTimeout)
		defer cancel()

		if err := f.closeProbeWindowForLocked(cleanupCtx, namespace, destination, overlayUID); err != nil {
			f.drifted[namespace] = true
			resultErr = errors.Join(resultErr, ErrProbeCleanup, err)
		}
	}()

	// Not applyVerifiedLocked: that would record the permits as permanent session state.
	if err := f.apply(openCtx, namespace, script); err != nil {
		return err
	}

	before, err := f.readProbeRulesetLocked(openCtx, namespace)
	if err != nil {
		return err
	}

	if err := verify(before, true); err != nil {
		return err
	}

	if overlayUID != 0 && (openCtx.Err() != nil || !time.Now().Before(openDeadline)) {
		return ErrTrafficGate
	}

	probeCtx, cancel := context.WithTimeout(ctx, probeExecutionTimeout)
	defer cancel()

	probeErr := probe(probeCtx)
	if err := probeCtx.Err(); err != nil {
		probeErr = errors.Join(probeErr, err)
	}

	// The probe window must still be exactly as opened, with time left, when the probe returns; the
	// overlay's element may have expired.
	after, err := f.readProbeRulesetLocked(ctx, namespace)
	if err != nil {
		return errors.Join(probeErr, err)
	}

	return errors.Join(probeErr, verify(after, false))
}
