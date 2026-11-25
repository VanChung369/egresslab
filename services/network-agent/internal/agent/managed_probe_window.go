package agent

import (
	"context"
	"errors"
	"fmt"
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

// closeProbeWindowLocked removes only the verified permits and the reserved set, in one
// transaction, and requires the sealed policy afterwards. The firewall is never rebuilt around a
// live tunnel. The caller must hold manager.mu.
func (f *LabFirewall) closeProbeWindowLocked(ctx context.Context, namespace string) error {
	data, err := f.readProbeRulesetLocked(ctx, namespace)
	if err != nil {
		return err
	}

	// The opening transaction may have failed without changing anything.
	if verifySealedPolicy(data) == nil {
		return f.requireSealedPolicyLocked(ctx, namespace)
	}

	handles, err := verifyManagedProbePolicy(data, false)
	if err != nil {
		return err
	}

	script := fmt.Sprintf("delete rule inet %[1]s input handle %[2]d\n"+
		"delete rule inet %[1]s output handle %[3]d\n"+
		"delete set inet %[1]s %[4]s\n",
		labNFTTable, handles.input, handles.output, managedProbeSet)

	if err := f.apply(ctx, namespace, script); err != nil {
		return err
	}

	return f.requireSealedPolicyLocked(ctx, namespace)
}

// withManagedProbeWindowLocked opens a kernel-timed window for 1.1.1.1:443 over wg0, runs probe
// with a bounded context, and always closes the window with its own context. The window is never
// recorded as a session script or baseline, so a Reconcile cannot bring it back. An unconfirmed
// close marks the namespace drifted; the caller must then fault the tunnel and discard the result.
//
// The caller must hold manager.mu and must have verified the managed tunnel itself; probe must
// not take manager.mu.
func (f *LabFirewall) withManagedProbeWindowLocked(
	ctx context.Context,
	namespace string,
	probe func(context.Context) error,
) (resultErr error) {
	if !labNamePattern.MatchString(namespace) || probe == nil {
		return ErrProbePolicyDrift
	}

	if err := f.requireSealedPolicyLocked(ctx, namespace); err != nil {
		return err
	}

	if err := ctx.Err(); err != nil {
		return err
	}

	// Registered before the firewall is touched.
	defer func() {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), probeCleanupTimeout)
		defer cancel()

		if err := f.closeProbeWindowLocked(cleanupCtx, namespace); err != nil {
			f.drifted[namespace] = true
			resultErr = errors.Join(resultErr, ErrProbeCleanup, err)
		}
	}()

	// Not applyVerifiedLocked: that would record the permits as permanent session state.
	if err := f.apply(ctx, namespace, managedProbeRules()); err != nil {
		return err
	}

	before, err := f.readProbeRulesetLocked(ctx, namespace)
	if err != nil {
		return err
	}

	if _, err := verifyManagedProbePolicy(before, true); err != nil {
		return err
	}

	probeCtx, cancel := context.WithTimeout(ctx, probeExecutionTimeout)
	defer cancel()

	probeErr := probe(probeCtx)
	if err := probeCtx.Err(); err != nil {
		probeErr = errors.Join(probeErr, err)
	}

	// The window must still be exactly as opened, with time left, when the probe returns.
	after, err := f.readProbeRulesetLocked(ctx, namespace)
	if err != nil {
		return errors.Join(probeErr, err)
	}

	_, verifyErr := verifyManagedProbePolicy(after, true)

	return errors.Join(probeErr, verifyErr)
}
