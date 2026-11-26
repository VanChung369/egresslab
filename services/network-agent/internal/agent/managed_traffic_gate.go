package agent

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"time"
)

const (
	managedTrafficSet = "egresslab_app4"

	trafficGateTTLSeconds = 10
	trafficGateTTL        = trafficGateTTLSeconds * time.Second

	// trafficGateCloseBudget is kept between the element's expiry and the health deadline, for the
	// normal close and its verification.
	trafficGateCloseBudget = 2 * time.Second

	// trafficGateConnMark tags the conntrack entries the proxy permit admitted; only their replies
	// come back. No other rule of the lab sets a mark.
	trafficGateConnMark = 0x65676c01
)

var (
	ErrTrafficGate = errors.New("managed traffic gate not verified")

	// ErrTrafficGateTooLate: too little health is left to open the gate. Nothing was written.
	ErrTrafficGateTooLate = errors.New("too little monitoring health left to open the traffic gate")
)

// managedTrafficRules opens the data-plane gate as one nft transaction: a one-element set holding
// "wg0", which the kernel expires on its own, and two permits that both match through it. Only
// IPv4 TCP of the dedicated UID leaves over wg0, marking its connections, and only the established
// replies of marked connections come back: no general "ct state established" rule survives the
// element, and a flow admitted earlier (a probe's, say) stays closed. The sealed IPv6 and DNS drops
// still come first.
func managedTrafficRules(uid uint32) (string, error) {
	if uid == 0 || uid == ^uint32(0) {
		return "", ErrTrafficGate
	}

	return fmt.Sprintf(`add set inet %[1]s %[2]s { type ifname; flags timeout; size 1; }
add element inet %[1]s %[2]s { "wg0" timeout %[3]ds }
add rule inet %[1]s output meta nfproto ipv4 oifname @%[2]s meta skuid %[4]d meta l4proto tcp ct mark set %[5]d accept
add rule inet %[1]s input meta nfproto ipv4 iifname @%[2]s meta l4proto tcp ct state established ct mark %[5]d accept
`, labNFTTable, managedTrafficSet, trafficGateTTLSeconds, uid, trafficGateConnMark), nil
}

// expectedTrafficRules is the canonical form of the two permits as nft prints them; another
// rendering is refused, as for the seal and the probe window.
func expectedTrafficRules(uid uint32) map[string]string {
	return map[string]string{
		"output": fmt.Sprintf(`[{"match":{"left":{"meta":{"key":"nfproto"}},"op":"==","right":"ipv4"}},`+
			`{"match":{"left":{"meta":{"key":"oifname"}},"op":"==","right":"@egresslab_app4"}},`+
			`{"match":{"left":{"meta":{"key":"skuid"}},"op":"==","right":%d}},`+
			`{"match":{"left":{"meta":{"key":"l4proto"}},"op":"==","right":"tcp"}},`+
			`{"mangle":{"key":{"ct":{"key":"mark"}},"value":%d}},{"accept":null}]`, uid, trafficGateConnMark),
		"input": fmt.Sprintf(`[{"match":{"left":{"meta":{"key":"nfproto"}},"op":"==","right":"ipv4"}},`+
			`{"match":{"left":{"meta":{"key":"iifname"}},"op":"==","right":"@egresslab_app4"}},`+
			`{"match":{"left":{"meta":{"key":"l4proto"}},"op":"==","right":"tcp"}},`+
			`{"match":{"left":{"ct":{"key":"state"}},"op":"in","right":"established"}},`+
			`{"match":{"left":{"ct":{"key":"mark"}},"op":"==","right":%d}},{"accept":null}]`, trafficGateConnMark),
	}
}

// verifyTrafficSet requires the reserved set exactly as the gate creates it. An active gate holds
// "wg0" with time left; once it expired the kernel lists no "elem", which only cleanup accepts.
func verifyTrafficSet(raw []byte, requireActive bool) error {
	var set managedProbeSetInfo

	if err := decodeProbeJSON(raw, &set); err != nil {
		return ErrTrafficGate
	}

	if set.Family != "inet" || set.Table != labNFTTable || set.Name != managedTrafficSet || set.Type != "ifname" ||
		set.Handle == 0 || set.Size != 1 || len(set.Flags) != 1 || set.Flags[0] != "timeout" {
		return ErrTrafficGate
	}

	if set.Elem == nil {
		if requireActive {
			return ErrTrafficGate
		}

		return nil
	}

	var elements []managedProbeElement
	if err := decodeProbeJSON(set.Elem, &elements); err != nil || len(elements) != 1 {
		return ErrTrafficGate
	}

	elem := elements[0].Elem

	if elem.Val != "wg0" || elem.Timeout == nil || *elem.Timeout != trafficGateTTLSeconds ||
		elem.Expires == nil || *elem.Expires < 0 || *elem.Expires > trafficGateTTLSeconds {
		return ErrTrafficGate
	}

	if requireActive && *elem.Expires == 0 {
		return ErrTrafficGate
	}

	return nil
}

func verifyTrafficGatePolicy(data []byte, uid uint32, requireActive bool) (probeRuleHandles, error) {
	if uid == 0 || uid == ^uint32(0) {
		return probeRuleHandles{}, ErrTrafficGate
	}

	handles, err := verifyTimedWindowPolicy(data, expectedTrafficRules(uid), func(raw []byte) error {
		return verifyTrafficSet(raw, requireActive)
	})
	if err != nil {
		return probeRuleHandles{}, errors.Join(ErrTrafficGate, err)
	}

	return handles, nil
}

// closeTrafficGateLocked removes only the verified gate, in one transaction, and requires the
// sealed policy afterwards. The caller must hold manager.mu.
func (f *LabFirewall) closeTrafficGateLocked(ctx context.Context, namespace string, uid uint32) error {
	data, err := f.readProbeRulesetLocked(ctx, namespace)
	if err != nil {
		return err
	}

	// The opening transaction may have failed without changing anything.
	if verifySealedPolicy(data) == nil {
		return f.requireSealedPolicyLocked(ctx, namespace)
	}

	handles, err := verifyTrafficGatePolicy(data, uid, false)
	if err != nil {
		return err
	}

	script := fmt.Sprintf("delete rule inet %[1]s input handle %[2]d\n"+
		"delete rule inet %[1]s output handle %[3]d\n"+
		"delete set inet %[1]s %[4]s\n",
		labNFTTable, handles.input, handles.output, managedTrafficSet)

	if err := f.apply(ctx, namespace, script); err != nil {
		return err
	}

	return f.requireSealedPolicyLocked(ctx, namespace)
}

// withTrafficGateLocked opens the gate for uid only while healthUntil leaves the whole kernel
// timeout and the close budget, runs run within the element's lifetime, and always closes the gate
// with its own context. The gate is never recorded as a session script or baseline, so a Reconcile cannot
// bring it back; an unconfirmed close marks the namespace drifted. The caller must hold manager.mu;
// run must not take it.
func (f *LabFirewall) withTrafficGateLocked(
	ctx context.Context,
	namespace string,
	uid uint32,
	healthUntil time.Time,
	run func(context.Context) error,
) (resultErr error) {
	if !labNamePattern.MatchString(namespace) || run == nil {
		return ErrTrafficGate
	}

	script, err := managedTrafficRules(uid)
	if err != nil {
		return err
	}

	if err := f.requireSealedPolicyLocked(ctx, namespace); err != nil {
		return err
	}

	// The element must expire, and the gate close, before the health it rests on.
	openDeadline := healthUntil.Add(-trafficGateTTL - trafficGateCloseBudget)
	if !time.Now().Before(openDeadline) {
		return ErrTrafficGateTooLate
	}

	openCtx, cancelOpen := context.WithDeadline(ctx, openDeadline)
	defer cancelOpen()

	// Registered before the firewall is touched.
	defer func() {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), probeCleanupTimeout)
		defer cancel()

		if err := f.closeTrafficGateLocked(cleanupCtx, namespace, uid); err != nil {
			f.drifted[namespace] = true
			resultErr = errors.Join(resultErr, ErrTrafficGate, err)
		}
	}()

	startedAt := time.Now()

	// Not applyVerifiedLocked: that would record the permits as permanent session state.
	if err := f.apply(openCtx, namespace, script); err != nil {
		return err
	}

	data, err := f.readProbeRulesetLocked(openCtx, namespace)
	if err != nil {
		return err
	}

	if _, err := verifyTrafficGatePolicy(data, uid, true); err != nil {
		return err
	}

	if openCtx.Err() != nil || !time.Now().Before(openDeadline) {
		return ErrTrafficGate
	}

	// Measured from before the transaction, so run ends before the element can expire.
	runCtx, cancelRun := context.WithDeadline(ctx, startedAt.Add(trafficGateTTL-time.Second))
	defer cancelRun()

	if err := runCtx.Err(); err != nil {
		return err
	}

	runErr := run(runCtx)

	return errors.Join(runErr, runCtx.Err())
}

// WithTrafficWindow opens the data-plane gate for one trusted, context-bounded worker of the exact
// namespace, generation and sticky address. No IPC operation or application listener calls it yet.
// The namespace must hold no process before the gate opens and after run returns: run starts its
// workers and stops them before it returns.
func (b *ManagedTunnelBackend) WithTrafficWindow(
	ctx context.Context,
	namespace, generation string,
	expectedIP netip.Addr,
	uid uint32,
	healthUntil time.Time,
	run func(context.Context) error,
) error {
	b.sealed.manager.mu.Lock()
	defer b.sealed.manager.mu.Unlock()

	t := b.active

	if t == nil || t.namespace != namespace || t.generation != generation || t.faulted || t.linkRemoved ||
		!expectedIP.IsValid() || t.expectedIPv4 != expectedIP {
		return ErrManagedTunnelUncertain
	}

	if err := b.verifyConfiguredLocked(ctx, t); err != nil {
		return err
	}

	if err := b.requireIdleProbeNamespaceLocked(ctx, namespace); err != nil {
		return err
	}

	if err := b.sealed.firewall.withTrafficGateLocked(ctx, namespace, uid, healthUntil, run); err != nil {
		return err
	}

	if err := b.requireIdleProbeNamespaceLocked(ctx, namespace); err != nil {
		return err
	}

	return b.verifyConfiguredLocked(ctx, t)
}
