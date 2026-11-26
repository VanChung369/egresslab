package agent

import (
	"fmt"
	"net/netip"
	"strings"
	"time"
)

// MonitorTrafficOverlay keeps the proxy's existing streams flowing while a monitor check probes. UID
// and Alive come from the trusted data plane, never from a request; HealthUntil is the monitoring
// health the streams were admitted on, not the one the check is renewing.
type MonitorTrafficOverlay struct {
	UID         uint32
	HealthUntil time.Time
	Alive       func() bool
}

// monitorOverlayOpenBudget is the least time an eligible overlay has to open and be verified: a
// window that misses its opening deadline faults the generation, so a check that would leave less
// probes without the overlay.
const monitorOverlayOpenBudget = 2 * time.Second

// eligible: the overlay must open in time, and its element expire and the window close, before
// HealthUntil.
func (o *MonitorTrafficOverlay) eligible(now time.Time) bool {
	return o != nil && o.UID != 0 && o.UID != ^uint32(0) && o.Alive != nil && o.Alive() &&
		now.Add(monitorOverlayOpenBudget+trafficGateTTL+trafficGateCloseBudget).Before(o.HealthUntil)
}

// managedMonitorTrafficRules is the traffic gate as reopened around a monitor's probe window: the
// same set, the same input permit, and an output permit that keeps only the established connections
// the gate already marked. It marks nothing, so no new connection leaves.
func managedMonitorTrafficRules(uid uint32) (string, error) {
	rules, err := managedTrafficRules(uid)
	if err != nil {
		return "", err
	}

	old := fmt.Sprintf("meta l4proto tcp ct mark set %d accept", trafficGateConnMark)
	replacement := fmt.Sprintf("meta l4proto tcp ct state established ct mark %d accept", trafficGateConnMark)

	if strings.Count(rules, old) != 1 {
		return "", ErrTrafficGate
	}

	return strings.Replace(rules, old, replacement, 1), nil
}

// expectedMonitorTrafficRules is the canonical form of the overlay's permits; nil, which accepts
// nothing, if the gate's own form changed.
func expectedMonitorTrafficRules(uid uint32) map[string]string {
	rules := expectedTrafficRules(uid)

	old := fmt.Sprintf(`{"mangle":{"key":{"ct":{"key":"mark"}},"value":%d}}`, trafficGateConnMark)
	replacement := fmt.Sprintf(`{"match":{"left":{"ct":{"key":"state"}},"op":"in","right":"established"}},`+
		`{"match":{"left":{"ct":{"key":"mark"}},"op":"==","right":%d}}`, trafficGateConnMark)

	if strings.Count(rules["output"], old) != 1 {
		return nil
	}

	rules["output"] = strings.Replace(rules["output"], old, replacement, 1)

	return rules
}

// verifyMonitorOverlay takes the probe window out of a readback first, then the overlay, and
// requires the sealed policy for the rest: sealed rules, then the overlay's permits, then the
// probe's, each last in its chain. Anything else is refused.
func verifyMonitorOverlay(
	data []byte,
	uid uint32,
	destination netip.Addr,
	probeActive, trafficActive bool,
) (probeRuleHandles, probeRuleHandles, error) {
	if uid == 0 || uid == ^uint32(0) {
		return probeRuleHandles{}, probeRuleHandles{}, ErrTrafficGate
	}

	if _, err := parseCandidateIPv4(destination.String()); err != nil {
		return probeRuleHandles{}, probeRuleHandles{}, ErrProbePolicyDrift
	}

	remaining, probe, err := stripTimedWindow(data, managedProbeSet, expectedProbeRules, func(raw []byte) error {
		return verifyManagedProbeSetFor(raw, probeActive, destination)
	})
	if err != nil {
		return probeRuleHandles{}, probeRuleHandles{}, err
	}

	sealed, traffic, err := stripTimedWindow(remaining, managedTrafficSet, expectedMonitorTrafficRules(uid),
		func(raw []byte) error {
			return verifyTrafficSet(raw, trafficActive)
		})
	if err != nil {
		return probeRuleHandles{}, probeRuleHandles{}, err
	}

	if err := verifySealedPolicy(sealed); err != nil {
		return probeRuleHandles{}, probeRuleHandles{}, fmt.Errorf("%w: %w", ErrProbePolicyDrift, err)
	}

	return probe, traffic, nil
}
