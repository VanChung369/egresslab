package agent

import (
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"strings"
	"testing"
	"time"
)

// testdata/nft-lab-monitor-overlay-*.json are REAL captures (nft 1.0.2, Linux 6.6, Ubuntu 22.04 on
// WSL2) of a throwaway namespace sealed with sealLabRules, then the overlay of
// managedMonitorTrafficRules(998) and the probe window for 1.1.1.1 in one transaction: open, after
// the overlay's 10 s element expired (the probe's still had 14 s), and closed. In the same namespace,
// a connection the gate had marked kept flowing under the overlay until its element expired, while
// new connections of UID 998 and 999 timed out.
const overlayCaptureUID = 998

var overlayCaptureHandles = struct{ probe, traffic probeRuleHandles }{
	probe:   probeRuleHandles{input: 24, output: 23},
	traffic: probeRuleHandles{input: 21, output: 20},
}

func TestMonitorOverlayRules(t *testing.T) {
	overlay, err := managedMonitorTrafficRules(1001)
	if err != nil {
		t.Fatal(err)
	}

	gate, _ := managedTrafficRules(1001)

	if strings.Contains(overlay, "ct mark set") ||
		!strings.Contains(overlay, "meta skuid 1001 meta l4proto tcp ct state established ct mark 1701276673 accept") ||
		strings.Count(overlay, "\n") != strings.Count(gate, "\n") {
		t.Fatalf("overlay may admit new connections: %q", overlay)
	}

	// Only the output permit differs from the gate.
	for i, line := range strings.Split(overlay, "\n") {
		if gateLine := strings.Split(gate, "\n")[i]; line != gateLine && !strings.Contains(gateLine, "output") {
			t.Fatalf("overlay changed %q", gateLine)
		}
	}

	for _, uid := range []uint32{0, ^uint32(0)} {
		if _, err := managedMonitorTrafficRules(uid); err == nil {
			t.Fatalf("UID %d accepted", uid)
		}
	}
}

func TestMonitorOverlayRealCapture(t *testing.T) {
	active := probeCapture(t, "nft-lab-monitor-overlay-active.json")
	expired := probeCapture(t, "nft-lab-monitor-overlay-expired.json")
	closed := probeCapture(t, "nft-lab-monitor-overlay-closed.json")
	probeIP := netip.MustParseAddr(managedProbeIP)

	probe, traffic, err := verifyMonitorOverlay(active, overlayCaptureUID, probeIP, true, true)
	if err != nil || probe != overlayCaptureHandles.probe || traffic != overlayCaptureHandles.traffic {
		t.Fatalf("real overlay refused: %+v %+v %v", probe, traffic, err)
	}

	if _, _, err := verifyMonitorOverlay(expired, overlayCaptureUID, probeIP, true, true); err == nil {
		t.Fatal("expired overlay accepted as active")
	}

	// After the probe: the overlay may have expired, the probe window may not.
	if _, _, err := verifyMonitorOverlay(expired, overlayCaptureUID, probeIP, true, false); err != nil {
		t.Fatalf("expired overlay refused after the probe: %v", err)
	}

	if probe, traffic, err := verifyMonitorOverlay(expired, overlayCaptureUID, probeIP, false, false); err != nil ||
		probe != overlayCaptureHandles.probe || traffic != overlayCaptureHandles.traffic {
		t.Fatalf("expired overlay cannot be closed: %v", err)
	}

	if err := verifySealedPolicy(closed); err != nil {
		t.Fatalf("closed overlay left no sealed policy: %v", err)
	}

	if _, _, err := verifyMonitorOverlay(closed, overlayCaptureUID, probeIP, false, false); err == nil {
		t.Fatal("sealed policy accepted as an overlay")
	}

	if _, _, err := verifyMonitorOverlay(active, overlayCaptureUID+1, probeIP, true, true); err == nil {
		t.Fatal("overlay of another UID accepted")
	}

	if _, _, err := verifyMonitorOverlay(active, overlayCaptureUID, netip.MustParseAddr("9.9.9.9"), true, true); err == nil {
		t.Fatal("probe window of another destination accepted")
	}

	// Neither window alone accepts the pair.
	if _, err := verifyManagedProbePolicy(active, true); err == nil {
		t.Fatal("overlay accepted as part of a plain probe window")
	}

	if _, err := verifyTrafficGatePolicy(active, overlayCaptureUID, true); err == nil {
		t.Fatal("overlay accepted as a traffic gate")
	}
}

func TestMonitorOverlayRejectsDrift(t *testing.T) {
	var parsed map[string]any
	if err := json.Unmarshal(probeCapture(t, "nft-lab-monitor-overlay-active.json"), &parsed); err != nil {
		t.Fatal(err)
	}

	fixture := string(encodeRuleset(t, parsed))

	edit := func(change func(items []any) []any) string {
		t.Helper()

		var doc map[string]any
		if err := json.Unmarshal([]byte(fixture), &doc); err != nil {
			t.Fatal(err)
		}

		doc["nftables"] = change(objects(doc))

		return string(encodeRuleset(t, doc))
	}

	index := func(items []any, match func(map[string]any) bool) int {
		t.Helper()

		for i, item := range items {
			for _, value := range item.(map[string]any) {
				if object, ok := value.(map[string]any); ok && match(object) {
					return i
				}
			}
		}

		t.Fatal("object missing from the capture")

		return -1
	}

	ruleWith := func(chain, text string) func(map[string]any) bool {
		return func(object map[string]any) bool {
			expr, _ := json.Marshal(object["expr"])
			return object["chain"] == chain && strings.Contains(string(expr), text)
		}
	}

	swap := func(a, b func(map[string]any) bool) string {
		return edit(func(items []any) []any {
			i, j := index(items, a), index(items, b)
			items[i], items[j] = items[j], items[i]

			return items
		})
	}

	drop := func(match func(map[string]any) bool) string {
		return edit(func(items []any) []any {
			i := index(items, match)
			return append(items[:i:i], items[i+1:]...)
		})
	}

	set := func(name string) func(map[string]any) bool {
		return func(object map[string]any) bool { return object["name"] == name && object["type"] != nil }
	}

	gateOutput, _ := json.Marshal(map[string]any{"rule": map[string]any{
		"family": "inet", "table": labNFTTable, "chain": "output", "handle": 50,
		"expr": json.RawMessage(expectedTrafficRules(overlayCaptureUID)["output"]),
	}})

	// The overlay's output permit replaced by the gate's, which marks new connections.
	markingOutput := edit(func(items []any) []any {
		var expr any
		_ = json.Unmarshal([]byte(expectedTrafficRules(overlayCaptureUID)["output"]), &expr)

		rule := items[index(items, ruleWith("output", "@egresslab_app4"))].(map[string]any)["rule"].(map[string]any)
		rule["expr"] = expr

		return items
	})

	tests := map[string]string{
		"wrong UID":                strings.ReplaceAll(fixture, `"right":998`, `"right":999`),
		"marking output permit":    markingOutput,
		"probe before overlay":     swap(ruleWith("output", "@egresslab_probe4"), ruleWith("output", "@egresslab_app4")),
		"overlay before seal":      swap(ruleWith("output", "@egresslab_app4"), ruleWith("output", `"lo"`)),
		"extended overlay timeout": strings.ReplaceAll(fixture, `"timeout":10`, `"timeout":100`),
		"overlay on eth0":          strings.ReplaceAll(fixture, `"val":"wg0"`, `"val":"eth0"`),
		"probe to 8.8.8.8":         strings.ReplaceAll(fixture, `"val":"1.1.1.1"`, `"val":"8.8.8.8"`),
		"no overlay set":           drop(set(managedTrafficSet)),
		"no probe set":             drop(set(managedProbeSet)),
		"no overlay input permit":  drop(ruleWith("input", "@egresslab_app4")),
		"unknown set": edit(func(items []any) []any {
			var extra any
			_ = json.Unmarshal([]byte(`{"set":{"family":"inet","name":"egresslab_extra","table":"egresslab_lab",`+
				`"type":"ipv4_addr","handle":60,"size":1,"flags":["timeout"]}}`), &extra)

			return append(items, extra)
		}),
		"gate permit beside the overlay": edit(func(items []any) []any {
			var extra any
			_ = json.Unmarshal(gateOutput, &extra)

			return append(items, extra)
		}),
	}

	for name, data := range tests {
		t.Run(name, func(t *testing.T) {
			if data == fixture {
				t.Fatal("fixture edit did not apply")
			}

			if _, _, err := verifyMonitorOverlay([]byte(data), overlayCaptureUID, netip.MustParseAddr(managedProbeIP),
				true, true); err == nil {
				t.Fatal("unsafe composite policy accepted")
			}
		})
	}
}

func TestMonitorOverlayEligible(t *testing.T) {
	now := time.Now()
	alive := func() bool { return true }
	least := now.Add(monitorOverlayOpenBudget + trafficGateTTL + trafficGateCloseBudget)
	enough := least.Add(time.Millisecond)

	for name, tt := range map[string]struct {
		overlay *MonitorTrafficOverlay
		want    bool
	}{
		"eligible":         {&MonitorTrafficOverlay{UID: 998, HealthUntil: enough, Alive: alive}, true},
		"none":             {nil, false},
		"root":             {&MonitorTrafficOverlay{UID: 0, HealthUntil: enough, Alive: alive}, false},
		"invalid UID":      {&MonitorTrafficOverlay{UID: ^uint32(0), HealthUntil: enough, Alive: alive}, false},
		"no liveness":      {&MonitorTrafficOverlay{UID: 998, HealthUntil: enough}, false},
		"streams ended":    {&MonitorTrafficOverlay{UID: 998, HealthUntil: enough, Alive: func() bool { return false }}, false},
		"no time to open":  {&MonitorTrafficOverlay{UID: 998, HealthUntil: least, Alive: alive}, false},
		"health too short": {&MonitorTrafficOverlay{UID: 998, HealthUntil: now.Add(trafficGateTTL + trafficGateCloseBudget), Alive: alive}, false},
		"health expired":   {&MonitorTrafficOverlay{UID: 998, HealthUntil: now.Add(-time.Second), Alive: alive}, false},
	} {
		if got := tt.overlay.eligible(now); got != tt.want {
			t.Errorf("%s: eligible %v", name, got)
		}
	}
}

// overlayKernel models the lab table: sealed, or holding what the last opening transaction put in.
type overlayKernel struct {
	t        *testing.T
	sealed   []byte
	window   []byte
	open     bool
	scripts  []string
	closed   []string
	failDel  bool
	addDelay time.Duration
}

func (k *overlayKernel) list(context.Context, string) ([]byte, error) {
	if k.open {
		return k.window, nil
	}

	return k.sealed, nil
}

func (k *overlayKernel) run(_ context.Context, _ string, script string, checkOnly bool) error {
	switch {
	case strings.HasPrefix(script, "add set"):
		if !checkOnly {
			time.Sleep(k.addDelay)
			k.scripts = append(k.scripts, script)
			k.open = true
		}

	case strings.HasPrefix(script, "delete rule"):
		if k.failDel {
			return errors.New("cleanup failed")
		}

		if !checkOnly {
			k.closed = append(k.closed, script)
			k.open = false
		}

	default:
		k.t.Fatalf("unexpected firewall mutation: %q", script)
	}

	return nil
}

func overlayFirewall(t *testing.T) (*LabFirewall, *overlayKernel) {
	t.Helper()

	f, _ := verifyingFirewall(t)

	if err := f.Seal(context.Background(), firewallTestName); err != nil {
		t.Fatal(err)
	}

	kernel := &overlayKernel{
		t:      t,
		sealed: encodeRuleset(t, sealedRulesetFixture(t)),
		window: probeCapture(t, "nft-lab-monitor-overlay-active.json"),
	}

	f.list, f.run = kernel.list, kernel.run

	return f, kernel
}

func TestMonitoredProbeWindow(t *testing.T) {
	probeIP := netip.MustParseAddr(managedProbeIP)
	overlayScript, _ := managedMonitorTrafficRules(overlayCaptureUID)
	composite := overlayScript + managedProbeRules()

	wantClose := "delete rule inet egresslab_lab input handle 24\n" +
		"delete rule inet egresslab_lab output handle 23\n" +
		"delete rule inet egresslab_lab input handle 21\n" +
		"delete rule inet egresslab_lab output handle 20\n" +
		"delete set inet egresslab_lab egresslab_probe4\n" +
		"delete set inet egresslab_lab egresslab_app4\n"

	healthy := func() *MonitorTrafficOverlay {
		return &MonitorTrafficOverlay{UID: overlayCaptureUID, HealthUntil: time.Now().Add(time.Minute),
			Alive: func() bool { return true }}
	}

	run := func(f *LabFirewall, overlay *MonitorTrafficOverlay, probe func(context.Context) error) error {
		f.manager.mu.Lock()
		defer f.manager.mu.Unlock()

		return f.withMonitoredProbeWindowLocked(context.Background(), firewallTestName, probeIP, overlay, probe)
	}

	t.Run("overlay and probe open and close together", func(t *testing.T) {
		f, kernel := overlayFirewall(t)
		baseline := f.baseline[firewallTestName]

		err := run(f, healthy(), func(context.Context) error {
			if !kernel.open {
				t.Fatal("probe ran without its window")
			}

			// The overlay's element expires during a long probe; the window stays valid.
			kernel.window = probeCapture(t, "nft-lab-monitor-overlay-expired.json")

			return nil
		})

		if err != nil || len(kernel.scripts) != 1 || kernel.scripts[0] != composite || kernel.open ||
			len(kernel.closed) != 1 || kernel.closed[0] != wantClose || f.drifted[firewallTestName] {
			t.Fatalf("overlay window lifecycle: %v %q %q", err, kernel.scripts, kernel.closed)
		}

		if f.baseline[firewallTestName] != baseline || len(f.applied[firewallTestName]) != 1 {
			t.Fatal("temporary overlay became permanent")
		}
	})

	for name, overlay := range map[string]*MonitorTrafficOverlay{
		"no overlay":       nil,
		"streams ended":    {UID: overlayCaptureUID, HealthUntil: time.Now().Add(time.Minute), Alive: func() bool { return false }},
		"health too short": {UID: overlayCaptureUID, HealthUntil: time.Now().Add(trafficGateTTL), Alive: func() bool { return true }},
	} {
		t.Run(name+": the gate stays closed", func(t *testing.T) {
			f, kernel := overlayFirewall(t)
			kernel.window = probeCapture(t, "nft-lab-probe-window.json")

			if err := run(f, overlay, func(context.Context) error { return nil }); err != nil ||
				len(kernel.scripts) != 1 || kernel.scripts[0] != managedProbeRules() || strings.Contains(kernel.closed[0], managedTrafficSet) {
				t.Fatalf("overlay opened without eligibility: %v %q", err, kernel.scripts)
			}
		})
	}

	t.Run("health runs out while opening", func(t *testing.T) {
		f, kernel := overlayFirewall(t)
		kernel.addDelay = monitorOverlayOpenBudget + 300*time.Millisecond

		overlay := healthy()
		overlay.HealthUntil = time.Now().Add(monitorOverlayOpenBudget + trafficGateTTL + trafficGateCloseBudget +
			100*time.Millisecond)

		err := run(f, overlay, func(context.Context) error {
			t.Fatal("probe ran past the overlay's deadline")
			return nil
		})

		if !errors.Is(err, ErrTrafficGate) || kernel.open || len(kernel.closed) != 1 || kernel.closed[0] != wantClose {
			t.Fatalf("late overlay not refused and closed: %v", err)
		}
	})

	t.Run("probe window expired", func(t *testing.T) {
		f, kernel := overlayFirewall(t)

		// Both elements gone, as the kernel lists sets whose element expired.
		var doc map[string]any
		if err := json.Unmarshal(probeCapture(t, "nft-lab-monitor-overlay-expired.json"), &doc); err != nil {
			t.Fatal(err)
		}

		for _, item := range objects(doc) {
			if set, ok := item.(map[string]any)["set"].(map[string]any); ok {
				delete(set, "elem")
			}
		}

		bothExpired := encodeRuleset(t, doc)

		err := run(f, healthy(), func(context.Context) error {
			kernel.window = bothExpired
			return nil
		})

		if !errors.Is(err, ErrProbePolicyDrift) || errors.Is(err, ErrProbeCleanup) || kernel.open ||
			len(kernel.closed) != 1 || kernel.closed[0] != wantClose {
			t.Fatalf("expired probe window accepted or not closed: %v", err)
		}
	})

	t.Run("overlay of another UID", func(t *testing.T) {
		f, kernel := overlayFirewall(t)
		overlay := healthy()
		overlay.UID = overlayCaptureUID + 1

		err := run(f, overlay, func(context.Context) error {
			t.Fatal("probe ran beside a foreign overlay")
			return nil
		})

		// Cleanup cannot identify foreign objects: it refuses, and the lab is drifted.
		if err == nil || !errors.Is(err, ErrProbeCleanup) || !f.drifted[firewallTestName] || !kernel.open {
			t.Fatalf("foreign overlay accepted: %v", err)
		}
	})

	t.Run("unconfirmed close drifts the namespace", func(t *testing.T) {
		f, kernel := overlayFirewall(t)
		kernel.failDel = true

		if err := run(f, healthy(), func(context.Context) error { return nil }); !errors.Is(err, ErrProbeCleanup) ||
			!f.drifted[firewallTestName] {
			t.Fatalf("unconfirmed close accepted: %v", err)
		}
	})
}

// overlayCaptureForDestination is the real overlay capture with its probe element changed, by
// structure, to destination.
func overlayCaptureForDestination(t *testing.T, name string, destination netip.Addr) []byte {
	t.Helper()

	var doc map[string]any
	if err := json.Unmarshal(probeCapture(t, name), &doc); err != nil {
		t.Fatal(err)
	}

	for _, item := range objects(doc) {
		if set, ok := item.(map[string]any)["set"].(map[string]any); ok && set["name"] == managedProbeSet {
			set["elem"].([]any)[0].(map[string]any)["elem"].(map[string]any)["val"] = destination.String()
			return encodeRuleset(t, doc)
		}
	}

	t.Fatal("probe set missing")

	return nil
}

func TestManagedMultiProbeWithOverlay(t *testing.T) {
	setup := func(t *testing.T) (*ManagedTunnelBackend, *managedTestKernel, *probeWindowKernel, *[]string, *string) {
		b, kernel, window, _ := managedProbeFixture(t)
		sources := testManagedHTTPSources(t)
		overlays := new([]string)

		overlayScript, _ := managedMonitorTrafficRules(overlayCaptureUID)

		b.sealed.firewall.run = func(ctx context.Context, namespace, script string, checkOnly bool) error {
			if strings.HasPrefix(script, "add set") {
				window.expectedScript = ""

				for _, source := range sources {
					probe, _ := managedProbeRulesFor(source.destination)

					switch script {
					case probe:
						window.window = probeCaptureForDestination(t, source.destination)
					case overlayScript + probe:
						window.window = overlayCaptureForDestination(t, "nft-lab-monitor-overlay-active.json",
							source.destination)
					default:
						continue
					}

					window.expectedScript, window.destination = script, source.destination

					if !checkOnly {
						*overlays = append(*overlays, script[:len(script)-len(probe)])
					}
				}

				if window.expectedScript == "" {
					t.Fatalf("unexpected window script: %q", script)
				}
			}

			return window.run(ctx, namespace, script, checkOnly)
		}

		observedIP := "8.8.4.4"
		installStickyTestRunner(t, b, kernel, window, &observedIP)

		return b, kernel, window, overlays, &observedIP
	}

	ctx := context.Background()

	t.Run("every window carries the overlay", func(t *testing.T) {
		b, _, window, overlays, _ := setup(t)
		generation := b.active.generation

		alive := 0
		overlay := MonitorTrafficOverlay{UID: overlayCaptureUID, HealthUntil: time.Now().Add(time.Minute),
			Alive: func() bool { alive++; return true }}

		result, err := b.ProbeConfiguredMultiForGenerationWithOverlay(ctx, vpnTestNS, generation, overlay)
		if err != nil || result.TunnelGeneration != generation || len(*overlays) != 2 || (*overlays)[0] == "" ||
			(*overlays)[1] == "" || alive != 2 || window.open || len(window.closed) != 2 {
			t.Fatalf("overlay not carried: %v %q", err, *overlays)
		}

		for _, closed := range window.closed {
			if !strings.Contains(closed, "delete set inet egresslab_lab egresslab_app4") {
				t.Fatalf("overlay not closed with its window: %q", closed)
			}
		}
	})

	t.Run("streams that ended get no overlay", func(t *testing.T) {
		b, _, _, overlays, _ := setup(t)

		calls := 0
		overlay := MonitorTrafficOverlay{UID: overlayCaptureUID, HealthUntil: time.Now().Add(time.Minute),
			Alive: func() bool { calls++; return calls == 1 }}

		if _, err := b.ProbeConfiguredMultiForGenerationWithOverlay(ctx, vpnTestNS, b.active.generation, overlay); err != nil ||
			len(*overlays) != 2 || (*overlays)[0] == "" || (*overlays)[1] != "" {
			t.Fatalf("overlay outlived its streams: %v %q", err, *overlays)
		}
	})

	t.Run("IP drift stops at the first source and faults", func(t *testing.T) {
		b, _, window, overlays, observedIP := setup(t)
		tracked := b.active

		if _, err := b.ProbeConfiguredMulti(ctx, vpnTestNS); err != nil || !tracked.expectedIPv4.IsValid() {
			t.Fatalf("pin failed: %v", err)
		}

		*observedIP = "8.8.8.8"
		opened := window.opened

		overlay := MonitorTrafficOverlay{UID: overlayCaptureUID, HealthUntil: time.Now().Add(time.Minute),
			Alive: func() bool { return true }}

		_, err := b.ProbeConfiguredMultiForGenerationWithOverlay(ctx, vpnTestNS, tracked.generation, overlay)
		if !errors.Is(err, ErrManagedStickyIPChanged) || !errors.Is(err, ErrManagedProbeFailed) || !tracked.faulted ||
			window.opened != opened+1 || window.open || (*overlays)[len(*overlays)-1] == "" {
			t.Fatalf("IP drift not stopped at once: %v", err)
		}
	})

	t.Run("no generation", func(t *testing.T) {
		b, _, window, _, _ := setup(t)

		if _, err := b.ProbeConfiguredMultiForGenerationWithOverlay(ctx, vpnTestNS, "", MonitorTrafficOverlay{}); !errors.Is(err,
			ErrManagedTunnelGenerationMismatch) || window.opened != 0 {
			t.Fatalf("probe without a generation: %v", err)
		}
	})
}
