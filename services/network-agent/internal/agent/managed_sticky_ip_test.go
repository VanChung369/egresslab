package agent

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"net/netip"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestManagedTunnelGeneration(t *testing.T) {
	seen := make(map[string]bool)

	for range 100 {
		id, err := newManagedTunnelGeneration()
		if err != nil {
			t.Fatal(err)
		}

		raw, ok := strings.CutPrefix(id, managedTunnelGenerationPrefix)
		decoded, err := hex.DecodeString(raw)

		if !ok || err != nil || len(decoded) != 16 || hex.EncodeToString(decoded) != raw {
			t.Fatalf("invalid generation identifier: %s", id)
		}

		if seen[id] {
			t.Fatal("duplicate generation identifier")
		}

		seen[id] = true
	}
}

// installStickyTestRunner answers every source with *observedIP, as a provider that may change its
// exit address between attempts. No request is made.
func installStickyTestRunner(
	t *testing.T,
	b *ManagedTunnelBackend,
	kernel *managedTestKernel,
	window *probeWindowKernel,
	observedIP *string,
) {
	t.Helper()

	b.multiProbe = &managedMultiProbeConfig{
		identPin: testManagedHTTPSources(t)[1].destination,
		run: func(ctx context.Context, namespace string, source managedProbeHTTPSource) ([]byte, error) {
			if namespace != vpnTestNS || !window.open || window.destination != source.destination {
				t.Fatal("sticky probe ran outside its own firewall window")
			}

			if err := ctx.Err(); err != nil {
				return nil, err
			}

			kernel.wgOverrides["latest-handshakes"] = fmt.Sprintf("%s\t%d", demoKey(2), time.Now().Unix())

			return syntheticSourceBody(source, *observedIP), nil
		},
	}
}

func TestManagedStickyIPLifecycle(t *testing.T) {
	for _, uncertain := range []bool{false, true} {
		t.Run(fmt.Sprintf("uncertain rollback=%t", uncertain), func(t *testing.T) {
			ctx := context.Background()
			b, kernel, window, _ := multiProbeFixture(t)

			observedIP := "8.8.4.4"
			installStickyTestRunner(t, b, kernel, window, &observedIP)

			tunnel := b.active
			if tunnel == nil || tunnel.generation == "" || tunnel.expectedIPv4.IsValid() {
				t.Fatal("new tunnel already pinned")
			}

			generation := tunnel.generation

			// Kernel verification alone pins nothing.
			if err := b.VerifyConfigured(ctx, vpnTestNS); err != nil || tunnel.expectedIPv4.IsValid() {
				t.Fatalf("configured tunnel pinned without consensus: %v", err)
			}

			first, err := b.ProbeConfiguredMulti(ctx, vpnTestNS)
			if err != nil {
				t.Fatal(err)
			}

			if first.IPv4.String() != observedIP || tunnel.expectedIPv4 != first.IPv4 || first.NetworkReady ||
				len(first.Sources) != 2 || b.active != tunnel || tunnel.generation != generation ||
				window.open || window.opened != 2 || len(window.closed) != 2 {
				t.Fatalf("initial pin failed: %+v", first)
			}

			second, err := b.ProbeConfiguredMulti(ctx, vpnTestNS)
			if err != nil || second.IPv4 != first.IPv4 || tunnel.expectedIPv4 != first.IPv4 ||
				tunnel.generation != generation || window.open || window.opened != 4 || len(window.closed) != 4 {
				t.Fatalf("stable IP verification failed: %+v %v", second, err)
			}

			// Both sources agree on another address: consensus passes, the sticky gate refuses.
			observedIP = "8.8.8.8"

			if uncertain {
				kernel.failDelete = true
			}

			changed, err := b.ProbeConfiguredMulti(ctx, vpnTestNS)
			if !errors.Is(err, ErrManagedStickyIPChanged) || !errors.Is(err, ErrManagedProbeFailed) {
				t.Fatalf("IP change not refused: %v", err)
			}

			if !reflect.DeepEqual(changed, ManagedMultiProbeObservation{}) {
				t.Fatalf("sticky violation returned evidence: %+v", changed)
			}

			if !tunnel.faulted || tunnel.expectedIPv4 != first.IPv4 {
				t.Fatal("sticky violation replaced the original pin")
			}

			if window.open || window.opened != 6 || len(window.closed) != 6 {
				t.Fatal("firewall not resealed after the sticky violation")
			}

			if uncertain {
				if !errors.Is(err, ErrManagedTunnelUncertain) || b.active != tunnel || kernel.tableRemovals != 0 {
					t.Fatal("uncertain tunnel state was forgotten")
				}

				if _, err := b.ProbeConfiguredMulti(ctx, vpnTestNS); !errors.Is(err, ErrManagedTunnelUncertain) ||
					window.opened != 6 {
					t.Fatalf("faulted tunnel probed again: %v", err)
				}

				// A later successful cleanup, not an override of the pin.
				kernel.failDelete = false

				if err := b.CleanupStage(ctx, vpnTestNS); err != nil {
					t.Fatal(err)
				}
			}

			if b.active != nil || kernel.name != "" || kernel.tableRemovals != 1 {
				t.Fatal("sticky violation did not remove the tunnel")
			}
		})
	}
}

func TestManagedStickyIPNewGeneration(t *testing.T) {
	ctx := context.Background()
	b, kernel, window, _ := multiProbeFixture(t)

	observedIP := "8.8.4.4"
	installStickyTestRunner(t, b, kernel, window, &observedIP)

	first, err := b.ProbeConfiguredMulti(ctx, vpnTestNS)
	if err != nil {
		t.Fatal(err)
	}

	old := b.active
	if old == nil || old.expectedIPv4 != first.IPv4 {
		t.Fatal("old generation not pinned")
	}

	oldGeneration := old.generation

	if err := b.Disconnect(ctx, vpnTestNS); err != nil || b.active != nil {
		t.Fatalf("confirmed disconnect kept the tunnel: %v", err)
	}

	// Same backend, namespace and config: an entirely new tunnel.
	if err := b.connectConfig(ctx, vpnTestNS, vpnTestConfig(t)); err != nil {
		t.Fatal(err)
	}

	current := b.active
	if current == nil || current == old || current.generation == "" || current.generation == oldGeneration ||
		current.expectedIPv4.IsValid() {
		t.Fatal("new generation inherited old sticky state")
	}

	// The old tunnel is never the target of a pin operation.
	b.sealed.manager.mu.Lock()
	err = b.acceptStickyConsensusLocked(old, managedProbeConsensus{
		ipv4:       first.IPv4,
		observedAt: first.ObservedAt,
		sourceIDs:  []string{managedCloudflareSourceID, managedIdentSourceID},
	})
	b.sealed.manager.mu.Unlock()

	if !errors.Is(err, ErrManagedTunnelUncertain) || current.expectedIPv4.IsValid() {
		t.Fatalf("old generation changed the current state: %v", err)
	}

	// The new generation pins only through its own complete verification.
	observedIP = "8.8.8.8"

	second, err := b.ProbeConfiguredMulti(ctx, vpnTestNS)
	if err != nil || second.IPv4.String() != observedIP || current.expectedIPv4 != second.IPv4 ||
		old.expectedIPv4 != first.IPv4 {
		t.Fatalf("new generation verification failed: %+v %v", second, err)
	}

	if window.open || window.opened != 4 || len(window.closed) != 4 {
		t.Fatal("unexpected firewall window state")
	}

	if err := b.Disconnect(ctx, vpnTestNS); err != nil || b.active != nil || kernel.tableRemovals != 2 {
		t.Fatalf("incomplete generation cleanup: %v", err)
	}
}

func TestManagedStickyIPRejectsLegacyRunner(t *testing.T) {
	ctx := context.Background()
	b, kernel, window, _ := multiProbeFixture(t)

	observedIP := "8.8.4.4"
	installStickyTestRunner(t, b, kernel, window, &observedIP)

	// A single-source runner set on a multi-source backend by mistake.
	legacyCalls := 0
	b.vpn.probe = func(context.Context, string, string) ([]byte, error) {
		legacyCalls++
		return []byte("ip=8.8.8.8\n"), nil
	}

	if _, err := b.ProbeConfigured(ctx, vpnTestNS); !errors.Is(err, ErrManagedProbeUnavailable) {
		t.Fatalf("legacy probe accepted: %v", err)
	}

	if legacyCalls != 0 || window.opened != 0 || b.active.expectedIPv4.IsValid() || b.active.faulted {
		t.Fatal("legacy probe changed the tunnel")
	}

	result, err := b.ProbeConfiguredMulti(ctx, vpnTestNS)
	if err != nil || result.IPv4 != b.active.expectedIPv4 {
		t.Fatalf("multi-source verification failed: %v", err)
	}

	if err := b.Disconnect(ctx, vpnTestNS); err != nil {
		t.Fatal(err)
	}
}

func TestManagedStickyIPFailureAfterPin(t *testing.T) {
	for _, mode := range []string{"source unavailable", "source disagreement", "first source failure"} {
		t.Run(mode, func(t *testing.T) {
			ctx := context.Background()
			b, kernel, window, _ := multiProbeFixture(t)

			observedIP := "8.8.4.4"
			installStickyTestRunner(t, b, kernel, window, &observedIP)

			first, err := b.ProbeConfiguredMulti(ctx, vpnTestNS)
			if err != nil {
				t.Fatal(err)
			}

			tracked := b.active
			original := b.multiProbe.run

			b.multiProbe.run = func(ctx context.Context, namespace string, source managedProbeHTTPSource) ([]byte, error) {
				switch {
				case mode == "first source failure" && source.id == managedCloudflareSourceID:
					return nil, errors.New("first source unavailable")
				case mode == "first source failure" || source.id != managedIdentSourceID:
					return original(ctx, namespace, source)
				case mode == "source unavailable":
					return nil, errors.New("second source unavailable")
				default:
					return syntheticSourceBody(source, "8.8.8.8"), nil
				}
			}

			result, err := b.ProbeConfiguredMulti(ctx, vpnTestNS)
			if !errors.Is(err, ErrManagedProbeFailed) || !reflect.DeepEqual(result, ManagedMultiProbeObservation{}) {
				t.Fatalf("failed verification returned evidence: %+v %v", result, err)
			}

			if mode == "source disagreement" && !errors.Is(err, ErrManagedProbeIPMismatch) {
				t.Fatalf("wrong consensus failure: %v", err)
			}

			if !tracked.faulted || tracked.expectedIPv4 != first.IPv4 {
				t.Fatal("failed verification overwrote the pin")
			}

			windows := 4
			if mode == "first source failure" {
				windows = 3
			}

			if b.active != nil || window.open || window.opened != windows || len(window.closed) != windows ||
				kernel.tableRemovals != 1 {
				t.Fatal("incomplete cleanup after the failed verification")
			}
		})
	}
}

// The gate on its own: only consensus for the active, healthy generation counts, and the pin is
// set once.
func TestAcceptStickyConsensus(t *testing.T) {
	b, _, _, _ := multiProbeFixture(t)
	tunnel := b.active
	a, other := netip.MustParseAddr("8.8.4.4"), netip.MustParseAddr("8.8.8.8")

	valid := func(ip netip.Addr) managedProbeConsensus {
		return managedProbeConsensus{ipv4: ip, observedAt: time.Now(),
			sourceIDs: []string{managedCloudflareSourceID, managedIdentSourceID}}
	}

	accept := func(c managedProbeConsensus) error {
		b.sealed.manager.mu.Lock()
		defer b.sealed.manager.mu.Unlock()

		return b.acceptStickyConsensusLocked(tunnel, c)
	}

	for name, tt := range map[string]struct {
		consensus managedProbeConsensus
		want      error
	}{
		"private address": {valid(netip.MustParseAddr("10.0.0.1")), ErrInvalidObservation},
		"IPv6 address":    {valid(netip.MustParseAddr("2001:4860::1")), ErrInvalidObservation},
		"no address": {managedProbeConsensus{observedAt: time.Now(), sourceIDs: valid(a).sourceIDs},
			ErrInvalidObservation},
		"no time": {managedProbeConsensus{ipv4: a, sourceIDs: valid(a).sourceIDs},
			ErrManagedProbeEvidenceIncomplete},
		"one source": {managedProbeConsensus{ipv4: a, observedAt: time.Now(),
			sourceIDs: []string{managedCloudflareSourceID}}, ErrManagedProbeEvidenceIncomplete},
	} {
		if err := accept(tt.consensus); !errors.Is(err, tt.want) || tunnel.expectedIPv4.IsValid() {
			t.Errorf("%s before the pin: %v", name, err)
		}
	}

	if err := accept(valid(a)); err != nil || tunnel.expectedIPv4 != a {
		t.Fatalf("first consensus not pinned: %v", err)
	}

	if err := accept(valid(a)); err != nil {
		t.Fatalf("matching consensus refused: %v", err)
	}

	if err := accept(valid(other)); !errors.Is(err, ErrManagedStickyIPChanged) || tunnel.expectedIPv4 != a {
		t.Fatalf("changed address: %v", err)
	}

	for name, edit := range map[string]func(*managedTunnel){
		"faulted":       func(t *managedTunnel) { t.faulted = true },
		"link removed":  func(t *managedTunnel) { t.linkRemoved = true },
		"no generation": func(t *managedTunnel) { t.generation = "" },
	} {
		saved := *tunnel
		edit(tunnel)

		if err := accept(valid(a)); !errors.Is(err, ErrManagedTunnelUncertain) {
			t.Errorf("%s tunnel accepted consensus: %v", name, err)
		}

		*tunnel = saved
	}

	// A healthy tunnel object that is not the active one (a stale copy, say) is refused too.
	stale := *tunnel
	stale.generation, stale.expectedIPv4 = "tunnelgen_ffffffffffffffffffffffffffffffff", netip.Addr{}

	for name, target := range map[string]*managedTunnel{"nil": nil, "inactive": &stale} {
		b.sealed.manager.mu.Lock()
		err := b.acceptStickyConsensusLocked(target, valid(other))
		b.sealed.manager.mu.Unlock()

		if !errors.Is(err, ErrManagedTunnelUncertain) || tunnel.expectedIPv4 != a || stale.expectedIPv4.IsValid() {
			t.Errorf("%s tunnel: %v", name, err)
		}
	}
}

func TestManagedProbeGenerationBinding(t *testing.T) {
	ctx := context.Background()
	b, kernel, window, _ := multiProbeFixture(t)

	observedIP := "8.8.4.4"
	installStickyTestRunner(t, b, kernel, window, &observedIP)

	old, err := b.CurrentTunnelGeneration(vpnTestNS)
	if err != nil || old != b.active.generation {
		t.Fatalf("missing tunnel generation: %v", err)
	}

	if err := b.Disconnect(ctx, vpnTestNS); err != nil {
		t.Fatal(err)
	}

	if _, err := b.CurrentTunnelGeneration(vpnTestNS); !errors.Is(err, ErrNoManagedTunnel) {
		t.Fatalf("removed generation still reported: %v", err)
	}

	if err := b.connectConfig(ctx, vpnTestNS, vpnTestConfig(t)); err != nil {
		t.Fatal(err)
	}

	current, err := b.CurrentTunnelGeneration(vpnTestNS)
	if err != nil || current == "" || current == old {
		t.Fatalf("generation reused after reconnect: %v", err)
	}

	tracked := b.active

	for _, wrong := range []string{"", old, "tunnelgen_invalid"} {
		result, err := b.ProbeConfiguredMultiForGeneration(ctx, vpnTestNS, wrong)
		if !errors.Is(err, ErrManagedTunnelGenerationMismatch) || !reflect.DeepEqual(result, ManagedMultiProbeObservation{}) {
			t.Fatalf("generation %q accepted: %v", wrong, err)
		}
	}

	if window.opened != 0 || b.active != tracked || tracked.faulted || tracked.expectedIPv4.IsValid() {
		t.Fatal("a refused generation changed the tunnel")
	}

	result, err := b.ProbeConfiguredMultiForGeneration(ctx, vpnTestNS, current)
	if err != nil || result.TunnelGeneration != current || result.IPv4.String() != observedIP || window.open ||
		window.opened != 2 || tracked.expectedIPv4 != result.IPv4 {
		t.Fatalf("current generation probe failed: %+v %v", result, err)
	}

	// The unbound entry point reports the generation too; the V1 adapter drops it.
	if plain, err := b.ProbeConfiguredMulti(ctx, vpnTestNS); err != nil || plain.TunnelGeneration != current {
		t.Fatalf("unbound probe: %+v %v", plain, err)
	}

	if err := b.Disconnect(ctx, vpnTestNS); err != nil {
		t.Fatal(err)
	}
}

func TestCurrentTunnelGenerationRefusals(t *testing.T) {
	b, _, _, _ := multiProbeFixture(t)

	if _, err := b.CurrentTunnelGeneration(vpnTestNS); !errors.Is(err, ErrManagedProbeUnavailable) {
		t.Fatalf("generation of a backend without the multi-source probe: %v", err)
	}

	observedIP := "8.8.4.4"
	installStickyTestRunner(t, b, nil, nil, &observedIP)

	if _, err := b.CurrentTunnelGeneration("egresslab-lab-00000000000000bb"); !errors.Is(err, ErrNoManagedTunnel) {
		t.Fatalf("generation of another namespace: %v", err)
	}

	for name, edit := range map[string]func(*managedTunnel){
		"faulted":       func(t *managedTunnel) { t.faulted = true },
		"link removed":  func(t *managedTunnel) { t.linkRemoved = true },
		"no generation": func(t *managedTunnel) { t.generation = "" },
	} {
		saved := *b.active
		edit(b.active)

		if _, err := b.CurrentTunnelGeneration(vpnTestNS); !errors.Is(err, ErrManagedTunnelUncertain) {
			t.Errorf("%s tunnel: %v", name, err)
		}

		*b.active = saved
	}

	if generation, err := b.CurrentTunnelGeneration(vpnTestNS); err != nil || generation != b.active.generation {
		t.Fatalf("healthy tunnel: %v", err)
	}
}
