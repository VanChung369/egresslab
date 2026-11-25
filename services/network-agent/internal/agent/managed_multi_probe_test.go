package agent

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"testing"
	"time"
)

// multiProbeFixture is a configured tunnel whose firewall fake serves, for each window in turn, a
// capture holding that source's destination; it fails the test if two windows overlap.
func multiProbeFixture(t *testing.T) (*ManagedTunnelBackend, *managedTestKernel, *probeWindowKernel, *[]string) {
	t.Helper()

	b, kernel, window, pids := managedProbeFixture(t)
	sources := testManagedHTTPSources(t)

	b.sealed.firewall.run = func(ctx context.Context, namespace, script string, checkOnly bool) error {
		if strings.HasPrefix(script, "add set") {
			index := window.opened
			if window.open || index >= len(sources) || len(window.closed) != index {
				t.Fatal("overlapping or unexpected probe window")
			}

			expected, err := managedProbeRulesFor(sources[index].destination)
			if err != nil {
				t.Fatal(err)
			}

			window.expectedScript = expected
			window.window = probeCaptureForDestination(t, sources[index].destination)
		}

		return window.run(ctx, namespace, script, checkOnly)
	}

	return b, kernel, window, pids
}

func syntheticSourceBody(source managedProbeHTTPSource, ip string) []byte {
	if source.id == managedCloudflareSourceID {
		return []byte("fl=1\nip=" + ip + "\nts=1\n")
	}

	return []byte(ip + "\n")
}

// offsetClock advances by spacing per reading from base, wall and monotonic alike, then moves the
// wall reading by offsets[i] at reading i+1. Readings: 1 start, 2 and 3 the sources, 4 the finish.
func offsetClock(base time.Time, spacing time.Duration, offsets ...time.Duration) managedProbeClock {
	readings := 0

	return func() (time.Time, time.Duration) {
		elapsed := time.Duration(readings+1) * spacing
		wall := base.Add(elapsed)

		if readings < len(offsets) {
			wall = wall.Add(offsets[readings])
		}

		readings++

		return wall, elapsed
	}
}

func TestManagedClockStep(t *testing.T) {
	start := time.Unix(1795500000, 0).UTC()

	for _, tt := range []struct {
		wall, mono time.Duration
		ok         bool
	}{
		{10 * time.Second, 10 * time.Second, true},
		{10*time.Second + maxManagedClockStep, 10 * time.Second, true},
		{10*time.Second - maxManagedClockStep, 10 * time.Second, true},
		{10*time.Second + maxManagedClockStep + time.Millisecond, 10 * time.Second, false},
		{5 * time.Second, 10 * time.Second, false},
		{-time.Second, time.Second, false},
	} {
		err := managedClockStep(start, time.Minute, start.Add(tt.wall), time.Minute+tt.mono)
		if (err == nil) != tt.ok || (err != nil && !errors.Is(err, ErrInvalidObservation)) {
			t.Errorf("wall %v, monotonic %v: %v", tt.wall, tt.mono, err)
		}
	}
}

func TestManagedMultiProbeLifecycle(t *testing.T) {
	tests := []struct {
		mode    string
		windows int   // worker calls, which is also the number of windows opened
		want    error // checked on top of ErrManagedProbeFailed when set
		text    string
	}{
		{mode: "success", windows: 2},
		{mode: "busy before probe", want: ErrNetNSBusy},
		{mode: "drift before probe", text: "fwmark"},
		{mode: "first source failure", windows: 1, text: "first source unavailable"},
		{mode: "worker left running", windows: 1, want: ErrNetNSBusy},
		{mode: "worker left after last source", windows: 2, want: ErrNetNSBusy},
		{mode: "first cleanup failure", windows: 1, want: ErrProbeCleanup},
		{mode: "drift after first source", windows: 1, text: "fwmark"},
		{mode: "cancelled operation", windows: 1, want: context.Canceled},
		{mode: "second source failure", windows: 2, text: "second source unavailable"},
		{mode: "IP mismatch", windows: 2, want: ErrManagedProbeIPMismatch},
		{mode: "private IP", windows: 2, want: ErrInvalidObservation},
		{mode: "second cleanup failure", windows: 2, want: ErrProbeCleanup},
		{mode: "expired second window", windows: 2, want: ErrProbePolicyDrift},
		{mode: "drift after second source", windows: 2, text: "fwmark"},
		{mode: "stale handshake", windows: 2, want: ErrManagedHandshake},
		{mode: "wrong handshake peer", windows: 2, want: ErrManagedHandshake},
		{mode: "clock stepped back between sources", windows: 2, want: ErrInvalidObservation, text: "clock"},
		{mode: "clock stepped forward before finish", windows: 2, want: ErrInvalidObservation, text: "clock"},
		{mode: "clock swung back between sources", windows: 2, want: ErrInvalidObservation, text: "clock"},
		{mode: "clock nudged back between sources", windows: 2, want: ErrInvalidObservation, text: "backwards"},
		{mode: "source pin routed locally", windows: 1, want: ErrManagedNetworkDrift},
		{mode: "handshake after finish", windows: 2, want: ErrManagedHandshake},
		{mode: "uncertain rollback", windows: 2, want: ErrManagedTunnelUncertain},
	}

	for _, tt := range tests {
		t.Run(tt.mode, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			b, kernel, window, pids := multiProbeFixture(t)
			sources := testManagedHTTPSources(t)

			switch tt.mode {
			case "busy before probe":
				*pids = []string{"4242\n"}
			case "worker left running":
				*pids = []string{"", "4242\n"}
			case "worker left after last source":
				*pids = []string{"", "", "", "4242\n"}
			case "drift before probe":
				kernel.wrongMark = true
			}

			var calls []string

			b.multiProbe = &managedMultiProbeConfig{
				identPin: sources[1].destination,
				run: func(probeCtx context.Context, namespace string, source managedProbeHTTPSource) ([]byte, error) {
					index := len(calls)
					if index >= len(sources) || source != sources[index] || namespace != vpnTestNS {
						t.Fatal("unexpected probe source")
					}

					if !window.open || window.opened != index+1 || len(window.closed) != index {
						t.Fatal("worker ran outside its own window")
					}

					if deadline, ok := probeCtx.Deadline(); !ok || time.Until(deadline) > probeExecutionTimeout {
						t.Fatal("worker execution is unbounded")
					}

					calls = append(calls, source.id)

					switch {
					case tt.mode == "first source failure" && index == 0:
						return nil, errors.New("first source unavailable")
					case tt.mode == "first cleanup failure" && index == 0,
						tt.mode == "second cleanup failure" && index == 1:
						window.failDel = true
					case tt.mode == "drift after first source" && index == 0,
						tt.mode == "drift after second source" && index == 1:
						kernel.wrongMark = true
					case tt.mode == "cancelled operation" && index == 0:
						cancel()
					case tt.mode == "second source failure" && index == 1:
						return nil, errors.New("second source unavailable")
					case tt.mode == "IP mismatch" && index == 1:
						return syntheticSourceBody(source, "8.8.8.8"), nil
					case tt.mode == "private IP" && index == 1:
						return syntheticSourceBody(source, "10.0.0.1"), nil
					case tt.mode == "expired second window" && index == 1:
						window.window = probeCapture(t, "nft-lab-probe-expired.json")
					case tt.mode == "stale handshake" && index == 1:
						kernel.wgOverrides["latest-handshakes"] = fmt.Sprintf("%s\t%d", demoKey(2), time.Now().Unix()-181)
					case tt.mode == "wrong handshake peer" && index == 1:
						kernel.wgOverrides["latest-handshakes"] = fmt.Sprintf("%s\t%d", demoKey(4), time.Now().Unix())
					case tt.mode == "uncertain rollback" && index == 1:
						kernel.failDelete = true
						return nil, errors.New("second source unavailable")
					}

					// Synthetic bodies; no request is made.
					return syntheticSourceBody(source, "8.8.4.4"), nil
				},
			}

			switch tt.mode {
			case "clock stepped back between sources":
				b.multiProbe.clock = offsetClock(time.Now().UTC(), time.Second, 0, 0, -1500*time.Millisecond,
					-1500*time.Millisecond)
			case "clock stepped forward before finish":
				b.multiProbe.clock = offsetClock(time.Now().UTC(), time.Second, 0, 0, 0, 5*time.Second)
			case "clock swung back between sources":
				// Within the tolerance of the start each time, but 1.5 s backwards between the two sources.
				b.multiProbe.clock = offsetClock(time.Now().UTC(), time.Second, 0, 750*time.Millisecond,
					-750*time.Millisecond, -750*time.Millisecond)
			case "clock nudged back between sources":
				// 300 ms apart, then 500 ms back: within every tolerance, but the second source predates the first.
				b.multiProbe.clock = offsetClock(time.Now().UTC(), 300*time.Millisecond, 0, 0,
					-500*time.Millisecond, -500*time.Millisecond)
			case "handshake after finish":
				// A steady clock ten minutes behind the kernel's handshake time.
				b.multiProbe.clock = offsetClock(time.Now().UTC().Add(-10*time.Minute), time.Second)
			case "source pin routed locally":
				kernel.networkOverrides["-4 -json route get 9.9.9.9"] = `[{"type":"local","dst":"9.9.9.9","dev":"lo",` +
					`"table":"local","prefsrc":"10.2.0.2","flags":[],"uid":0,"cache":[]}]`
			}

			result, err := b.ProbeConfiguredMulti(ctx, vpnTestNS)

			if len(calls) != tt.windows || window.opened != tt.windows {
				t.Fatalf("worker calls %v, windows opened %d", calls, window.opened)
			}

			if tt.mode == "success" {
				if err != nil {
					t.Fatal(err)
				}

				if result.IPv4.String() != "8.8.4.4" || result.NetworkReady || result.StartedAt.IsZero() ||
					result.FinishedAt.Before(result.StartedAt) || result.HandshakeAt.IsZero() ||
					result.HandshakeAt.After(result.FinishedAt) ||
					len(result.Sources) != len(sources) || !result.ObservedAt.Equal(result.Sources[0].ObservedAt) {
					t.Fatalf("invalid observation: %+v", result)
				}

				if !slices.Equal(calls, []string{managedCloudflareSourceID, managedIdentSourceID}) {
					t.Fatalf("unexpected source order: %v", calls)
				}

				for i, evidence := range result.Sources {
					if evidence.Source != sources[i].id || evidence.DestinationIPv4 != sources[i].destination ||
						evidence.IPv4 != result.IPv4 || evidence.ObservedAt.Before(result.StartedAt) ||
						evidence.ObservedAt.After(result.FinishedAt) {
						t.Fatalf("invalid source evidence: %+v", evidence)
					}
				}

				if window.open || len(window.closed) != 2 || b.active == nil || b.active.faulted {
					t.Fatal("invalid successful lifecycle")
				}

				if err := b.VerifyConfigured(ctx, vpnTestNS); err != nil {
					t.Fatal(err)
				}

				if err := b.Disconnect(ctx, vpnTestNS); err != nil {
					t.Fatal(err)
				}

				return
			}

			if !errors.Is(err, ErrManagedProbeFailed) || (tt.want != nil && !errors.Is(err, tt.want)) ||
				(tt.text != "" && !strings.Contains(err.Error(), tt.text)) {
				t.Fatalf("expected %v %q, got %v", tt.want, tt.text, err)
			}

			if result.IPv4.IsValid() || !result.StartedAt.IsZero() || !result.FinishedAt.IsZero() ||
				!result.ObservedAt.IsZero() || !result.HandshakeAt.IsZero() || result.Sources != nil ||
				result.NetworkReady {
				t.Fatalf("failed attempt returned evidence: %+v", result)
			}

			// A window that could not be closed is left to the kernel timeout, and is remembered.
			cleanupFailed := tt.mode == "first cleanup failure" || tt.mode == "second cleanup failure"
			if window.open != cleanupFailed || errors.Is(err, ErrProbeCleanup) != cleanupFailed ||
				b.sealed.firewall.drifted[vpnTestNS] != cleanupFailed {
				t.Fatalf("unexpected window cleanup state: %v", err)
			}

			if tt.mode == "uncertain rollback" {
				if b.active == nil || !b.active.faulted || kernel.tableRemovals != 0 {
					t.Fatal("uncertain tunnel state was forgotten")
				}

				return
			}

			if b.active != nil || kernel.name != "" || kernel.tableRemovals != 1 {
				t.Fatal("failed attempt did not remove the tunnel")
			}
		})
	}
}

// Refusals before the attempt starts leave the tunnel as it was.
func TestManagedMultiProbeRefusals(t *testing.T) {
	ctx := context.Background()
	b, kernel, window, _ := multiProbeFixture(t)

	b.vpn.probe = nil

	if _, err := b.ProbeConfiguredMulti(ctx, vpnTestNS); !errors.Is(err, ErrManagedProbeUnavailable) {
		t.Fatalf("multi-source probe without configuration: %v", err)
	}

	b.multiProbe = &managedMultiProbeConfig{identPin: netip.MustParseAddr("9.9.9.9")}

	if _, err := b.ProbeConfiguredMulti(ctx, vpnTestNS); !errors.Is(err, ErrManagedProbeUnavailable) {
		t.Fatalf("multi-source probe without a runner: %v", err)
	}

	b.multiProbe.run = func(context.Context, string, managedProbeHTTPSource) ([]byte, error) {
		t.Fatal("a refused attempt reached the worker")
		return nil, nil
	}

	for _, pin := range []netip.Addr{
		{},
		netip.MustParseAddr("1.1.1.1"),
		netip.MustParseAddr("10.0.0.1"),
		netip.MustParseAddr("2001:db8::1"),
	} {
		b.multiProbe.identPin = pin

		if _, err := b.ProbeConfiguredMulti(ctx, vpnTestNS); !errors.Is(err, ErrManagedProbeSourcePolicy) {
			t.Fatalf("source policy with pin %v accepted: %v", pin, err)
		}
	}

	b.multiProbe.identPin = netip.MustParseAddr("9.9.9.9")

	if _, err := b.ProbeConfiguredMulti(ctx, "egresslab-lab-00000000000000bb"); !errors.Is(err, ErrNoManagedTunnel) {
		t.Fatalf("multi-source probe of another namespace: %v", err)
	}

	cancelled, cancel := context.WithCancel(ctx)
	cancel()

	if _, err := b.ProbeConfiguredMulti(cancelled, vpnTestNS); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled multi-source probe: %v", err)
	}

	// A multi-source configuration does not enable the single-source operation.
	if _, err := b.ProbeConfigured(ctx, vpnTestNS); !errors.Is(err, ErrManagedProbeUnavailable) {
		t.Fatalf("legacy probe ran on a multi-source backend: %v", err)
	}

	if b.active == nil || b.active.faulted || kernel.tableRemovals != 0 || window.opened != 0 || window.open {
		t.Fatal("a refused attempt changed the tunnel")
	}

	b.active.faulted = true

	if _, err := b.ProbeConfiguredMulti(ctx, vpnTestNS); !errors.Is(err, ErrManagedTunnelUncertain) ||
		kernel.tableRemovals != 0 || window.opened != 0 {
		t.Fatalf("multi-source probe of a faulted tunnel: %v", err)
	}

	b.active.faulted = false

	if err := b.Disconnect(ctx, vpnTestNS); err != nil {
		t.Fatal(err)
	}
}
