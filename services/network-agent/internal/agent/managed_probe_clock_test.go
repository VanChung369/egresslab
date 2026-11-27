package agent

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"testing"
	"time"
)

// A wall-clock step alone ends an attempt without evidence and leaves the tunnel, like a source
// without an answer. A step together with anything else still faults it.
func TestManagedMultiProbeClockStepped(t *testing.T) {
	const ms = time.Millisecond

	tests := []struct {
		mode    string
		spacing time.Duration   // between clock readings; 1 s when zero
		offsets []time.Duration // wall-clock offsets of the readings: start, after each source, finish
		windows int
		soft    bool
		want    error
		text    string
	}{
		{mode: "steady within tolerance", offsets: []time.Duration{0, 900 * ms, 900 * ms, 900 * ms}, windows: 2},
		{mode: "stepped forward as on WSL", offsets: []time.Duration{0, 1100 * ms}, windows: 1, soft: true},
		{mode: "stepped forward before finish", offsets: []time.Duration{0, 0, 0, 5 * time.Second}, windows: 2, soft: true},
		{mode: "stepped back between sources", offsets: []time.Duration{0, 0, -1500 * ms, -1500 * ms}, windows: 2, soft: true},
		// Within the tolerance of the start each time, but 1.5 s backwards between the two sources.
		{mode: "swung back between sources", offsets: []time.Duration{0, 750 * ms, -750 * ms, -750 * ms}, windows: 2,
			soft: true},
		// 300 ms apart, then 500 ms back: within every tolerance, but the second source predates the first.
		{mode: "nudged back between sources", spacing: 300 * ms, offsets: []time.Duration{0, 0, -500 * ms, -500 * ms},
			windows: 2, soft: true},
		{mode: "stepped, window not closed", offsets: []time.Duration{0, 0, 2 * time.Second}, windows: 2,
			want: ErrProbeCleanup},
		{mode: "stepped, then drift", offsets: []time.Duration{0, 0, 2 * time.Second}, windows: 2, text: "fwmark"},
		{mode: "stepped, pinned address changed", offsets: []time.Duration{0, 0, 2 * time.Second}, windows: 2,
			want: ErrManagedStickyIPChanged},
		{mode: "stepped, sources disagree", offsets: []time.Duration{0, 0, 2 * time.Second}, windows: 2,
			want: ErrManagedProbeIPMismatch},
		{mode: "stepped at the finish, wrong handshake peer", offsets: []time.Duration{0, 0, 0, 5 * time.Second},
			windows: 2, want: ErrManagedHandshake},
	}

	for _, tt := range tests {
		t.Run(tt.mode, func(t *testing.T) {
			ctx := context.Background()

			b, kernel, window, _ := multiProbeFixture(t)
			sources := testManagedHTTPSources(t)
			tracked := b.active

			switch tt.mode {
			case "stepped, pinned address changed":
				tracked.expectedIPv4 = netip.MustParseAddr("8.8.4.4")
			case "stepped at the finish, wrong handshake peer":
				kernel.wgOverrides["latest-handshakes"] = fmt.Sprintf("%s	%d", demoKey(4), time.Now().Unix())
			}

			spacing := tt.spacing
			if spacing == 0 {
				spacing = time.Second
			}

			calls := 0

			b.multiProbe = &managedMultiProbeConfig{
				identPin: sources[1].destination,
				clock:    offsetClock(time.Now().UTC(), spacing, tt.offsets...),
				run: func(_ context.Context, _ string, source managedProbeHTTPSource) ([]byte, error) {
					index := calls
					calls++

					if index == 1 {
						switch tt.mode {
						case "stepped, window not closed":
							window.failDel = true
						case "stepped, then drift":
							kernel.wrongMark = true
						case "stepped, pinned address changed", "stepped, sources disagree":
							return syntheticSourceBody(source, "8.8.8.8"), nil
						}
					}

					return syntheticSourceBody(source, "8.8.4.4"), nil
				},
			}

			pinned := tracked.expectedIPv4

			result, err := b.ProbeConfiguredMultiForGeneration(ctx, vpnTestNS, tracked.generation)

			if calls != tt.windows || window.opened != tt.windows {
				t.Fatalf("worker calls %d, windows opened %d", calls, window.opened)
			}

			if tt.windows == 2 && !tt.soft && tt.want == nil && tt.text == "" {
				if err != nil || result.IPv4.String() != "8.8.4.4" {
					t.Fatalf("a step within the tolerance failed the attempt: %v", err)
				}

				return
			}

			if result.IPv4.IsValid() || result.Sources != nil || !result.FinishedAt.IsZero() {
				t.Fatalf("an attempt with a clock step returned evidence: %+v", result)
			}

			if tt.soft {
				if !errors.Is(err, ErrManagedProbeSourceUnavailable) || errors.Is(err, ErrManagedProbeFailed) ||
					!strings.Contains(err.Error(), managedClockStepReason) {
					t.Fatalf("expected a clock step without a fault, got %v", err)
				}

				if b.active != tracked || tracked.faulted || tracked.expectedIPv4 != pinned || kernel.tableRemovals != 0 ||
					window.open || len(window.closed) != window.opened || b.sealed.firewall.drifted[vpnTestNS] {
					t.Fatal("a clock step changed the tunnel, its pin or its firewall")
				}

				if err := b.VerifyConfigured(ctx, vpnTestNS); err != nil {
					t.Fatal(err)
				}

				// The next attempt, on a steady clock, runs as usual.
				b.multiProbe.clock = offsetClock(time.Now().UTC(), time.Second)

				if result, err := b.ProbeConfiguredMultiForGeneration(ctx, vpnTestNS, tracked.generation); err != nil ||
					result.IPv4.String() != "8.8.4.4" {
					t.Fatalf("the probe after a clock step: %v", err)
				}

				return
			}

			if errors.Is(err, ErrManagedProbeSourceUnavailable) || !errors.Is(err, ErrManagedProbeFailed) ||
				(tt.want != nil && !errors.Is(err, tt.want)) || (tt.text != "" && !strings.Contains(err.Error(), tt.text)) {
				t.Fatalf("expected a failure %v %q, got %v", tt.want, tt.text, err)
			}

			if b.active != nil || kernel.tableRemovals != 1 {
				t.Fatal("a clock step on top of a failure kept the tunnel")
			}
		})
	}
}
