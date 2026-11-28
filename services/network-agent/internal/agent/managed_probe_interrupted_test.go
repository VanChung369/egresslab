package agent

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptrace"
	"net/netip"
	"strings"
	"testing"
	"time"
)

func TestProbeTLSPrefix(t *testing.T) {
	for _, tt := range []struct {
		received []byte
		tls      bool
	}{
		{nil, false},
		{[]byte{22}, false},
		{[]byte{22, 3}, true},
		{[]byte{22, 3, 3, 0}, true},
		{[]byte{21, 3}, false},
		{[]byte{23, 3}, false},
		{[]byte{22, 4}, false},
		{[]byte("HTTP/1.1"), false},
	} {
		var trace probeConnTrace
		for _, b := range tt.received {
			trace.record([]byte{b})
		}

		if trace.tlsPrefix() != tt.tls {
			t.Errorf("%v: TLS prefix %v", tt.received, !tt.tls)
		}
	}
}

type scriptedTransport func(*http.Request) (*http.Response, error)

func (f scriptedTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// The request's deadline can be what Do returns after the handshake itself was refused; the refusal
// still decides.
func TestProbeHandshakeRefusedAtTheDeadline(t *testing.T) {
	for name, tt := range map[string]struct {
		handshake error
		reason    string
	}{
		"refused, then the deadline": {x509.UnknownAuthorityError{}, "HTTPS_TLS_FAILED"},
		"cut by the deadline":        {context.DeadlineExceeded, "HTTPS_TLS_INTERRUPTED"},
	} {
		client := &http.Client{Transport: scriptedTransport(func(r *http.Request) (*http.Response, error) {
			trace := r.Context().Value(probeReceivedKey{}).(*probeConnTrace)
			trace.record([]byte{22, 3, 3})
			trace.received.Store(true)

			httptrace.ContextClientTrace(r.Context()).TLSHandshakeDone(tls.ConnectionState{}, tt.handshake)

			return nil, context.DeadlineExceeded
		})}

		if _, err := readManagedProbeHTTPS(context.Background(), client, "https://example.com/"); managedProbeReasonOf(err) != tt.reason {
			t.Errorf("%s: want %s, got %v", name, tt.reason, err)
		}
	}
}

// On a pinned generation, one source's handshake cut short is outweighed by every other source
// answering the pin in the same attempt: nothing is renewed and the tunnel stays. Anything less, or
// anything more, faults as before.
func TestManagedMultiProbeInterrupted(t *testing.T) {
	cut := probeSourceFailure("HTTPS_TLS_INTERRUPTED", ErrManagedProbeFailed)

	tests := []struct {
		mode  string
		cut   int // the source whose handshake is cut short
		calls int
		soft  bool
		want  error
		text  string
	}{
		{mode: "first source, pin confirmed", cut: 0, calls: 2, soft: true},
		{mode: "second source, pin confirmed", cut: 1, calls: 2, soft: true},
		{mode: "no pin", cut: 0, calls: 1, text: "HTTPS_TLS_INTERRUPTED"},
		{mode: "other source without an answer", cut: 0, calls: 2, text: "unconfirmed (HTTPS_NO_ANSWER)"},
		{mode: "other source clock stepped", cut: 0, calls: 2, text: "unconfirmed (WALL_CLOCK_STEPPED)"},
		{mode: "both sources cut", cut: 0, calls: 2, text: "source ident_me"},
		{mode: "other source sees another address", cut: 0, calls: 2, want: ErrManagedStickyIPChanged},
		{mode: "confirmed, then a step at the finish", cut: 0, calls: 2, want: ErrManagedClockStepped},
		{mode: "wrong handshake peer", cut: 0, calls: 2, want: ErrManagedHandshake},
		{mode: "window not closed", cut: 0, calls: 1, want: ErrProbeCleanup},
		{mode: "drift", cut: 0, calls: 1, text: "fwmark"},
		{mode: "worker left running", cut: 0, calls: 1, want: ErrNetNSBusy},
		{mode: "worker left running on the last source", cut: 1, calls: 2, want: ErrNetNSBusy},
		{mode: "drift on the last source", cut: 1, calls: 2, text: "fwmark"},
		{mode: "cancelled", cut: 0, calls: 1, want: context.Canceled},
		{mode: "cancelled on the last source", cut: 1, calls: 2, want: context.Canceled},
		{mode: "expired window", cut: 0, calls: 1, want: ErrProbePolicyDrift},
		{mode: "wrapped", cut: 0, calls: 1, text: "HTTPS_TLS_INTERRUPTED"},
		{mode: "TLS failed", cut: 0, calls: 1, text: "HTTPS_TLS_FAILED"},
		{mode: "TLS alert", cut: 0, calls: 1, text: "HTTPS_TLS_ALERT"},
	}

	for _, tt := range tests {
		t.Run(tt.mode, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			b, kernel, window, pids := multiProbeFixture(t)
			sources := testManagedHTTPSources(t)
			tracked := b.active

			pin := netip.MustParseAddr("8.8.4.4")
			if tt.mode != "no pin" {
				tracked.expectedIPv4 = pin
			}

			switch tt.mode {
			case "worker left running":
				*pids = []string{"", "4242\n"}
			case "worker left running on the last source":
				*pids = []string{"", "", "", "4242\n"}
			case "wrong handshake peer":
				kernel.wgOverrides["latest-handshakes"] = fmt.Sprintf("%s\t%d", demoKey(4), time.Now().Unix())
			}

			// The cut source reads no clock, so the second reading is the other source's: 2 s ahead.
			var clock managedProbeClock
			switch tt.mode {
			case "other source clock stepped":
				clock = offsetClock(time.Now().UTC(), time.Second, 0, 2*time.Second)
			case "confirmed, then a step at the finish":
				clock = offsetClock(time.Now().UTC(), time.Second, 0, 0, 5*time.Second)
			}

			calls := 0

			b.multiProbe = &managedMultiProbeConfig{
				identPin: sources[1].destination,
				clock:    clock,
				run: func(_ context.Context, _ string, source managedProbeHTTPSource) ([]byte, error) {
					index := calls
					calls++

					if index != tt.cut {
						switch tt.mode {
						case "other source without an answer":
							return nil, probeSourceFailure("HTTPS_NO_ANSWER", ErrManagedProbeFailed)
						case "both sources cut":
							return nil, cut
						case "other source sees another address":
							return syntheticSourceBody(source, "8.8.8.8"), nil
						}

						return syntheticSourceBody(source, "8.8.4.4"), nil
					}

					switch tt.mode {
					case "window not closed":
						window.failDel = true
					case "drift", "drift on the last source":
						kernel.wrongMark = true
					case "cancelled", "cancelled on the last source":
						cancel()
					case "expired window":
						window.window = probeCapture(t, "nft-lab-probe-expired.json")
					case "wrapped":
						return nil, fmt.Errorf("worker: %w", cut)
					case "TLS failed":
						return nil, probeSourceFailure("HTTPS_TLS_FAILED", ErrManagedProbeFailed)
					case "TLS alert":
						return nil, probeSourceFailure("HTTPS_TLS_ALERT", ErrManagedProbeFailed)
					}

					return nil, cut
				},
			}

			result, err := b.ProbeConfiguredMultiForGeneration(ctx, vpnTestNS, tracked.generation)

			if calls != tt.calls || window.opened != tt.calls {
				t.Fatalf("worker calls %d, windows opened %d; err %v", calls, window.opened, err)
			}

			if result.IPv4.IsValid() || result.Sources != nil || !result.FinishedAt.IsZero() {
				t.Fatalf("an attempt with a handshake cut short returned evidence: %+v", result)
			}

			if tt.soft {
				if !errors.Is(err, ErrManagedProbeSourceUnavailable) || errors.Is(err, ErrManagedProbeFailed) ||
					!strings.Contains(err.Error(), "HTTPS_TLS_INTERRUPTED") {
					t.Fatalf("expected a confirmed pin without a fault, got %v", err)
				}

				if b.active != tracked || tracked.faulted || tracked.expectedIPv4 != pin || kernel.tableRemovals != 0 ||
					window.open || len(window.closed) != window.opened || b.sealed.firewall.drifted[vpnTestNS] {
					t.Fatal("a confirmed pin changed the tunnel, its pin or its firewall")
				}

				if err := b.VerifyConfigured(ctx, vpnTestNS); err != nil {
					t.Fatal(err)
				}

				b.multiProbe.clock = nil
				b.multiProbe.run = func(_ context.Context, _ string, source managedProbeHTTPSource) ([]byte, error) {
					return syntheticSourceBody(source, "8.8.4.4"), nil
				}

				if result, err := b.ProbeConfiguredMultiForGeneration(ctx, vpnTestNS, tracked.generation); err != nil ||
					result.IPv4 != pin {
					t.Fatalf("the probe after a confirmed pin: %v", err)
				}

				return
			}

			if errors.Is(err, ErrManagedProbeSourceUnavailable) || !errors.Is(err, ErrManagedProbeFailed) ||
				(tt.want != nil && !errors.Is(err, tt.want)) || (tt.text != "" && !strings.Contains(err.Error(), tt.text)) {
				t.Fatalf("expected a failure %v %q, got %v", tt.want, tt.text, err)
			}

			if b.active != nil || kernel.tableRemovals != 1 {
				t.Fatal("a failure kept the tunnel")
			}
		})
	}
}
