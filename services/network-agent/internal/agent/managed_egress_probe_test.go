package agent

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"testing"
	"time"
)

// managedProbeFixture is a connected managed tunnel whose lab firewall is the real sealed capture
// and, while the window is open, the real window capture. The probe never touches the network.
func managedProbeFixture(t *testing.T) (*ManagedTunnelBackend, *managedTestKernel, *probeWindowKernel, *[]string) {
	t.Helper()

	b, kernel := newManagedTunnelFixture(t)

	if err := b.connectConfig(context.Background(), vpnTestNS, vpnTestConfig(t)); err != nil {
		t.Fatal(err)
	}

	window := &probeWindowKernel{
		t:      t,
		sealed: encodeRuleset(t, sealedRulesetFixture(t)),
		window: probeCapture(t, "nft-lab-probe-window.json"),
	}

	b.vpn.firewall.list, b.vpn.firewall.run = window.list, window.run

	pids := &[]string{}
	base := b.sealed.manager.run

	b.sealed.manager.run = func(ctx context.Context, args ...string) ([]byte, error) {
		if slices.Equal(args, []string{"netns", "pids", vpnTestNS}) {
			if len(*pids) == 0 {
				return nil, nil
			}

			current := (*pids)[0]
			*pids = (*pids)[1:]

			return []byte(current), nil
		}

		return base(ctx, args...)
	}

	kernel.wgOverrides["latest-handshakes"] = fmt.Sprintf("%s\t%d", demoKey(2), time.Now().Unix())

	return b, kernel, window, pids
}

func TestManagedEgressProbe(t *testing.T) {
	for _, mode := range []string{
		"success",
		"busy namespace",
		"worker left running",
		"pre-probe drift",
		"HTTP failure",
		"private IP",
		"no handshake",
		"stale handshake",
		"wrong peer",
		"post-probe drift",
		"window cleanup failure",
		"uncertain tunnel cleanup",
	} {
		t.Run(mode, func(t *testing.T) {
			ctx := context.Background()
			b, kernel, window, pids := managedProbeFixture(t)

			switch mode {
			case "busy namespace":
				*pids = []string{"123\n"}
			case "worker left running":
				*pids = []string{"", "4242\n"}
			case "pre-probe drift":
				kernel.wrongMark = true
			}

			calls := 0

			b.vpn.probe = func(ctx context.Context, namespace, url string) ([]byte, error) {
				calls++

				if !window.open || namespace != vpnTestNS || url != DefaultEgressProbeURL {
					t.Fatal("probe escaped its policy")
				}

				if deadline, ok := ctx.Deadline(); !ok || time.Until(deadline) > probeExecutionTimeout {
					t.Fatal("probe is not bounded")
				}

				switch mode {
				case "HTTP failure":
					return nil, errors.New("HTTPS failed")
				case "private IP":
					return []byte("ip=10.0.0.1\n"), nil
				case "no handshake":
					kernel.wgOverrides["latest-handshakes"] = demoKey(2) + "\t0"
				case "stale handshake":
					kernel.wgOverrides["latest-handshakes"] = fmt.Sprintf("%s\t%d", demoKey(2), time.Now().Unix()-181)
				case "wrong peer":
					kernel.wgOverrides["latest-handshakes"] = fmt.Sprintf("%s\t%d", demoKey(4), time.Now().Unix())
				case "post-probe drift":
					kernel.wrongMark = true
				case "window cleanup failure":
					window.failDel = true
				case "uncertain tunnel cleanup":
					window.failDel = true
					kernel.failDelete = true
				}

				// Synthetic trace body; no request is made.
				return []byte("fl=1\nip=8.8.4.4\nts=1\n"), nil
			}

			result, err := b.ProbeConfigured(ctx, vpnTestNS)

			if mode == "success" {
				if err != nil || result.IPv4.String() != "8.8.4.4" || result.HandshakeAt.IsZero() ||
					result.ObservedAt.IsZero() || result.Source != "cloudflare_trace" || result.NetworkReady {
					t.Fatalf("unexpected result: %+v %v", result, err)
				}

				if window.open || len(window.closed) != 1 || calls != 1 || b.active == nil || b.active.faulted {
					t.Fatal("invalid successful probe lifecycle")
				}

				if err := b.VerifyConfigured(ctx, vpnTestNS); err != nil {
					t.Fatal(err)
				}

				if err := b.Disconnect(ctx, vpnTestNS); err != nil {
					t.Fatal(err)
				}

				return
			}

			if !errors.Is(err, ErrManagedProbeFailed) || result.IPv4.IsValid() || !result.ObservedAt.IsZero() {
				t.Fatalf("failed probe accepted: %+v %v", result, err)
			}

			if (mode == "busy namespace" || mode == "pre-probe drift") && (calls != 0 || window.opened != 0) {
				t.Fatal("probe window opened before the gates passed")
			}

			// A failed close leaves the window to the kernel timeout and must be reported.
			cleanupFailed := mode == "window cleanup failure" || mode == "uncertain tunnel cleanup"
			if window.open != cleanupFailed || errors.Is(err, ErrProbeCleanup) != cleanupFailed {
				t.Fatalf("window open %t, cleanup error %t", window.open, errors.Is(err, ErrProbeCleanup))
			}

			if mode == "uncertain tunnel cleanup" {
				if !errors.Is(err, ErrManagedTunnelUncertain) || b.active == nil || !b.active.faulted ||
					kernel.tableRemovals != 0 {
					t.Fatal("uncertain tunnel state forgotten")
				}

				return
			}

			if b.active != nil || kernel.name != "" || kernel.tableRemovals != 1 {
				t.Fatal("failed probe did not remove the tunnel")
			}
		})
	}
}

func TestManagedEgressProbeRefusalsKeepTheTunnel(t *testing.T) {
	ctx := context.Background()
	b, kernel, window, _ := managedProbeFixture(t)

	// Without a runner (the helper's default backend), nothing starts and nothing is faulted.
	b.vpn.probe = nil

	if _, err := b.ProbeConfigured(ctx, vpnTestNS); !errors.Is(err, ErrManagedProbeUnavailable) {
		t.Fatalf("probe without a runner: %v", err)
	}

	b.vpn.probe = func(context.Context, string, string) ([]byte, error) {
		t.Fatal("probe ran")
		return nil, nil
	}

	if _, err := b.ProbeConfigured(ctx, "egresslab-lab-00000000000000bb"); !errors.Is(err, ErrNoManagedTunnel) {
		t.Fatalf("probe of another namespace: %v", err)
	}

	cancelled, cancel := context.WithCancel(ctx)
	cancel()

	if _, err := b.ProbeConfigured(cancelled, vpnTestNS); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled probe: %v", err)
	}

	if b.active == nil || b.active.faulted || kernel.tableRemovals != 0 || window.opened != 0 {
		t.Fatal("a refused probe changed the tunnel")
	}
}

func TestManagedHandshakeFreshness(t *testing.T) {
	now := time.Unix(1795500000, 0)
	peer := demoKey(2)

	tests := []struct {
		name    string
		output  string
		allowed bool
	}{
		{"recent", fmt.Sprintf("%s\t%d", peer, now.Unix()-10), true},
		{"at the limit", fmt.Sprintf("%s\t%d", peer, now.Unix()-180), true},
		{"stale", fmt.Sprintf("%s\t%d", peer, now.Unix()-181), false},
		{"future", fmt.Sprintf("%s\t%d", peer, now.Unix()+1), false},
		{"never connected", peer + "\t0", false},
		{"malformed", peer + "\tinvalid", false},
		{"leading zero", fmt.Sprintf("%s\t0%d", peer, now.Unix()-10), false},
		{"two peers", fmt.Sprintf("%s\t%d\n%s\t%d", peer, now.Unix(), demoKey(4), now.Unix()), false},
		{"wrong peer", fmt.Sprintf("%s\t%d", demoKey(4), now.Unix()), false},
		{"empty", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			stamp, err := parseManagedHandshake(tt.output, peer, now)

			if tt.allowed {
				if err != nil || stamp.IsZero() {
					t.Fatal(stamp, err)
				}
			} else if !errors.Is(err, ErrManagedHandshake) {
				t.Fatalf("invalid handshake accepted: %v", err)
			}
		})
	}
}
