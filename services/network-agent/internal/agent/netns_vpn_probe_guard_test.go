package agent

import (
	"context"
	"errors"
	"net/netip"
	"testing"
)

// newProbeGuardTestLab returns a connected VPN lab whose namespace firewall, host-side underlay
// table and wg0 fwmark all read back as expected. 198.51.100.x and 203.0.113.x are
// documentation addresses, not real VPN servers.
func newProbeGuardTestLab(t *testing.T) (*VPNEgressLab, *vpnLabRecorder) {
	t.Helper()

	lab, rec := testVPNLab(true)

	if err := lab.Connect(context.Background(), vpnTestNS, vpnTestConfig(t)); err != nil {
		t.Fatal(err)
	}

	// Host namespace nftables readback for the current tunnel.
	lab.rootNFT.list = func(context.Context, string) ([]byte, error) {
		return underlayListing(t, "198.51.100.7:51820", 0xabcd, "accept"), nil
	}

	// wg show wg0 fwmark.
	originalWG := lab.runWG
	lab.runWG = func(ctx context.Context, namespace string, stdin []byte, args ...string) (string, error) {
		if len(args) == 3 && args[0] == "show" && args[1] == "wg0" && args[2] == "fwmark" {
			return "0xabcd", nil
		}

		return originalWG(ctx, namespace, stdin, args...)
	}

	// Namespace firewall readback from the sealed-lab capture.
	fixture := encodeRuleset(t, sealedRulesetFixture(t))

	fingerprint, err := labRulesetFingerprint(fixture)
	if err != nil {
		t.Fatal(err)
	}

	lab.firewall.list = func(context.Context, string) ([]byte, error) { return fixture, nil }
	lab.firewall.baseline[vpnTestNS] = fingerprint

	return lab, rec
}

func defaultProbeTarget(t *testing.T) EgressProbeTarget {
	t.Helper()

	target, err := ParseEgressProbeURL(DefaultEgressProbeURL)
	if err != nil {
		t.Fatal(err)
	}

	return target
}

func TestProbeVerifiedSuccess(t *testing.T) {
	lab, rec := newProbeGuardTestLab(t)

	ip, err := lab.ProbeVerified(context.Background(), vpnTestNS, defaultProbeTarget(t))
	if err != nil {
		t.Fatal(err)
	}

	if ip != netip.MustParseAddr("203.0.113.9") {
		t.Fatalf("unexpected IP: %v", ip)
	}

	if len(rec.probed) != 1 {
		t.Fatalf("expected one probe, got %d", len(rec.probed))
	}
}

func TestProbeVerifiedRejectsFirewallDrift(t *testing.T) {
	lab, rec := newProbeGuardTestLab(t)

	lab.firewall.list = func(context.Context, string) ([]byte, error) {
		return []byte(`{"nftables":[]}`), nil
	}

	ip, err := lab.ProbeVerified(context.Background(), vpnTestNS, defaultProbeTarget(t))
	if ip.IsValid() || !errors.Is(err, ErrVPNIsolationNotVerified) || !errors.Is(err, ErrFirewallDrift) {
		t.Fatalf("firewall drift accepted: %v", err)
	}

	if len(rec.probed) != 0 {
		t.Fatal("network probe ran after drift")
	}
}

func TestProbeVerifiedRejectsUnderlayDrift(t *testing.T) {
	lab, rec := newProbeGuardTestLab(t)

	// A different endpoint from the one the WireGuard tunnel uses.
	lab.rootNFT.list = func(context.Context, string) ([]byte, error) {
		return underlayListing(t, "198.51.100.8:51820", 0xabcd, "accept"), nil
	}

	ip, err := lab.ProbeVerified(context.Background(), vpnTestNS, defaultProbeTarget(t))
	if ip.IsValid() || !errors.Is(err, ErrVPNIsolationNotVerified) {
		t.Fatalf("underlay drift accepted: %v", err)
	}

	if len(rec.probed) != 0 {
		t.Fatal("probe ran with unsafe underlay")
	}
}

func TestProbeVerifiedRejectsFwmarkDrift(t *testing.T) {
	lab, rec := newProbeGuardTestLab(t)

	lab.runWG = func(_ context.Context, _ string, _ []byte, args ...string) (string, error) {
		return "off", nil
	}

	ip, err := lab.ProbeVerified(context.Background(), vpnTestNS, defaultProbeTarget(t))
	if ip.IsValid() || !errors.Is(err, ErrVPNIsolationNotVerified) {
		t.Fatalf("missing fwmark accepted: %v", err)
	}

	if len(rec.probed) != 0 {
		t.Fatal("probe ran without the tunnel fwmark")
	}
}

func TestProbeVerifiedRejectsDriftAfterProbe(t *testing.T) {
	lab, rec := newProbeGuardTestLab(t)

	readbacks := 0
	lab.rootNFT.list = func(context.Context, string) ([]byte, error) {
		readbacks++

		endpoint := "198.51.100.7:51820"
		if readbacks > 1 {
			endpoint = "198.51.100.8:51820"
		}

		return underlayListing(t, endpoint, 0xabcd, "accept"), nil
	}

	ip, err := lab.ProbeVerified(context.Background(), vpnTestNS, defaultProbeTarget(t))
	if ip.IsValid() || !errors.Is(err, ErrVPNIsolationNotVerified) {
		t.Fatalf("post-probe drift accepted: %v", err)
	}

	if len(rec.probed) != 1 || readbacks != 2 {
		t.Fatalf("unexpected probe/readback count: %d/%d", len(rec.probed), readbacks)
	}
}

func TestProbeVerifiedChecksAfterFailedProbe(t *testing.T) {
	lab, _ := newProbeGuardTestLab(t)

	probeErr := errors.New("egress probe failed: timeout")
	lab.probe = func(context.Context, string, string) ([]byte, error) { return nil, probeErr }

	// Clean state: the network error comes back as-is, so the caller may retry it.
	if _, err := lab.ProbeVerified(context.Background(), vpnTestNS, defaultProbeTarget(t)); !errors.Is(err, probeErr) ||
		errors.Is(err, ErrVPNIsolationNotVerified) {
		t.Fatalf("unexpected error for a plain probe failure: %v", err)
	}

	// Drift during a failed probe wins over the network error and is not retryable.
	readbacks := 0
	lab.rootNFT.list = func(context.Context, string) ([]byte, error) {
		readbacks++

		endpoint := "198.51.100.7:51820"
		if readbacks > 1 {
			endpoint = "198.51.100.8:51820"
		}

		return underlayListing(t, endpoint, 0xabcd, "accept"), nil
	}

	if _, err := lab.ProbeVerified(context.Background(), vpnTestNS, defaultProbeTarget(t)); !errors.Is(err, ErrVPNIsolationNotVerified) {
		t.Fatalf("drift during a failed probe was not reported: %v", err)
	}
}

func TestProbeVerifiedRejectsTargetMismatch(t *testing.T) {
	lab, rec := newProbeGuardTestLab(t)

	target := EgressProbeTarget{URL: DefaultEgressProbeURL, IP: netip.MustParseAddr("8.8.8.8")}

	ip, err := lab.ProbeVerified(context.Background(), vpnTestNS, target)
	if ip.IsValid() || !errors.Is(err, ErrVPNIsolationNotVerified) {
		t.Fatalf("mismatched target accepted: %v", err)
	}

	if len(rec.probed) != 0 {
		t.Fatal("unexpected network request")
	}
}

func TestProbeVerifiedRejectsInvalidNamespace(t *testing.T) {
	lab, rec := newProbeGuardTestLab(t)

	if _, err := lab.ProbeVerified(context.Background(), "default", defaultProbeTarget(t)); !errors.Is(err, ErrVPNIsolationNotVerified) {
		t.Fatalf("invalid namespace accepted: %v", err)
	}

	if len(rec.probed) != 0 {
		t.Fatal("unexpected network request")
	}
}
