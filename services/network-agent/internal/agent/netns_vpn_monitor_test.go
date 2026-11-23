package agent

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestVPNQuarantineRemovesTunnel(t *testing.T) {
	lab, rec := newProbeGuardTestLab(t)
	before := len(rec.root)

	if err := lab.Quarantine(context.Background(), vpnTestNS); err != nil {
		t.Fatal(err)
	}

	if _, exists := lab.underlay[vpnTestNS]; exists {
		t.Fatal("underlay still tracked after disconnect")
	}

	if got := rec.root[before:]; len(got) != 1 || !strings.HasPrefix(got[0].script, "delete table inet egresslab_ul_") {
		t.Fatalf("underlay table not removed: %#v", got)
	}
}

func TestVPNQuarantineFallbackOnDeleteFailure(t *testing.T) {
	lab, rec := newProbeGuardTestLab(t)

	rec.failIP = func(args []string) error {
		if reflect.DeepEqual(args, []string{"-n", vpnTestNS, "link", "del", "wg0"}) {
			return errors.New("permission denied")
		}
		return nil
	}

	rootBefore := len(rec.root)

	if err := lab.Quarantine(context.Background(), vpnTestNS); err == nil {
		t.Fatal("incomplete quarantine reported success")
	}

	if _, exists := lab.underlay[vpnTestNS]; !exists || len(rec.root) != rootBefore {
		t.Fatal("underlay removed while the link survived")
	}

	last := rec.ipCalls[len(rec.ipCalls)-1]
	if want := []string{"-n", vpnTestNS, "link", "set", "wg0", "down"}; !reflect.DeepEqual(last, want) {
		t.Fatalf("emergency fallback missing: %v", last)
	}
}

func TestVPNQuarantineReportsFailedFallback(t *testing.T) {
	lab, rec := newProbeGuardTestLab(t)

	rec.failIP = func([]string) error { return errors.New("RTNETLINK answers: Operation not permitted") }

	err := lab.Quarantine(context.Background(), vpnTestNS)
	if err == nil || !strings.Contains(err.Error(), "emergency interface down") {
		t.Fatalf("failed fallback not reported: %v", err)
	}

	if _, exists := lab.underlay[vpnTestNS]; !exists {
		t.Fatal("underlay removed although wg0 could not be removed or downed")
	}
}

func TestVPNQuarantineRejectsForeignNamespace(t *testing.T) {
	lab, rec := newProbeGuardTestLab(t)
	before := len(rec.ipCalls)

	if err := lab.Quarantine(context.Background(), "egresslab-lab-ffffffffffffffff"); err == nil {
		t.Fatal("foreign namespace accepted")
	}

	if len(rec.ipCalls) != before {
		t.Fatal("modified a foreign namespace")
	}
}

func TestVPNQuarantineRejectsMalformedName(t *testing.T) {
	lab, _ := newProbeGuardTestLab(t)

	if err := lab.Quarantine(context.Background(), "../../default"); err == nil {
		t.Fatal("invalid namespace accepted")
	}
}

// countingUnderlay serves underlay listings from the watchdog goroutine; the counter is locked
// so the test can read it while the watchdog may still run.
type countingUnderlay struct {
	mu    sync.Mutex
	reads int
}

func (c *countingUnderlay) count() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.reads
}

func TestVPNIsolationWatchDetectsDrift(t *testing.T) {
	lab, _ := newProbeGuardTestLab(t)

	counter := &countingUnderlay{}
	lab.rootNFT.list = func(context.Context, string) ([]byte, error) {
		counter.mu.Lock()
		counter.reads++
		reads := counter.reads
		counter.mu.Unlock()

		// The first check passes; the next sees a different endpoint.
		endpoint := "198.51.100.7:51820"
		if reads >= 2 {
			endpoint = "198.51.100.8:51820"
		}

		return underlayListing(t, endpoint, 0xabcd, "accept"), nil
	}

	faults := lab.WatchIsolation(context.Background(), vpnTestNS, 5*time.Millisecond)

	select {
	case err, ok := <-faults:
		if !ok || !errors.Is(err, ErrVPNIsolationNotVerified) || !strings.Contains(err.Error(), "quarantined") {
			t.Fatalf("drift was not reported: %v", err)
		}

	case <-time.After(2 * time.Second):
		t.Fatal("watchdog did not detect drift")
	}

	if _, open := <-faults; open {
		t.Fatal("watchdog channel stayed open after reporting")
	}

	if _, exists := lab.underlay[vpnTestNS]; exists {
		t.Fatal("unsafe tunnel was not quarantined")
	}

	if counter.count() < 2 {
		t.Fatalf("watchdog did not repeat verification: %d", counter.count())
	}
}

func TestVPNIsolationWatchStopsOnCancel(t *testing.T) {
	lab, _ := newProbeGuardTestLab(t)

	ctx, cancel := context.WithCancel(context.Background())
	faults := lab.WatchIsolation(ctx, vpnTestNS, 5*time.Millisecond)

	// Let it run a few healthy checks first.
	time.Sleep(30 * time.Millisecond)
	cancel()

	select {
	case err, ok := <-faults:
		if ok || err != nil {
			t.Fatalf("unexpected watchdog error: %v", err)
		}

	case <-time.After(time.Second):
		t.Fatal("watchdog did not stop")
	}

	if _, exists := lab.underlay[vpnTestNS]; !exists {
		t.Fatal("cancellation unexpectedly removed the tunnel")
	}
}

func TestVPNIsolationWatchRejectsBadInterval(t *testing.T) {
	lab, _ := newProbeGuardTestLab(t)

	if err := <-lab.WatchIsolation(context.Background(), vpnTestNS, 0); err == nil {
		t.Fatal("zero interval was accepted")
	}

	if err := <-lab.WatchIsolation(context.Background(), "default", time.Second); err == nil {
		t.Fatal("invalid namespace was accepted")
	}
}

func TestVPNIsolationWatchFailsOnReadbackError(t *testing.T) {
	lab, _ := newProbeGuardTestLab(t)

	lab.rootNFT.list = func(context.Context, string) ([]byte, error) {
		return nil, errors.New("nftables unavailable")
	}

	select {
	case err := <-lab.WatchIsolation(context.Background(), vpnTestNS, 5*time.Millisecond):
		if !errors.Is(err, ErrVPNIsolationNotVerified) {
			t.Fatalf("unreadable firewall accepted: %v", err)
		}

	case <-time.After(2 * time.Second):
		t.Fatal("watchdog did not report readback failure")
	}

	if _, exists := lab.underlay[vpnTestNS]; exists {
		t.Fatal("unverifiable tunnel was not quarantined")
	}
}

func TestVPNIsolationWatchFirewallDriftQuarantines(t *testing.T) {
	lab, _ := newProbeGuardTestLab(t)

	lab.firewall.list = func(context.Context, string) ([]byte, error) {
		return []byte(`{"nftables":[]}`), nil
	}

	select {
	case err := <-lab.WatchIsolation(context.Background(), vpnTestNS, 5*time.Millisecond):
		if !errors.Is(err, ErrVPNIsolationNotVerified) || !errors.Is(err, ErrFirewallDrift) {
			t.Fatalf("namespace firewall drift not reported: %v", err)
		}

	case <-time.After(2 * time.Second):
		t.Fatal("watchdog did not report firewall drift")
	}

	if _, exists := lab.underlay[vpnTestNS]; exists {
		t.Fatal("tunnel survived namespace firewall drift")
	}
}
