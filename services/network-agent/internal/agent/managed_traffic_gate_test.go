package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
)

// The real captures (nft 1.0.9, Lima Ubuntu 24.04) were taken in a throwaway namespace sealed with
// sealLabRules, with the gate of managedTrafficRules(997) open, expired and closed (two temporary
// permits, since removed, used handles 13 and 14 before it).
const trafficCaptureUID = 997

func TestManagedTrafficGateRules(t *testing.T) {
	rules, err := managedTrafficRules(1001)
	if err != nil {
		t.Fatal(err)
	}

	for _, expected := range []string{
		"type ifname; flags timeout; size 1;",
		`"wg0" timeout 10s`,
		"oifname @egresslab_app4",
		"iifname @egresslab_app4",
		"meta skuid 1001",
		"meta nfproto ipv4",
		"meta l4proto tcp",
		"ct state established",
		"ct mark set 1701276673 accept",
		"ct state established ct mark 1701276673 accept",
	} {
		if !strings.Contains(rules, expected) {
			t.Fatalf("missing rule: %s", expected)
		}
	}

	for _, uid := range []uint32{0, ^uint32(0)} {
		if _, err := managedTrafficRules(uid); err == nil {
			t.Fatalf("UID %d accepted", uid)
		}
	}
}

func TestManagedTrafficGatePolicy(t *testing.T) {
	var doc struct {
		Nftables []map[string]json.RawMessage `json:"nftables"`
	}

	if err := json.Unmarshal(probeCapture(t, "nft-lab-sealed-v2.json"), &doc); err != nil {
		t.Fatal(err)
	}

	doc.Nftables = append(doc.Nftables, map[string]json.RawMessage{
		"set": json.RawMessage(`{"family":"inet","table":"egresslab_lab","name":"egresslab_app4","type":"ifname",` +
			`"handle":100,"size":1,"flags":["timeout"],"elem":[{"elem":{"val":"wg0","timeout":10,"expires":9}}]}`),
	})

	for chain, expr := range expectedTrafficRules(1001) {
		handle := 101
		if chain == "output" {
			handle = 102
		}

		doc.Nftables = append(doc.Nftables, map[string]json.RawMessage{
			"rule": json.RawMessage(fmt.Sprintf(`{"family":"inet","table":"egresslab_lab","chain":%q,"handle":%d,"expr":%s}`,
				chain, handle, expr)),
		})
	}

	data, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := verifyTrafficGatePolicy(data, 1001, true); err != nil {
		t.Fatal(err)
	}

	for name, bad := range map[string]string{
		"wrong UID":        strings.ReplaceAll(string(data), `"right":1001`, `"right":1002`),
		"wrong interface":  strings.ReplaceAll(string(data), `"val":"wg0"`, `"val":"eth0"`),
		"extended timeout": strings.ReplaceAll(string(data), `"timeout":10`, `"timeout":100`),
		"expired":          strings.ReplaceAll(string(data), `"expires":9`, `"expires":0`),
		"any protocol":     strings.ReplaceAll(string(data), `"right":"tcp"`, `"right":"udp"`),
		"another mark":     strings.ReplaceAll(string(data), `1701276673`, `1`),
	} {
		t.Run(name, func(t *testing.T) {
			if bad == string(data) {
				t.Fatal("mutation did not apply")
			}

			if _, err := verifyTrafficGatePolicy([]byte(bad), 1001, true); err == nil {
				t.Fatal("unsafe traffic policy accepted")
			}
		})
	}
}

func TestManagedTrafficGateRealCapture(t *testing.T) {
	active := probeCapture(t, "nft-lab-traffic-active.json")
	expired := probeCapture(t, "nft-lab-traffic-expired.json")
	closed := probeCapture(t, "nft-lab-traffic-closed.json")

	handles, err := verifyTrafficGatePolicy(active, trafficCaptureUID, true)
	if err != nil || handles.input != 16 || handles.output != 15 {
		t.Fatalf("real open gate refused: %+v %v", handles, err)
	}

	if _, err := verifyTrafficGatePolicy(active, trafficCaptureUID+1, true); err == nil {
		t.Fatal("gate of another UID accepted")
	}

	if _, err := verifyTrafficGatePolicy(expired, trafficCaptureUID, true); err == nil {
		t.Fatal("expired gate accepted as active")
	}

	if handles, err := verifyTrafficGatePolicy(expired, trafficCaptureUID, false); err != nil || handles.input != 16 ||
		handles.output != 15 {
		t.Fatalf("expired gate cannot be closed: %+v %v", handles, err)
	}

	if err := verifySealedPolicy(closed); err != nil {
		t.Fatalf("closed gate left no sealed policy: %v", err)
	}

	if _, err := verifyTrafficGatePolicy(closed, trafficCaptureUID, false); err == nil {
		t.Fatal("sealed policy accepted as a gate")
	}

	if _, err := verifyManagedProbePolicy(active, false); err == nil {
		t.Fatal("traffic gate accepted as a probe window")
	}
}

// trafficGateKernel models the lab table: sealed, or holding the real open gate. It fails the test
// on any mutation other than opening or closing the gate.
type trafficGateKernel struct {
	t       *testing.T
	sealed  []byte
	gate    []byte
	open    bool
	opened  int
	closed  []string
	failAdd bool
	failDel bool
}

func (k *trafficGateKernel) list(context.Context, string) ([]byte, error) {
	if k.open {
		return k.gate, nil
	}

	return k.sealed, nil
}

func (k *trafficGateKernel) run(_ context.Context, _ string, script string, checkOnly bool) error {
	switch {
	case strings.HasPrefix(script, "add set"):
		expected, _ := managedTrafficRules(trafficCaptureUID)
		if script != expected {
			k.t.Fatal("unexpected gate script")
		}

		if k.failAdd {
			return errors.New("open failed")
		}

		if !checkOnly {
			k.open = true
			k.opened++
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

func trafficGateFirewall(t *testing.T) (*LabFirewall, *trafficGateKernel) {
	t.Helper()

	f, _ := verifyingFirewall(t)

	if err := f.Seal(context.Background(), firewallTestName); err != nil {
		t.Fatal(err)
	}

	kernel := &trafficGateKernel{
		t:      t,
		sealed: encodeRuleset(t, sealedRulesetFixture(t)),
		gate:   probeCapture(t, "nft-lab-traffic-active.json"),
	}

	f.list, f.run = kernel.list, kernel.run

	return f, kernel
}

func runTrafficGate(f *LabFirewall, healthUntil time.Time, run func(context.Context) error) error {
	f.manager.mu.Lock()
	defer f.manager.mu.Unlock()

	return f.withTrafficGateLocked(context.Background(), firewallTestName, trafficCaptureUID, healthUntil, run)
}

func TestManagedTrafficGateWindow(t *testing.T) {
	healthy := time.Now().Add(time.Minute)

	t.Run("opens, runs within the element and closes", func(t *testing.T) {
		f, kernel := trafficGateFirewall(t)
		startedAt := time.Now()

		err := runTrafficGate(f, healthy, func(ctx context.Context) error {
			deadline, ok := ctx.Deadline()
			if !kernel.open || !ok || deadline.After(startedAt.Add(trafficGateTTL)) {
				t.Fatal("worker ran outside a verified gate")
			}

			return nil
		})

		want := "delete rule inet egresslab_lab input handle 16\n" +
			"delete rule inet egresslab_lab output handle 15\n" +
			"delete set inet egresslab_lab egresslab_app4\n"

		if err != nil || kernel.open || kernel.opened != 1 || len(kernel.closed) != 1 || kernel.closed[0] != want ||
			f.drifted[firewallTestName] {
			t.Fatalf("gate not opened and closed: %v %q", err, kernel.closed)
		}
	})

	t.Run("worker failure still closes", func(t *testing.T) {
		f, kernel := trafficGateFirewall(t)
		failure := errors.New("worker failed")

		if err := runTrafficGate(f, healthy, func(context.Context) error { return failure }); !errors.Is(err, failure) ||
			kernel.open || len(kernel.closed) != 1 {
			t.Fatalf("unexpected result: %v", err)
		}
	})

	t.Run("unconfirmed close drifts the namespace", func(t *testing.T) {
		f, kernel := trafficGateFirewall(t)
		kernel.failDel = true

		err := runTrafficGate(f, healthy, func(context.Context) error { return nil })
		if !errors.Is(err, ErrTrafficGate) || !f.drifted[firewallTestName] {
			t.Fatalf("unconfirmed close accepted: %v", err)
		}
	})

	t.Run("health too short for the kernel timeout", func(t *testing.T) {
		f, kernel := trafficGateFirewall(t)

		err := runTrafficGate(f, time.Now().Add(trafficGateTTL+trafficGateCloseBudget), func(context.Context) error {
			t.Fatal("worker ran without enough health")
			return nil
		})

		if !errors.Is(err, ErrTrafficGateTooLate) || kernel.opened != 0 || len(kernel.closed) != 0 {
			t.Fatalf("gate opened past the health: %v", err)
		}
	})

	t.Run("seal drifted before opening", func(t *testing.T) {
		f, kernel := trafficGateFirewall(t)
		kernel.sealed = probeCapture(t, "nft-lab-sealed.json")

		if err := runTrafficGate(f, healthy, func(context.Context) error { return nil }); !errors.Is(err, ErrFirewallDrift) ||
			kernel.opened != 0 {
			t.Fatalf("gate opened on a drifted seal: %v", err)
		}
	})

	t.Run("opening transaction failed", func(t *testing.T) {
		f, kernel := trafficGateFirewall(t)
		kernel.failAdd = true

		err := runTrafficGate(f, healthy, func(context.Context) error {
			t.Fatal("worker ran without a gate")
			return nil
		})

		if err == nil || errors.Is(err, ErrTrafficGate) || f.drifted[firewallTestName] {
			t.Fatalf("unexpected result: %v", err)
		}
	})
}
