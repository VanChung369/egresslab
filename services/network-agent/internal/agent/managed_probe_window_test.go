package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"
)

// testdata/nft-lab-probe-window.json and nft-lab-probe-expired.json are REAL captures (nft 1.0.9,
// Linux 6.8, Ubuntu 24.04 on Lima) of the Step 28B seal plus managedProbeRules(): one second after
// opening (expires 29) and after the 30 s timeout (the kernel then lists no element).
func probeCapture(t *testing.T, name string) []byte {
	t.Helper()

	data, err := os.ReadFile("testdata/" + name)
	if err != nil {
		t.Fatal(err)
	}

	return data
}

func TestManagedProbePolicy(t *testing.T) {
	handles, err := verifyManagedProbePolicy(probeCapture(t, "nft-lab-probe-window.json"), true)
	if err != nil || handles.input != 17 || handles.output != 16 {
		t.Fatalf("unexpected policy: %+v %v", handles, err)
	}
}

func TestManagedProbePolicyRejectsDrift(t *testing.T) {
	// Re-encoded first, so the textual edits below do not depend on how the file is formatted.
	var parsed map[string]any
	if err := json.Unmarshal(probeCapture(t, "nft-lab-probe-window.json"), &parsed); err != nil {
		t.Fatal(err)
	}

	fixture := string(encodeRuleset(t, parsed))

	withRule := func(rule string) string {
		var doc map[string]any
		if err := json.Unmarshal([]byte(fixture), &doc); err != nil {
			t.Fatal(err)
		}

		return string(encodeRuleset(t, withObject(t, doc, rule)))
	}

	// Structural edits on the parsed capture, so they do not depend on how the file is formatted.
	edit := func(object string, match func(map[string]any) bool, change func(map[string]any)) string {
		t.Helper()

		var doc map[string]any
		if err := json.Unmarshal([]byte(fixture), &doc); err != nil {
			t.Fatal(err)
		}

		for _, item := range objects(doc) {
			if value, ok := item.(map[string]any)[object].(map[string]any); ok && match(value) {
				change(value)
				return string(encodeRuleset(t, doc))
			}
		}

		t.Fatalf("%s missing from the capture", object)

		return ""
	}

	mutateSet := func(change func(map[string]any)) string {
		return edit("set", func(map[string]any) bool { return true }, change)
	}

	mutatePermit := func(chain string, change func(map[string]any)) string {
		return edit("rule", func(rule map[string]any) bool {
			expr, _ := json.Marshal(rule["expr"])
			return rule["chain"] == chain && strings.Contains(string(expr), "@egresslab_probe4")
		}, change)
	}

	firstElement := func(set map[string]any) map[string]any {
		return set["elem"].([]any)[0].(map[string]any)["elem"].(map[string]any)
	}

	// The output permit moved ahead of the loopback accept: every sealed rule is still present and in
	// order, so only the "permit last in its chain" check can refuse it.
	permitFirst := func() string {
		var doc map[string]any
		if err := json.Unmarshal([]byte(fixture), &doc); err != nil {
			t.Fatal(err)
		}

		items := objects(doc)
		permit, loopback := -1, -1

		for i, item := range items {
			rule, ok := item.(map[string]any)["rule"].(map[string]any)
			if !ok || rule["chain"] != "output" {
				continue
			}

			expr, _ := json.Marshal(rule["expr"])

			switch {
			case strings.Contains(string(expr), "@egresslab_probe4"):
				permit = i
			case strings.Contains(string(expr), `"oifname"`) && strings.Contains(string(expr), `"lo"`):
				loopback = i
			}
		}

		if permit < 0 || loopback < 0 || loopback > permit {
			t.Fatal("unexpected window fixture")
		}

		items[permit], items[loopback] = items[loopback], items[permit]

		return string(encodeRuleset(t, doc))
	}

	tests := map[string]string{
		"permit before a sealed rule": permitFirst(),
		"wrong destination":           strings.ReplaceAll(fixture, `"1.1.1.1"`, `"8.8.8.8"`),
		"wrong interface":             strings.ReplaceAll(fixture, `"wg0"`, `"eth0"`),
		"wrong port":                  strings.ReplaceAll(fixture, `"right":443`, `"right":80`),
		"extended lifetime":           strings.ReplaceAll(fixture, `"timeout":30`, `"timeout":300`),
		"expired":                     strings.ReplaceAll(fixture, `"expires":29`, `"expires":0`),
		"expires past TTL":            strings.ReplaceAll(fixture, `"expires":29`, `"expires":31`),
		"no expiry":                   mutateSet(func(set map[string]any) { delete(firstElement(set), "expires") }),
		"second element": mutateSet(func(set map[string]any) {
			set["elem"] = append(set["elem"].([]any), map[string]any{
				"elem": map[string]any{"val": "1.0.0.1", "timeout": 30, "expires": 29},
			})
		}),
		"larger set":        strings.ReplaceAll(fixture, `"size":1`, `"size":2`),
		"extra set flag":    mutateSet(func(set map[string]any) { set["flags"] = []any{"timeout", "interval"} }),
		"unknown set field": strings.ReplaceAll(fixture, `"size":1`, `"size":1,"gc-interval":1`),
		"other set name":    strings.ReplaceAll(fixture, `"name":"egresslab_probe4"`, `"name":"probe"`),
		"set membership op": mutatePermit("output", func(rule map[string]any) {
			for _, item := range rule["expr"].([]any) {
				if match, ok := item.(map[string]any)["match"].(map[string]any); ok && match["right"] == "@egresslab_probe4" {
					match["op"] = "in"
					return
				}
			}

			t.Fatal("set membership expression missing")
		}),
		"stateless input": mutatePermit("input", func(rule map[string]any) {
			expr := rule["expr"].([]any)

			for i, item := range expr {
				if match, ok := item.(map[string]any)["match"].(map[string]any); ok {
					if left, ok := match["left"].(map[string]any); ok && left["ct"] != nil {
						rule["expr"] = append(expr[:i:i], expr[i+1:]...)
						return
					}
				}
			}

			t.Fatal("conntrack expression missing")
		}),
		"missing DNS drop":   strings.ReplaceAll(fixture, `"right":853`, `"right":8853`),
		"empty element list": mutateSet(func(set map[string]any) { set["elem"] = []any{} }),
		"extra permit": withRule(`{"rule": {"family": "inet", "table": "egresslab_lab", "chain": "output", "handle": 40,
			"expr": [{"match": {"op": "==", "left": {"meta": {"key": "oifname"}}, "right": "wg0"}}, {"accept": null}]}}`),
		"sealed rule after the permit": withRule(`{"rule": {"family": "inet", "table": "egresslab_lab",
			"chain": "output", "handle": 41,
			"expr": [{"match": {"op": "==", "left": {"meta": {"key": "oifname"}}, "right": "lo"}}, {"accept": null}]}}`),
		"second set": withRule(`{"set": {"family": "inet", "name": "egresslab_probe4", "table": "egresslab_lab",
			"type": "ipv4_addr", "handle": 42, "size": 1, "flags": ["timeout"]}}`),
	}

	for name, data := range tests {
		t.Run(name, func(t *testing.T) {
			if data == fixture {
				t.Fatal("fixture edit did not apply")
			}

			if _, err := verifyManagedProbePolicy([]byte(data), true); !errors.Is(err, ErrProbePolicyDrift) {
				t.Fatalf("unsafe policy accepted: %v", err)
			}
		})
	}

	sealedOnly := encodeRuleset(t, sealedRulesetFixture(t))
	if _, err := verifyManagedProbePolicy(sealedOnly, false); !errors.Is(err, ErrProbePolicyDrift) {
		t.Fatal("a ruleset without a window was taken for one")
	}
}

func TestManagedProbePolicyExpiredCleanup(t *testing.T) {
	data := probeCapture(t, "nft-lab-probe-expired.json")

	if _, err := verifyManagedProbePolicy(data, true); !errors.Is(err, ErrProbePolicyDrift) {
		t.Fatalf("expired permission accepted: %v", err)
	}

	if handles, err := verifyManagedProbePolicy(data, false); err != nil || handles.input != 17 || handles.output != 16 {
		t.Fatalf("expired permission cannot be cleaned up: %+v %v", handles, err)
	}
}

// probeWindowKernel models the lab table: sealed, or holding the window as captured. It fails
// the test on any mutation other than opening or closing the window.
type probeWindowKernel struct {
	t       *testing.T
	sealed  []byte
	window  []byte
	open    bool
	opened  int
	closed  []string
	failAdd bool
	failDel bool
}

func (k *probeWindowKernel) list(context.Context, string) ([]byte, error) {
	if k.open {
		return k.window, nil
	}

	return k.sealed, nil
}

func (k *probeWindowKernel) run(_ context.Context, _ string, script string, checkOnly bool) error {
	switch {
	case strings.HasPrefix(script, "add set"):
		if script != managedProbeRules() {
			k.t.Fatal("unexpected window script")
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

func probeWindowFirewall(t *testing.T) (*LabFirewall, *probeWindowKernel) {
	t.Helper()

	f, _ := verifyingFirewall(t)

	if err := f.Seal(context.Background(), firewallTestName); err != nil {
		t.Fatal(err)
	}

	kernel := &probeWindowKernel{
		t:      t,
		sealed: encodeRuleset(t, sealedRulesetFixture(t)),
		window: probeCapture(t, "nft-lab-probe-window.json"),
	}

	f.list, f.run = kernel.list, kernel.run

	return f, kernel
}

func runProbeWindow(f *LabFirewall, probe func(context.Context) error) error {
	f.manager.mu.Lock()
	defer f.manager.mu.Unlock()

	return f.withManagedProbeWindowLocked(context.Background(), firewallTestName, probe)
}

func TestManagedProbeWindowCleanup(t *testing.T) {
	for _, failCleanup := range []bool{false, true} {
		t.Run(fmt.Sprint("cleanup fails: ", failCleanup), func(t *testing.T) {
			f, kernel := probeWindowFirewall(t)
			kernel.failDel = failCleanup

			baseline := f.baseline[firewallTestName]
			probeErr := errors.New("diagnostic probe failed")
			calls := 0

			err := runProbeWindow(f, func(ctx context.Context) error {
				calls++

				if !kernel.open {
					t.Fatal("probe ran without permission")
				}

				if deadline, ok := ctx.Deadline(); !ok || time.Until(deadline) > probeExecutionTimeout {
					t.Fatal("probe is not bounded")
				}

				return probeErr
			})

			if !errors.Is(err, probeErr) || calls != 1 {
				t.Fatalf("probe result lost: %v", err)
			}

			if failCleanup {
				if !errors.Is(err, ErrProbeCleanup) || !f.drifted[firewallTestName] {
					t.Fatal("cleanup failure ignored")
				}
			} else {
				want := "delete rule inet egresslab_lab input handle 17\n" +
					"delete rule inet egresslab_lab output handle 16\n" +
					"delete set inet egresslab_lab egresslab_probe4\n"

				if kernel.open || len(kernel.closed) != 1 || kernel.closed[0] != want || f.drifted[firewallTestName] {
					t.Fatalf("temporary permission survived: %q", kernel.closed)
				}
			}

			if f.baseline[firewallTestName] != baseline || len(f.applied[firewallTestName]) != 1 {
				t.Fatal("temporary policy became permanent")
			}
		})
	}
}

func TestManagedProbeWindowRefusals(t *testing.T) {
	probeMustNotRun := func(context.Context) error {
		t.Fatal("probe ran")
		return nil
	}

	t.Run("seal drifted before opening", func(t *testing.T) {
		f, kernel := probeWindowFirewall(t)
		kernel.sealed = probeCapture(t, "nft-lab-sealed.json")

		if err := runProbeWindow(f, probeMustNotRun); !errors.Is(err, ErrFirewallDrift) || kernel.opened != 0 {
			t.Fatalf("window opened on a drifted seal: %v", err)
		}
	})

	t.Run("opening transaction failed", func(t *testing.T) {
		f, kernel := probeWindowFirewall(t)
		kernel.failAdd = true

		err := runProbeWindow(f, probeMustNotRun)
		if err == nil || errors.Is(err, ErrProbeCleanup) || f.drifted[firewallTestName] {
			t.Fatalf("unexpected result: %v", err)
		}
	})

	t.Run("unexpected window readback", func(t *testing.T) {
		f, kernel := probeWindowFirewall(t)
		kernel.window = []byte(strings.ReplaceAll(string(kernel.window), `"1.1.1.1"`, `"8.8.8.8"`))

		// Cleanup cannot identify foreign objects, so it refuses and marks the lab drifted.
		err := runProbeWindow(f, probeMustNotRun)
		if !errors.Is(err, ErrProbePolicyDrift) || !errors.Is(err, ErrProbeCleanup) || !f.drifted[firewallTestName] {
			t.Fatalf("unexpected result: %v", err)
		}
	})

	t.Run("window expired before the probe returned", func(t *testing.T) {
		f, kernel := probeWindowFirewall(t)

		err := runProbeWindow(f, func(context.Context) error {
			kernel.window = probeCapture(t, "nft-lab-probe-expired.json")
			return nil
		})

		if !errors.Is(err, ErrProbePolicyDrift) || errors.Is(err, ErrProbeCleanup) || kernel.open {
			t.Fatalf("expired window accepted or not cleaned up: %v", err)
		}
	})

	t.Run("invalid arguments", func(t *testing.T) {
		f, kernel := probeWindowFirewall(t)

		f.manager.mu.Lock()
		errName := f.withManagedProbeWindowLocked(context.Background(), "../default", probeMustNotRun)
		errProbe := f.withManagedProbeWindowLocked(context.Background(), firewallTestName, nil)
		f.manager.mu.Unlock()

		if !errors.Is(errName, ErrProbePolicyDrift) || !errors.Is(errProbe, ErrProbePolicyDrift) || kernel.opened != 0 {
			t.Fatal("invalid window request accepted")
		}
	})
}
