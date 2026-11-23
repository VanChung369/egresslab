package agent

import (
	"context"
	"errors"
	"reflect"
	"testing"
)

func TestRecoveryRejectsUnsafeInterfaces(t *testing.T) {
	tests := []struct {
		name    string
		output  string
		readErr error
		liveWG  bool
	}{
		{name: "WireGuard interface", output: `[{"ifname":"lo"}, {"ifname":"wg0", "linkinfo":{"info_kind":"wireguard"}}]`, liveWG: true},
		{name: "WireGuard named wg0 without linkinfo", output: `[{"ifname":"lo"}, {"ifname":"wg0"}]`, liveWG: true},
		{name: "renamed WireGuard interface", output: `[{"ifname":"lo"}, {"ifname":"wg-backup", "linkinfo":{"info_kind":"wireguard"}}]`, liveWG: true},
		{name: "unexpected physical interface", output: `[{"ifname":"lo"}, {"ifname":"eth0"}]`},
		{name: "incorrect veth type", output: `[{"ifname":"lo"}, {"ifname":"ev-a", "linkinfo":{"info_kind":"dummy"}}]`},
		{name: "malformed JSON", output: `not-json`},
		{name: "empty kernel response", output: `[]`},
		{name: "missing loopback", output: `[{"ifname":"ev-a", "linkinfo":{"info_kind":"veth"}}]`},
		{name: "duplicate interface", output: `[{"ifname":"lo"},{"ifname":"lo"}]`},
		{name: "kernel read failure", readErr: errors.New("permission denied")},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newRecoveryFixture(t)

			var inspected []string
			f.recovery.env.inspectLinks = func(_ context.Context, namespace string) ([]byte, error) {
				inspected = append(inspected, namespace)

				if namespace == recOrphan {
					return []byte(tt.output), tt.readErr
				}

				return []byte(`[{"ifname":"lo"}]`), nil
			}

			_, err := f.recovery.Clean(context.Background())

			if !errors.Is(err, ErrRecoveryUnsafeLinks) {
				t.Fatalf("unsafe interface accepted: %v", err)
			}

			if tt.liveWG && !errors.Is(err, ErrRecoveryLiveTunnel) {
				t.Fatalf("live WireGuard not detected: %v", err)
			}

			if !f.present[recOrphan] {
				t.Fatal("unsafe namespace was deleted")
			}

			for _, args := range f.ipCalls {
				if len(args) >= 3 && args[1] == "delete" && args[2] == recOrphan {
					t.Fatal("kernel delete was attempted")
				}
			}

			if _, exists, markerErr := f.manager.markers.read(recOrphan); markerErr != nil || !exists {
				t.Fatal("unsafe namespace lost its marker")
			}

			if _, owned := f.manager.owned[recOrphan]; owned {
				t.Fatal("refused orphan stayed adopted")
			}

			// Only orphans are inspected; active and unmarked namespaces are never touched.
			for _, namespace := range inspected {
				if namespace == recActive || namespace == recUnmarked {
					t.Fatalf("inspected a namespace that is not an orphan: %s", namespace)
				}
			}
		})
	}
}

func TestRecoveryAllowsKnownLabVeth(t *testing.T) {
	f := newRecoveryFixture(t)

	f.recovery.env.inspectLinks = func(_ context.Context, namespace string) ([]byte, error) {
		if namespace == recOrphan {
			return []byte(`[{"ifname":"lo"}, {"ifname":"ev-a", "linkinfo":{"info_kind":"veth"}}]`), nil
		}

		return []byte(`[{"ifname":"lo"}]`), nil
	}

	_, err := f.recovery.Clean(context.Background())

	// The fixture's deliberately busy orphan must still fail deletion.
	if !errors.Is(err, ErrNetNSBusy) || errors.Is(err, ErrRecoveryUnsafeLinks) {
		t.Fatalf("unexpected recovery result: %v", err)
	}

	if f.present[recOrphan] {
		t.Fatal("safe veth-only orphan was not removed")
	}
}

func TestRecoveryRechecksStaleMarker(t *testing.T) {
	f := newRecoveryFixture(t)

	// A namespace appeared after the scan.
	f.present[recStale] = true

	if err := f.recovery.removeStaleMarker(recStale); !errors.Is(err, ErrRecoveryMarkerNotStale) {
		t.Fatalf("new namespace not protected: %v", err)
	}

	delete(f.present, recStale)

	// The marker's owner (pid 102) is running again.
	f.recovery.env.alive = func(pid int, _ string) bool { return pid == 102 || pid == 200 }

	if err := f.recovery.removeStaleMarker(recStale); !errors.Is(err, ErrRecoveryMarkerNotStale) {
		t.Fatalf("live marker owner not protected: %v", err)
	}

	// Namespace absent and owner gone: removal is safe within this ownership model.
	f.recovery.env.alive = func(pid int, _ string) bool { return pid == 200 }

	if err := f.recovery.removeStaleMarker(recStale); err != nil {
		t.Fatal(err)
	}

	if _, exists, err := f.manager.markers.read(recStale); err != nil || exists {
		t.Fatal("stale marker survived cleanup")
	}

	// A second call (marker already gone) is not an error.
	if err := f.recovery.removeStaleMarker(recStale); err != nil {
		t.Fatalf("already-removed marker reported as error: %v", err)
	}

	if err := f.recovery.removeStaleMarker("../etc"); !errors.Is(err, ErrRecoveryMarkerNotStale) {
		t.Fatalf("invalid name accepted: %v", err)
	}
}

func TestRecoveryKeepsOrphanUnderlayTables(t *testing.T) {
	f := newRecoveryFixture(t)

	before := append([]string(nil), f.tables...)

	if _, err := f.recovery.Clean(context.Background()); !errors.Is(err, ErrNetNSBusy) {
		t.Fatalf("busy namespace should be preserved: %v", err)
	}

	if !reflect.DeepEqual(before, f.tables) {
		t.Fatal("automatic recovery removed an underlay table")
	}

	items, err := f.recovery.Scan(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	got := states(items)

	for _, table := range []string{"egresslab_ul_00000000000000a1", "egresslab_ul_00000000000000ff"} {
		if got[table] != LabStateOrphanTable {
			t.Fatalf("expected retained orphan table %s: %s", table, got[table])
		}
	}
}
