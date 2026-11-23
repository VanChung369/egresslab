package agent

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

const (
	recOrphan   = "egresslab-lab-00000000000000a1"
	recActive   = "egresslab-lab-00000000000000a2"
	recUnmarked = "egresslab-lab-00000000000000a3"
	recStale    = "egresslab-lab-00000000000000a4"
	recBusy     = "egresslab-lab-00000000000000a5"
)

func testMarkers(t *testing.T, pid int, start string) *labMarkers {
	t.Helper()

	return &labMarkers{
		dir:   filepath.Join(t.TempDir(), "netns"),
		pid:   pid,
		start: start,
		now:   func() time.Time { return time.Date(2026, 11, 23, 0, 0, 0, 0, time.UTC) },
	}
}

func TestParseProcStatStart(t *testing.T) {
	stat := "4242 (egresslab (vpn) lab) S 1 4242 4242 0 -1 4194560 100 0 0 0 1 2 0 0 20 0 1 0 987654 1234 56 18446744073709551615"

	start, err := parseProcStatStart(stat)
	if err != nil || start != "987654" {
		t.Fatalf("unexpected start %q %v", start, err)
	}

	for _, bad := range []string{"", "4242 egresslab S 1", "4242 (x) S 1 2 3"} {
		if _, err := parseProcStatStart(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestMarkersRoundTrip(t *testing.T) {
	markers := testMarkers(t, 4242, "987654")

	if err := markers.write(recOrphan); err != nil {
		t.Fatal(err)
	}

	marker, ok, err := markers.read(recOrphan)
	if err != nil || !ok || marker.PID != 4242 || marker.PIDStart != "987654" || marker.Name != recOrphan {
		t.Fatalf("unexpected marker %+v %v %v", marker, ok, err)
	}

	if names, err := markers.names(); err != nil || !reflect.DeepEqual(names, []string{recOrphan}) {
		t.Fatalf("unexpected names %v %v", names, err)
	}

	// A marker copied under another namespace's name must not be trusted.
	if err := os.Rename(markers.path(recOrphan), markers.path(recActive)); err != nil {
		t.Fatal(err)
	}

	if _, _, err := markers.read(recActive); err == nil {
		t.Fatal("marker for another namespace accepted")
	}

	if err := markers.remove(recActive); err != nil {
		t.Fatal(err)
	}

	if _, ok, err := markers.read(recActive); err != nil || ok {
		t.Fatal("removed marker still readable")
	}
}

func TestCreateWritesMarkerFirstAndDeleteRemovesIt(t *testing.T) {
	var markerAtAdd bool

	m := newNetNSLabManager(nil, func() (string, error) { return recOrphan, nil }, func(string) (bool, error) { return false, nil })
	m.markers = testMarkers(t, 1, "1")
	m.run = func(_ context.Context, args ...string) ([]byte, error) {
		if args[1] == "add" {
			_, markerAtAdd, _ = m.markers.read(recOrphan)
		}
		return nil, nil
	}

	name, err := m.Create(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	if !markerAtAdd {
		t.Fatal("namespace created before its ownership marker")
	}

	if err := m.Delete(context.Background(), name); err != nil {
		t.Fatal(err)
	}

	if _, ok, _ := m.markers.read(name); ok {
		t.Fatal("marker survived namespace deletion")
	}
}

func TestCreateFailureRemovesMarker(t *testing.T) {
	m := newNetNSLabManager(
		func(context.Context, ...string) ([]byte, error) { return nil, errors.New("add failed") },
		func() (string, error) { return recOrphan, nil },
		func(string) (bool, error) { return false, nil },
	)
	m.markers = testMarkers(t, 1, "1")

	if _, err := m.Create(context.Background()); err == nil {
		t.Fatal("expected failure")
	}

	if _, ok, _ := m.markers.read(recOrphan); ok {
		t.Fatal("marker left behind for a namespace that was never created")
	}
}

type recoveryFixture struct {
	recovery *LabRecovery
	manager  *NetNSLabManager
	present  map[string]bool
	tables   []string
	deleted  []string
	ipCalls  [][]string
}

func newRecoveryFixture(t *testing.T) *recoveryFixture {
	t.Helper()

	f := &recoveryFixture{present: map[string]bool{
		recOrphan: true, recActive: true, recUnmarked: true, recBusy: true,
	}}

	f.manager = newNetNSLabManager(
		func(_ context.Context, args ...string) ([]byte, error) {
			f.ipCalls = append(f.ipCalls, args)
			if args[1] == "pids" && args[2] == recBusy {
				return []byte("1234\n"), nil
			}
			if args[1] == "delete" {
				delete(f.present, args[2])
			}
			return nil, nil
		},
		nil,
		func(name string) (bool, error) { return f.present[name], nil },
	)
	f.manager.markers = testMarkers(t, 1, "1")

	// Markers: two dead owners (orphan, busy), one live owner, one for a namespace that is gone.
	for name, pid := range map[string]int{recOrphan: 100, recBusy: 101, recActive: 200, recStale: 102} {
		m := *f.manager.markers
		m.pid, m.start = pid, "7"
		if err := m.write(name); err != nil {
			t.Fatal(err)
		}
	}

	f.tables = []string{
		"egresslab_ul_00000000000000a1", // namespace orphaned -> removable after it is deleted
		"egresslab_ul_00000000000000a2", // namespace active -> kept
		"egresslab_ul_00000000000000ff", // namespace long gone -> removable
	}

	f.recovery = &LabRecovery{manager: f.manager, env: recoveryEnv{
		listNamespaces: func() ([]string, error) {
			var names []string
			for name := range f.present {
				names = append(names, name)
			}
			return names, nil
		},
		alive: func(pid int, _ string) bool { return pid == 200 },
		listTables: func(context.Context) ([]string, error) {
			return append([]string(nil), f.tables...), nil
		},
		deleteTable: func(_ context.Context, table string) error {
			f.deleted = append(f.deleted, table)
			for i, name := range f.tables {
				if name == table {
					f.tables = append(f.tables[:i], f.tables[i+1:]...)
					break
				}
			}
			return nil
		},
	}}

	return f
}

func states(items []LabRecoveryItem) map[string]string {
	out := map[string]string{}
	for _, item := range items {
		out[item.Name] = item.State
	}
	return out
}

func TestRecoveryScanIsReadOnly(t *testing.T) {
	f := newRecoveryFixture(t)

	items, err := f.recovery.Scan(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	want := map[string]string{
		recOrphan:                       LabStateOrphan,
		recBusy:                         LabStateOrphan,
		recActive:                       LabStateActive,
		recUnmarked:                     LabStateUnmarked,
		recStale:                        LabStateStaleMarker,
		"egresslab_ul_00000000000000a1": LabStateKeptTable,
		"egresslab_ul_00000000000000a2": LabStateKeptTable,
		"egresslab_ul_00000000000000ff": LabStateOrphanTable,
	}

	if got := states(items); !reflect.DeepEqual(got, want) {
		t.Fatalf("unexpected scan:\n got %v\nwant %v", got, want)
	}

	if len(f.ipCalls) != 0 || len(f.deleted) != 0 {
		t.Fatal("scan changed something")
	}
}

func TestRecoveryCleanRemovesOnlyProvenOrphans(t *testing.T) {
	f := newRecoveryFixture(t)

	removed, err := f.recovery.Clean(context.Background())
	if err == nil || !errors.Is(err, ErrNetNSBusy) {
		t.Fatalf("busy orphan should be reported: %v", err)
	}

	got := states(removed)
	want := map[string]string{
		recOrphan:                       LabStateOrphan,
		recStale:                        LabStateStaleMarker,
		"egresslab_ul_00000000000000a1": LabStateOrphanTable,
		"egresslab_ul_00000000000000ff": LabStateOrphanTable,
	}

	if !reflect.DeepEqual(got, want) {
		t.Fatalf("unexpected removals:\n got %v\nwant %v", got, want)
	}

	for _, kept := range []string{recActive, recUnmarked, recBusy} {
		if !f.present[kept] {
			t.Fatalf("%s was deleted", kept)
		}
	}

	if !reflect.DeepEqual(f.tables, []string{"egresslab_ul_00000000000000a2"}) {
		t.Fatalf("active namespace lost its underlay table: %v", f.tables)
	}

	if _, owned := f.manager.owned[recBusy]; owned {
		t.Fatal("busy orphan stayed adopted after a failed delete")
	}

	if _, ok, _ := f.manager.markers.read(recBusy); !ok {
		t.Fatal("busy orphan lost its marker")
	}
}

func TestUnderlayTablesFromJSON(t *testing.T) {
	data := []byte(`{"nftables": [{"metainfo": {}},
	  {"table": {"family": "inet", "name": "egresslab_ul_00000000000000a1", "handle": 1}},
	  {"table": {"family": "ip", "name": "egresslab_ul_00000000000000a2", "handle": 2}},
	  {"table": {"family": "inet", "name": "egresslab_ul_bad", "handle": 3}},
	  {"table": {"family": "inet", "name": "filter", "handle": 4}}]}`)

	tables, err := underlayTablesFromJSON(data)
	if err != nil || !reflect.DeepEqual(tables, []string{"egresslab_ul_00000000000000a1"}) {
		t.Fatalf("unexpected tables %v %v", tables, err)
	}

	if _, err := underlayTablesFromJSON([]byte("nope")); err == nil || !strings.Contains(err.Error(), "parse") {
		t.Fatal("garbage accepted")
	}
}
