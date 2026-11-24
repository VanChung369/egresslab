package agent

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"
)

type preflightFixture struct {
	backend   *SealedLabBackend
	kernel    *fakeSealedKernel
	tables    []string
	tablesErr error
}

func newPreflightFixture(t *testing.T) *preflightFixture {
	t.Helper()

	b, kernel, _ := sealedBackendFixture(t)
	b.manager.markers = testMarkers(t, 4242, "s1")
	b.kernelCheck = func() error { return nil }

	f := &preflightFixture{backend: b, kernel: kernel}

	b.recovery = &LabRecovery{manager: b.manager, env: recoveryEnv{
		listNamespaces: func() ([]string, error) {
			var names []string
			for name := range kernel.present {
				names = append(names, name)
			}
			sort.Strings(names)
			return names, nil
		},
		alive:      func(pid int, start string) bool { return pid == 4242 && start == "s1" },
		listTables: func(context.Context) ([]string, error) { return f.tables, f.tablesErr },
	}}

	return f
}

// otherMarker writes a marker as another process would.
func (f *preflightFixture) otherMarker(t *testing.T, name string, pid int, start string) {
	t.Helper()

	other := &labMarkers{dir: f.backend.manager.markers.dir, pid: pid, start: start, now: time.Now}
	if err := other.write(name); err != nil {
		t.Fatal(err)
	}
}

func TestSealedLabPreflight(t *testing.T) {
	ctx := context.Background()

	requireBlocked := func(t *testing.T, f *preflightFixture, want string) {
		t.Helper()

		err := f.backend.Preflight(ctx)
		if !errors.Is(err, ErrRecoveryRequired) || !strings.Contains(err.Error(), want) {
			t.Fatalf("got %v, want recovery required naming %q", err, want)
		}
	}

	t.Run("clean host and own labs pass", func(t *testing.T) {
		f := newPreflightFixture(t)

		if err := f.backend.Preflight(ctx); err != nil {
			t.Fatal(err)
		}

		if _, err := f.backend.Create(ctx); err != nil {
			t.Fatal(err)
		}

		if err := f.backend.Preflight(ctx); err != nil {
			t.Fatalf("own lab blocked creation: %v", err)
		}
	})

	t.Run("orphan of a crashed session", func(t *testing.T) {
		f := newPreflightFixture(t)
		f.kernel.present[recOrphan] = true
		f.otherMarker(t, recOrphan, 999, "gone")
		requireBlocked(t, f, recOrphan+" (orphan)")
	})

	t.Run("lab of another live process", func(t *testing.T) {
		f := newPreflightFixture(t)
		f.kernel.present[recActive] = true
		f.otherMarker(t, recActive, 4242, "s1")
		requireBlocked(t, f, recActive+" (active)")
	})

	t.Run("unmarked namespace", func(t *testing.T) {
		f := newPreflightFixture(t)
		f.kernel.present[recUnmarked] = true
		requireBlocked(t, f, recUnmarked+" (unmarked)")
	})

	t.Run("stale marker", func(t *testing.T) {
		f := newPreflightFixture(t)
		f.otherMarker(t, recStale, 999, "gone")
		requireBlocked(t, f, "marker "+recStale)
	})

	t.Run("underlay table", func(t *testing.T) {
		f := newPreflightFixture(t)
		f.tables = []string{"egresslab_ul_00000000000000a1"}
		requireBlocked(t, f, "underlay_table")
	})

	t.Run("scan failure", func(t *testing.T) {
		f := newPreflightFixture(t)
		f.tablesErr = errors.New("nft: permission denied")
		requireBlocked(t, f, "permission denied")
	})

	t.Run("no scanner", func(t *testing.T) {
		f := newPreflightFixture(t)
		f.backend.recovery = nil
		requireBlocked(t, f, "unavailable")
	})

	t.Run("kernel check runs first", func(t *testing.T) {
		f := newPreflightFixture(t)
		f.tablesErr = errors.New("must not be reached")
		f.backend.kernelCheck = func() error { return ErrKernelIncompatible }

		if err := f.backend.Preflight(ctx); !errors.Is(err, ErrKernelIncompatible) {
			t.Fatalf("got %v", err)
		}
	})

	t.Run("never cleans", func(t *testing.T) {
		f := newPreflightFixture(t)
		f.kernel.present[recOrphan] = true
		f.otherMarker(t, recOrphan, 999, "gone")

		_ = f.backend.Preflight(ctx)

		if !f.kernel.present[recOrphan] || f.kernel.ran("delete") != 0 {
			t.Fatal("preflight removed a namespace")
		}
	})
}

func TestCheckFallbackTunnels(t *testing.T) {
	setup := func(t *testing.T, devices []string, sysctl *string) (string, string) {
		t.Helper()

		root := t.TempDir()
		netDir := filepath.Join(root, "net")
		if err := os.Mkdir(netDir, 0o755); err != nil {
			t.Fatal(err)
		}

		for _, name := range append([]string{"lo", "eth0"}, devices...) {
			if err := os.WriteFile(filepath.Join(netDir, name), nil, 0o644); err != nil {
				t.Fatal(err)
			}
		}

		sysctlPath := filepath.Join(root, "fb_tunnels_only_for_init_net")
		if sysctl != nil {
			if err := os.WriteFile(sysctlPath, []byte(*sysctl+"\n"), 0o644); err != nil {
				t.Fatal(err)
			}
		}

		return netDir, sysctlPath
	}

	value := func(s string) *string { return &s }

	tests := []struct {
		name    string
		devices []string
		sysctl  *string
		ok      bool
	}{
		{"no fallback devices", nil, value("0"), true},
		{"sit0 with sysctl 0", []string{"sit0"}, value("0"), false},
		{"tunl0 and gre0 without the sysctl", []string{"tunl0", "gre0"}, nil, false},
		{"sit0 with sysctl 1", []string{"sit0"}, value("1"), true},
		{"sit0 with sysctl 2", []string{"sit0"}, value("2"), true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			netDir, sysctlPath := setup(t, tt.devices, tt.sysctl)
			err := checkFallbackTunnels(netDir, sysctlPath)

			if tt.ok != (err == nil) || (err != nil && !errors.Is(err, ErrKernelIncompatible)) {
				t.Fatalf("got %v", err)
			}

			for _, device := range tt.devices {
				if err != nil && !strings.Contains(err.Error(), device) {
					t.Errorf("error does not name %s: %v", device, err)
				}
			}
		})
	}

	t.Run("unreadable sysctl", func(t *testing.T) {
		netDir, sysctlPath := setup(t, []string{"sit0"}, nil)
		if err := os.Mkdir(sysctlPath, 0o755); err != nil {
			t.Fatal(err)
		}

		if err := checkFallbackTunnels(netDir, sysctlPath); !errors.Is(err, ErrKernelIncompatible) {
			t.Fatalf("got %v", err)
		}
	})
}
