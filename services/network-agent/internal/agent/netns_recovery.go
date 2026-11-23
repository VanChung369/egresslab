package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"sort"
	"strings"
)

// Lab resource states reported by LabRecovery.Scan.
const (
	LabStateActive      = "active"          // owner process still running; never touched
	LabStateOrphan      = "orphan"          // marker owner is gone; deleted by -delete only if its links are safe
	LabStateUnmarked    = "unmarked"        // lab-named namespace without a marker; report only
	LabStateStaleMarker = "stale_marker"    // marker whose namespace no longer exists
	LabStateUnreadable  = "unreadable"      // marker exists but cannot be trusted; report only
	LabStateOrphanTable = "orphan_underlay" // no named namespace; never deleted automatically
	LabStateKeptTable   = "underlay_kept"   // its namespace still exists; removing it would unconfine wg0
)

type LabRecoveryItem struct {
	Kind   string `json:"kind"` // "namespace", "marker" or "underlay_table"
	Name   string `json:"name"`
	State  string `json:"state"`
	Detail string `json:"detail,omitempty"`
}

type recoveryEnv struct {
	listNamespaces func() ([]string, error)
	alive          func(pid int, start string) bool
	listTables     func(ctx context.Context) ([]string, error)
	inspectLinks   func(ctx context.Context, namespace string) ([]byte, error)
}

// LabRecovery finds lab resources left behind after a crash or restart. Scan never changes
// anything; Clean removes only orphans whose owner process is provably gone and whose kernel
// link inventory is safe, plus stale markers. Root underlay tables are never removed.
//
// Its checks can still race with root processes outside EgressLab; they do not replace an
// inter-process lock or ownership managed by a privileged helper.
type LabRecovery struct {
	manager *NetNSLabManager
	env     recoveryEnv
}

func NewLabRecovery(m *NetNSLabManager) (*LabRecovery, error) {
	if runtime.GOOS != "linux" {
		return nil, ErrLinuxRequired
	}

	if m == nil || m.markers == nil {
		return nil, errors.New("lab recovery needs a namespace manager with ownership markers")
	}

	nftPath, err := findSystemBinary("nft")
	if err != nil {
		return nil, err
	}

	env := recoveryEnv{
		listNamespaces: listLabNamespaces,
		alive:          processAlive,
		listTables: func(ctx context.Context) ([]string, error) {
			commandCtx, cancel := context.WithTimeout(ctx, netNSCommandTimeout)
			defer cancel()

			output, err := exec.CommandContext(commandCtx, nftPath, "-j", "list", "tables").Output()
			if err != nil {
				return nil, fmt.Errorf("nft list tables: %w", err)
			}

			return underlayTablesFromJSON(output)
		},
		// Read-only: the namespace manager's validated iproute2 runner lists the links.
		inspectLinks: func(ctx context.Context, namespace string) ([]byte, error) {
			commandCtx, cancel := context.WithTimeout(ctx, netNSCommandTimeout)
			defer cancel()

			return m.run(commandCtx, "-n", namespace, "-details", "-json", "link", "show")
		},
	}

	return &LabRecovery{manager: m, env: env}, nil
}

func listLabNamespaces() ([]string, error) {
	entries, err := os.ReadDir(netNSRunDir)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}

	if err != nil {
		return nil, err
	}

	var names []string
	for _, entry := range entries {
		if labNamePattern.MatchString(entry.Name()) {
			names = append(names, entry.Name())
		}
	}

	return names, nil
}

func underlayTablesFromJSON(data []byte) ([]string, error) {
	var doc struct {
		Nftables []struct {
			Table *struct {
				Family string `json:"family"`
				Name   string `json:"name"`
			} `json:"table"`
		} `json:"nftables"`
	}

	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("parse nft tables: %w", err)
	}

	var tables []string
	for _, object := range doc.Nftables {
		if object.Table != nil && object.Table.Family == "inet" && underlayTablePattern(object.Table.Name) {
			tables = append(tables, object.Table.Name)
		}
	}

	return tables, nil
}

func underlayTablePattern(name string) bool {
	id, ok := strings.CutPrefix(name, underlayTablePrefix)
	return ok && labNamePattern.MatchString("egresslab-lab-"+id)
}

// Scan classifies every lab namespace, marker and underlay table without changing anything.
func (r *LabRecovery) Scan(ctx context.Context) ([]LabRecoveryItem, error) {
	namespaces, err := r.env.listNamespaces()
	if err != nil {
		return nil, fmt.Errorf("list namespaces: %w", err)
	}

	markerNames, err := r.manager.markers.names()
	if err != nil {
		return nil, fmt.Errorf("list ownership markers: %w", err)
	}

	tables, err := r.env.listTables(ctx)
	if err != nil {
		return nil, err
	}

	r.manager.mu.Lock()
	defer r.manager.mu.Unlock()

	var items []LabRecoveryItem
	present := map[string]bool{}

	for _, name := range namespaces {
		present[name] = true
		items = append(items, r.classifyLocked(name))
	}

	for _, name := range markerNames {
		if present[name] {
			continue
		}

		item := LabRecoveryItem{Kind: "marker", Name: name, State: LabStateStaleMarker}
		if marker, ok, err := r.manager.markers.read(name); err != nil || !ok {
			item.State, item.Detail = LabStateUnreadable, fmt.Sprint(err)
		} else if r.env.alive(marker.PID, marker.PIDStart) {
			// The owner may be between writing the marker and creating the namespace.
			item.State, item.Detail = LabStateActive, fmt.Sprintf("owner pid %d is running", marker.PID)
		}

		items = append(items, item)
	}

	for _, table := range tables {
		namespace := "egresslab-lab-" + strings.TrimPrefix(table, underlayTablePrefix)
		item := LabRecoveryItem{Kind: "underlay_table", Name: table, State: LabStateOrphanTable}

		if present[namespace] {
			item.State, item.Detail = LabStateKeptTable, "namespace "+namespace+" still exists"
		}

		items = append(items, item)
	}

	sort.SliceStable(items, func(i, j int) bool {
		if items[i].Kind != items[j].Kind {
			return items[i].Kind < items[j].Kind
		}
		return items[i].Name < items[j].Name
	})

	return items, nil
}

func (r *LabRecovery) classifyLocked(name string) LabRecoveryItem {
	item := LabRecoveryItem{Kind: "namespace", Name: name}

	if _, owned := r.manager.owned[name]; owned {
		item.State, item.Detail = LabStateActive, "owned by this process"
		return item
	}

	marker, ok, err := r.manager.markers.read(name)
	switch {
	case err != nil:
		item.State, item.Detail = LabStateUnreadable, err.Error()

	case !ok:
		item.State, item.Detail = LabStateUnmarked, "no ownership marker; inspect and remove manually"

	case r.env.alive(marker.PID, marker.PIDStart):
		item.State, item.Detail = LabStateActive, fmt.Sprintf("owner pid %d is running", marker.PID)

	default:
		item.State, item.Detail = LabStateOrphan, fmt.Sprintf("owner pid %d is gone", marker.PID)
	}

	return item
}

// Clean removes proven orphan namespaces with safe link inventories (refused if processes still
// run inside), then stale ownership markers.
//
// Active, unmarked, unreadable and unsafe resources are preserved. Root underlay tables are
// never removed automatically.
func (r *LabRecovery) Clean(ctx context.Context) ([]LabRecoveryItem, error) {
	items, err := r.Scan(ctx)
	if err != nil {
		return nil, err
	}

	var errs []error
	var removed []LabRecoveryItem

	for _, item := range items {
		if item.Kind != "namespace" || item.State != LabStateOrphan {
			continue
		}

		if err := r.deleteOrphanNamespace(ctx, item.Name); err != nil {
			errs = append(errs, err)
			continue
		}

		removed = append(removed, item)
	}

	for _, item := range items {
		if item.Kind != "marker" || item.State != LabStateStaleMarker {
			continue
		}

		if err := r.removeStaleMarker(item.Name); err != nil {
			errs = append(errs, err)
			continue
		}

		removed = append(removed, item)
	}

	// Root-namespace underlay tables are intentionally preserved. A missing named namespace does
	// not prove the encrypted WireGuard socket is gone: a namespace without its /run/netns name
	// lives on while any process or file descriptor still holds it. Removing those tables needs
	// a separate, explicitly verified offline procedure.
	return removed, errors.Join(errs...)
}

func (r *LabRecovery) deleteOrphanNamespace(ctx context.Context, name string) error {
	r.manager.mu.Lock()
	defer r.manager.mu.Unlock()

	// Re-check under the lock: the owner must still be gone.
	if item := r.classifyLocked(name); item.State != LabStateOrphan {
		return fmt.Errorf("%s is no longer an orphan (%s)", name, item.State)
	}

	// The owner is gone, but the namespace may still hold a WireGuard interface or an
	// unexpected device. Refuse unless the kernel's own link listing is safe.
	if err := r.requireRecoverableLinksLocked(ctx, name); err != nil {
		return fmt.Errorf("refuse orphan cleanup for %s: %w", name, err)
	}

	r.manager.owned[name] = struct{}{}

	commandCtx, cancel := context.WithTimeout(ctx, netNSCommandTimeout)
	defer cancel()

	if err := r.manager.deleteLocked(commandCtx, name); err != nil {
		delete(r.manager.owned, name)
		return fmt.Errorf("delete orphan %s: %w", name, err)
	}

	return nil
}
