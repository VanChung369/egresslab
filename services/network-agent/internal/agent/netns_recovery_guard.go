package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
)

var (
	ErrRecoveryUnsafeLinks    = errors.New("recovery cannot prove the namespace contains only safe lab links")
	ErrRecoveryLiveTunnel     = fmt.Errorf("%w: WireGuard interface remains", ErrRecoveryUnsafeLinks)
	ErrRecoveryMarkerNotStale = errors.New("marker is not provably stale")
)

// requireRecoverableLinksLocked reads the namespace's interfaces from the kernel before an
// orphan is deleted. Only loopback and the known lab veth ends (ev-a, ev-b) qualify. Any
// WireGuard interface (even down), an unknown device, or a listing that cannot be read or
// parsed blocks automatic deletion. Its encrypted socket may live in the root namespace,
// so a dead owner process is not enough to call it safe.
//
// The caller must hold r.manager.mu.
func (r *LabRecovery) requireRecoverableLinksLocked(ctx context.Context, namespace string) error {
	if r.env.inspectLinks == nil {
		return fmt.Errorf("%w: link inspector unavailable", ErrRecoveryUnsafeLinks)
	}

	data, err := r.env.inspectLinks(ctx, namespace)
	if err != nil {
		return fmt.Errorf("%w: read links: %w", ErrRecoveryUnsafeLinks, err)
	}

	var links []struct {
		Name     string `json:"ifname"`
		LinkInfo struct {
			Kind string `json:"info_kind"`
		} `json:"linkinfo"`
	}

	if err := json.Unmarshal(data, &links); err != nil || len(links) == 0 {
		return fmt.Errorf("%w: empty or malformed link listing", ErrRecoveryUnsafeLinks)
	}

	seen := make(map[string]bool)
	loopback := false

	for _, link := range links {
		if link.Name == "" || seen[link.Name] {
			return fmt.Errorf("%w: missing or duplicate interface", ErrRecoveryUnsafeLinks)
		}

		seen[link.Name] = true

		if link.Name == labWGInterface || link.LinkInfo.Kind == "wireguard" {
			return fmt.Errorf("%w: %s", ErrRecoveryLiveTunnel, link.Name)
		}

		switch link.Name {
		case "lo":
			loopback = true

		case labVethA, labVethB:
			if link.LinkInfo.Kind != "veth" {
				return fmt.Errorf("%w: %s is not a veth", ErrRecoveryUnsafeLinks, link.Name)
			}

		default:
			return fmt.Errorf("%w: unknown interface %s", ErrRecoveryUnsafeLinks, link.Name)
		}
	}

	if !loopback {
		return fmt.Errorf("%w: loopback not present", ErrRecoveryUnsafeLinks)
	}

	return nil
}

// removeStaleMarker re-checks, under the manager lock, that the marker is still stale: its
// namespace did not appear and its owner did not come back since the scan.
//
// The caller must not hold r.manager.mu.
func (r *LabRecovery) removeStaleMarker(name string) error {
	if !labNamePattern.MatchString(name) {
		return fmt.Errorf("%w: invalid name", ErrRecoveryMarkerNotStale)
	}

	r.manager.mu.Lock()
	defer r.manager.mu.Unlock()

	if _, owned := r.manager.owned[name]; owned {
		return fmt.Errorf("%w: owned by this session", ErrRecoveryMarkerNotStale)
	}

	exists, err := r.manager.exists(name)
	if err != nil {
		return fmt.Errorf("%w: inspect namespace: %w", ErrRecoveryMarkerNotStale, err)
	}

	if exists {
		return fmt.Errorf("%w: namespace exists", ErrRecoveryMarkerNotStale)
	}

	marker, ok, err := r.manager.markers.read(name)
	if err != nil {
		return fmt.Errorf("%w: read marker: %w", ErrRecoveryMarkerNotStale, err)
	}

	// Another cleanup may already have removed it.
	if !ok {
		return nil
	}

	if r.env.alive(marker.PID, marker.PIDStart) {
		return fmt.Errorf("%w: marker owner is running", ErrRecoveryMarkerNotStale)
	}

	return r.manager.removeMarker(name)
}
