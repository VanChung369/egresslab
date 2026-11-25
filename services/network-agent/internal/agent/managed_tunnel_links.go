package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
)

// A managed tunnel link carries an alias (ifalias) naming its namespace and creation name. The
// kernel keeps the alias across the move into the namespace and the rename to wg0, so the link can
// be found in each place it passes through:
//
//	root namespace  egwgXXXXXXXX  after "ip link add"
//	lab namespace   egwgXXXXXXXX  after "ip link set netns"
//	lab namespace   wg0           after the rename
//
// The alias tells EgressLab's own links apart from others; it is not a defence against root.
type managedLink struct {
	Name     string `json:"ifname"`
	Index    int    `json:"ifindex"`
	Type     string `json:"link_type"`
	Alias    string `json:"ifalias"`
	LinkInfo struct {
		Kind string `json:"info_kind"`
	} `json:"linkinfo"`
}

type managedTunnel struct {
	namespace string
	rootName  string
	alias     string

	peer    managedPeerPolicy
	network managedNetworkPolicy

	linkRemoved bool
	faulted     bool
}

type managedLinkLocation struct {
	namespace string // empty for the root namespace
	name      string
}

// The caller must hold manager.mu.
func (b *ManagedTunnelBackend) listLinksLocked(ctx context.Context, namespace string) ([]managedLink, error) {
	args := []string{"-details", "-json", "link", "show"}
	if namespace != "" {
		args = append([]string{"-n", namespace}, args...)
	}

	commandCtx, cancel := context.WithTimeout(ctx, netNSCommandTimeout)
	defer cancel()

	data, err := b.sealed.manager.run(commandCtx, args...)
	if err != nil {
		return nil, fmt.Errorf("inspect kernel links: %w", err)
	}

	var links []managedLink
	if err := json.Unmarshal(data, &links); err != nil {
		return nil, fmt.Errorf("parse kernel links: %w", err)
	}

	if len(links) == 0 {
		return nil, errors.New("empty link inventory")
	}

	names := make(map[string]bool)
	indexes := make(map[int]bool)

	for _, link := range links {
		if link.Name == "" || link.Index <= 0 || names[link.Name] || indexes[link.Index] {
			return nil, errors.New("invalid or duplicate kernel link")
		}

		names[link.Name] = true
		indexes[link.Index] = true
	}

	return links, nil
}

// locateManagedTunnel finds the tagged link in the root (outside) or lab (inside) inventory. It
// returns nil when the link is in neither, and an error for anything it cannot attribute: a
// device with the tunnel's name or alias but not both, a second match, or a foreign device in the
// lab namespace. Unexpected devices are never adopted.
func locateManagedTunnel(outside, inside []managedLink, t *managedTunnel) (*managedLinkLocation, error) {
	var found *managedLinkLocation

	record := func(link managedLink, namespace string) error {
		if link.Alias != t.alias || link.LinkInfo.Kind != "wireguard" || found != nil {
			return errors.New("cannot establish tunnel ownership")
		}

		found = &managedLinkLocation{namespace: namespace, name: link.Name}

		return nil
	}

	for _, link := range outside {
		if link.Name != t.rootName && link.Alias != t.alias {
			continue
		}

		if link.Name != t.rootName {
			return nil, errors.New("unexpected root tunnel name")
		}

		if err := record(link, ""); err != nil {
			return nil, err
		}
	}

	loopback := false

	for _, link := range inside {
		if link.Name == "lo" {
			if link.Type != "loopback" || link.Alias == t.alias {
				return nil, errors.New("unexpected loopback identity")
			}

			loopback = true

			continue
		}

		if link.Name != labWGInterface && link.Name != t.rootName {
			return nil, fmt.Errorf("unexpected namespace device %s", link.Name)
		}

		if err := record(link, t.namespace); err != nil {
			return nil, err
		}
	}

	if !loopback {
		return nil, errors.New("namespace loopback missing")
	}

	return found, nil
}

// The caller must hold manager.mu.
func (b *ManagedTunnelBackend) locateLocked(ctx context.Context, t *managedTunnel) (*managedLinkLocation, error) {
	outside, err := b.listLinksLocked(ctx, "")
	if err != nil {
		return nil, err
	}

	inside, err := b.listLinksLocked(ctx, t.namespace)
	if err != nil {
		return nil, err
	}

	return locateManagedTunnel(outside, inside, t)
}
