package control

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"sort"
)

// Discovery data is read from the agent's read-only GET endpoints and passed to the desktop only
// after it has been bounded and sanitized. Nothing here can change the agent host.
const (
	maxDiscoveryBytes       = 64 << 10
	maxDiscoveredLinks      = 256
	maxDiscoveredNamespaces = 256
)

var (
	safeTokenPattern   = regexp.MustCompile(`^[A-Za-z0-9_.@:+-]{1,64}$`)
	checkKeyPattern    = regexp.MustCompile(`^[a-z0-9_]{1,40}$`)
	labNamespaceFormat = regexp.MustCompile(`^egresslab-lab-[0-9a-f]{16}$`)
)

type AgentCheck struct {
	Status string `json:"status"`
}

type AgentLink struct {
	Name             string `json:"name"`
	Kind             string `json:"kind"`
	Category         string `json:"category"`
	OperationalState string `json:"operational_state"`
}

type AgentDiscovery struct {
	OS              string                `json:"os,omitempty"`
	Capabilities    map[string]AgentCheck `json:"capabilities"`
	Links           []AgentLink           `json:"links"`
	LabNamespaces   []string              `json:"lab_namespaces"`
	OtherNamespaces int                   `json:"other_namespaces"`
	Errors          []string              `json:"errors"`
}

// DiscoveredTunnel is a WireGuard interface seen on the agent host. EgressLab does not manage it.
type DiscoveredTunnel struct {
	ID               string `json:"id"`
	Name             string `json:"name"`
	Kind             string `json:"kind"`
	OperationalState string `json:"operational_state"`
	Managed          bool   `json:"managed"`
	Source           string `json:"source"`
}

func (c *AgentClient) getJSON(ctx context.Context, path string, into any) error {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+path, nil)
	if err != nil {
		return err
	}

	request.Header.Set("Authorization", "Bearer "+c.token)
	request.Header.Set("Accept", "application/json")

	response, err := c.client.Do(request)
	if err != nil {
		return fmt.Errorf("unreachable")
	}
	defer response.Body.Close()

	body, err := io.ReadAll(io.LimitReader(response.Body, maxDiscoveryBytes+1))
	if err != nil || len(body) > maxDiscoveryBytes {
		return fmt.Errorf("response too large or unreadable")
	}

	if response.StatusCode != http.StatusOK {
		var failure struct {
			Error struct {
				Code string `json:"code"`
			} `json:"error"`
		}

		if json.Unmarshal(body, &failure) == nil && safeTokenPattern.MatchString(failure.Error.Code) {
			return fmt.Errorf("%s", failure.Error.Code)
		}

		return fmt.Errorf("HTTP %d", response.StatusCode)
	}

	if err := json.Unmarshal(body, into); err != nil {
		return fmt.Errorf("invalid response")
	}

	return nil
}

func safeToken(value, fallback string) string {
	if safeTokenPattern.MatchString(value) {
		return value
	}

	return fallback
}

// discover reads capabilities, links and namespaces. Each section fails independently.
func (c *AgentClient) discover(ctx context.Context) *AgentDiscovery {
	d := &AgentDiscovery{
		Capabilities:  map[string]AgentCheck{},
		Links:         []AgentLink{},
		LabNamespaces: []string{},
		Errors:        []string{},
	}

	var capabilities struct {
		OS     string `json:"os"`
		Checks map[string]struct {
			Status string `json:"status"`
		} `json:"checks"`
	}

	if err := c.getJSON(ctx, "/capabilities", &capabilities); err != nil {
		d.Errors = append(d.Errors, "capabilities: "+err.Error())
	} else {
		d.OS = safeToken(capabilities.OS, "unknown")

		for key, check := range capabilities.Checks {
			if checkKeyPattern.MatchString(key) && len(d.Capabilities) < 64 {
				d.Capabilities[key] = AgentCheck{Status: safeToken(check.Status, "unknown")}
			}
		}
	}

	var links struct {
		Links []AgentLink `json:"links"`
	}

	if err := c.getJSON(ctx, "/network/links", &links); err != nil {
		d.Errors = append(d.Errors, "links: "+err.Error())
	} else {
		for _, link := range links.Links {
			if len(d.Links) == maxDiscoveredLinks || !safeTokenPattern.MatchString(link.Name) {
				continue
			}

			d.Links = append(d.Links, AgentLink{
				Name:             link.Name,
				Kind:             safeToken(link.Kind, "unknown"),
				Category:         safeToken(link.Category, "unknown"),
				OperationalState: safeToken(link.OperationalState, "unknown"),
			})
		}
	}

	var namespaces struct {
		Namespaces []struct {
			Name string `json:"name"`
		} `json:"namespaces"`
	}

	if err := c.getJSON(ctx, "/network/namespaces", &namespaces); err != nil {
		d.Errors = append(d.Errors, "namespaces: "+err.Error())
	} else {
		for i, ns := range namespaces.Namespaces {
			if i == maxDiscoveredNamespaces {
				break
			}

			if labNamespaceFormat.MatchString(ns.Name) {
				d.LabNamespaces = append(d.LabNamespaces, ns.Name)
			} else {
				d.OtherNamespaces++
			}
		}

		sort.Strings(d.LabNamespaces)
	}

	return d
}

// discoveredTunnels lists WireGuard interfaces from a snapshot's discovery data.
func discoveredTunnels(status AgentStatus) []DiscoveredTunnel {
	tunnels := []DiscoveredTunnel{}

	if status.Discovery == nil {
		return tunnels
	}

	for _, link := range status.Discovery.Links {
		if link.Kind != "wireguard" {
			continue
		}

		tunnels = append(tunnels, DiscoveredTunnel{
			ID:               status.ID + ":" + link.Name,
			Name:             link.Name,
			Kind:             link.Kind,
			OperationalState: link.OperationalState,
			Managed:          false,
			Source:           "agent-discovery",
		})
	}

	return tunnels
}
