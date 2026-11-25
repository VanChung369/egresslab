package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os/exec"
	"runtime"
	"slices"
	"strings"
	"time"
)

var ErrLinuxRequired = errors.New("operation requires Linux")

type ClassifiedLink struct {
	Index            int    `json:"index"`
	Name             string `json:"name"`
	Kind             string `json:"kind"`
	Category         string `json:"category"`
	OperationalState string `json:"operational_state"`
}

type ClassifiedLinksResponse struct {
	Links []ClassifiedLink `json:"links"`
}

type ipLink struct {
	Index     int      `json:"ifindex"`
	Name      string   `json:"ifname"`
	Flags     []string `json:"flags"`
	LinkType  string   `json:"link_type"`
	OperState string   `json:"operstate"`

	LinkInfo struct {
		Kind string          `json:"info_kind"`
		Data json.RawMessage `json:"info_data"`
	} `json:"linkinfo"`
}

type linkProvider func(context.Context) ([]ClassifiedLink, error)

func discoverLinuxLinks(ctx context.Context) ([]ClassifiedLink, error) {
	if runtime.GOOS != "linux" {
		return nil, ErrLinuxRequired
	}

	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()

	output, err := exec.CommandContext(ctx, "ip", "-details", "-json", "link", "show").Output()
	if err != nil {
		return nil, fmt.Errorf("read link info with iproute2: %w", err)
	}

	return parseIPLinkJSON(output)
}

func parseIPLinkJSON(data []byte) ([]ClassifiedLink, error) {
	var raw []ipLink
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("decode ip link output: %w", err)
	}

	if raw == nil {
		return nil, errors.New("expected a JSON array of links")
	}

	result := make([]ClassifiedLink, 0, len(raw))

	for i, link := range raw {
		if link.Index <= 0 || link.Name == "" {
			return nil, fmt.Errorf("invalid link at index %d", i)
		}

		result = append(result, classifyIPLink(link))
	}

	return result, nil
}

func classifyIPLink(link ipLink) ClassifiedLink {
	kind := strings.ToLower(link.LinkInfo.Kind)
	category := "unknown"

	if kind == "tun" {
		var data struct {
			Type string `json:"type"`
		}
		if json.Unmarshal(link.LinkInfo.Data, &data) == nil &&
			strings.EqualFold(data.Type, "tap") {
			kind = "tap"
		}
	}

	if strings.EqualFold(link.LinkType, "loopback") || slices.Contains(link.Flags, "LOOPBACK") {
		kind = "loopback"
		category = "loopback"
	} else {
		switch kind {
		case "wireguard":
			category = "vpn-interface"

		case "tun", "tap", "gre", "gretap",
			"ipip", "sit", "ip6tnl", "ip6gre":
			category = "tunnel"

		case "veth", "bridge", "vlan",
			"dummy", "vxlan", "macvlan",
			"macvtap", "bond", "geneve",
			"ipvlan":
			category = "virtual"
		}
	}

	if kind == "" {
		kind = "unknown"
	}

	operState := strings.ToLower(link.OperState)
	if operState == "" {
		operState = "unknown"
	}

	return ClassifiedLink{
		Index:            link.Index,
		Name:             link.Name,
		Kind:             kind,
		Category:         category,
		OperationalState: operState,
	}
}
