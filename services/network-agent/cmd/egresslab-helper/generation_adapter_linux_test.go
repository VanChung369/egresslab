//go:build linux

package main

import (
	"net/netip"
	"testing"
	"time"

	"github.com/VanChung369/egresslab/services/network-agent/internal/agent"
)

// V1 evidence must never carry the generation: the V1 validator and the controller's strict decoder
// both refuse it.
func TestAdaptMultiProbeObservation(t *testing.T) {
	now := time.Now().UTC()
	ip := netip.MustParseAddr("8.8.4.4")
	result := agent.ManagedMultiProbeObservation{
		TunnelGeneration: "tunnelgen_0123456789abcdef0123456789abcdef",
		IPv4:             ip,
		StartedAt:        now,
		FinishedAt:       now,
		ObservedAt:       now,
		HandshakeAt:      now,
		Sources: []agent.ManagedProbeSourceObservation{
			{Source: "cloudflare_trace", DestinationIPv4: netip.MustParseAddr("1.1.1.1"), IPv4: ip, ObservedAt: now},
			{Source: "ident_me", DestinationIPv4: netip.MustParseAddr("9.9.9.9"), IPv4: ip, ObservedAt: now},
		},
	}

	v1, err := adaptMultiProbeObservation(result, false)
	if err != nil || v1.TunnelGeneration != "" || v1.IPv4 != ip || len(v1.Sources) != 2 ||
		v1.Sources[1].DestinationIPv4 != result.Sources[1].DestinationIPv4 {
		t.Fatalf("V1 adaptation: %+v %v", v1, err)
	}

	v2, err := adaptMultiProbeObservation(result, true)
	if err != nil || v2.TunnelGeneration != result.TunnelGeneration {
		t.Fatalf("V2 adaptation: %+v %v", v2, err)
	}

	result.NetworkReady = true
	if _, err := adaptMultiProbeObservation(result, true); err == nil {
		t.Fatal("an observation that activates networking was adapted")
	}
}
