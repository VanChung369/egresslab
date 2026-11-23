package agent

import (
	"context"
	"errors"
	"fmt"
)

func (f *LabFirewall) PermitWireGuardLab(ctx context.Context, name string, side LabSide) error {
	if !labNamePattern.MatchString(name) {
		return errors.New("invalid lab namespace name")
	}

	script, err := wireGuardLabRules(side)
	if err != nil {
		return err
	}

	f.manager.mu.Lock()
	defer f.manager.mu.Unlock()

	return f.applyVerifiedLocked(ctx, name, script)
}

func wireGuardLabRules(side LabSide) (string, error) {
	var iface, transportLocal, transportPeer, tunnelLocal, tunnelPeer string
	var localPort, peerPort int

	switch side {
	case LabSideA:
		iface = labVethA
		transportLocal, transportPeer = labHost(labAddressA), labHost(labAddressB)
		tunnelLocal, tunnelPeer = labHost(labWGAddressA), labHost(labWGAddressB)
		localPort, peerPort = labWGPortA, labWGPortB

	case LabSideB:
		iface = labVethB
		transportLocal, transportPeer = labHost(labAddressB), labHost(labAddressA)
		tunnelLocal, tunnelPeer = labHost(labWGAddressB), labHost(labWGAddressA)
		localPort, peerPort = labWGPortB, labWGPortA

	default:
		return "", errors.New("invalid lab side")
	}

	udpIn := fmt.Sprintf("udp sport %d udp dport %d accept", peerPort, localPort)
	udpOut := fmt.Sprintf("udp sport %d udp dport %d accept", localPort, peerPort)
	icmp := "icmp type { echo-request, echo-reply } accept"

	return labRule("input", iface, transportPeer, transportLocal, udpIn) +
		labRule("output", iface, transportLocal, transportPeer, udpOut) +
		labRule("input", labWGInterface, tunnelPeer, tunnelLocal, icmp) +
		labRule("output", labWGInterface, tunnelLocal, tunnelPeer, icmp), nil
}

func labRule(chain, iface, saddr, daddr, match string) string {
	direction := "iifname"
	if chain == "output" {
		direction = "oifname"
	}

	return fmt.Sprintf("add rule inet %s %s %s %q ip saddr %s ip daddr %s %s\n",
		labNFTTable, chain, direction, iface, saddr, daddr, match)
}
