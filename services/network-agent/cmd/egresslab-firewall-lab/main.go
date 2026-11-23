package main

import (
	"context"
	"fmt"
	"log"

	"github.com/VanChung369/egresslab/services/network-agent/internal/agent"
	"github.com/VanChung369/egresslab/services/network-agent/internal/labcli"
)

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func run() (resultErr error) {
	manager, err := agent.NewNetNSLabManager()
	if err != nil {
		return err
	}

	firewall, err := agent.NewLabFirewall(manager)
	if err != nil {
		return err
	}

	session := labcli.Start(manager)
	defer session.Close(&resultErr)

	a, err := session.CreateNamespace()
	if err != nil {
		return fmt.Errorf("create namespace A: %w", err)
	}

	b, err := session.CreateNamespace()
	if err != nil {
		return fmt.Errorf("create namespace B: %w", err)
	}

	steps := []struct {
		title string
		run   func(context.Context) error
	}{
		{"seal namespace A", func(ctx context.Context) error { return firewall.Seal(ctx, a) }},
		{"seal namespace B", func(ctx context.Context) error { return firewall.Seal(ctx, b) }},
		{"connect veth pair", func(ctx context.Context) error { return manager.ConnectLabVeth(ctx, a, b) }},
	}

	for _, step := range steps {
		if err := session.Step(step.title, step.run); err != nil {
			return err
		}
	}

	fmt.Printf("Namespace A: %s (ev-a = 10.253.0.1/30)\n", a)
	fmt.Printf("Namespace B: %s (ev-b = 10.253.0.2/30)\n", b)
	fmt.Println("Phase 1: SEALED. A -> B ping must fail.")
	fmt.Printf("Test: sudo ip netns exec %s ping -c 2 -W 1 10.253.0.2\n", a)
	fmt.Println(labcli.StopCommandsHint)
	fmt.Println("Press Enter to allow peer ICMP, or Ctrl+C to clean up.")

	if !session.WaitForEnter() {
		return nil
	}

	if err := session.Step("allow peer ICMP in A", func(ctx context.Context) error {
		return firewall.PermitPeerICMP(ctx, a, agent.LabSideA)
	}); err != nil {
		return err
	}

	if err := session.Step("allow peer ICMP in B", func(ctx context.Context) error {
		return firewall.PermitPeerICMP(ctx, b, agent.LabSideB)
	}); err != nil {
		return err
	}

	fmt.Println("Phase 2: ICMP allowed only between veth peers.")
	fmt.Printf("Test: sudo ip netns exec %s ping -c 2 -W 1 10.253.0.2\n", a)
	fmt.Printf("Rules: sudo ip netns exec %s nft list table inet egresslab_lab\n", a)
	fmt.Println(labcli.StopCommandsHint)
	fmt.Println("Press Enter or Ctrl+C to clean up.")

	session.WaitForEnter()

	return nil
}
