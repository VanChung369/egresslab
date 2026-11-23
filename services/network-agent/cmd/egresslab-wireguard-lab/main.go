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

	wg, err := agent.NewWireGuardLab(manager, firewall)
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
		{"connect veth", func(ctx context.Context) error { return manager.ConnectLabVeth(ctx, a, b) }},
		{"setup WireGuard", func(ctx context.Context) error { return wg.Setup(ctx, a, b) }},
	}

	for _, step := range steps {
		if err := session.Step(step.title, step.run); err != nil {
			return err
		}
	}

	fmt.Printf("Namespace A: %s (ev-a=10.253.0.1, wg0=10.254.0.1)\n", a)
	fmt.Printf("Namespace B: %s (ev-b=10.253.0.2, wg0=10.254.0.2)\n", b)
	fmt.Printf("Encrypted ping: sudo ip netns exec %s ping -c 3 -W 2 10.254.0.2\n", a)
	fmt.Printf("Handshake: sudo ip netns exec %s wg show wg0 latest-handshakes\n", a)
	fmt.Println("Do not run wg showconf: it may reveal private keys.")
	fmt.Println(labcli.StopCommandsHint)
	fmt.Println("Press Enter or Ctrl+C to clean up.")

	session.WaitForEnter()

	return nil
}
