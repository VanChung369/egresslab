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

	if err := session.Step("connect lab namespaces", func(ctx context.Context) error {
		return manager.ConnectLabVeth(ctx, a, b)
	}); err != nil {
		return err
	}

	fmt.Printf("Namespace A: %s (ev-a = 10.253.0.1/30)\n", a)
	fmt.Printf("Namespace B: %s (ev-b = 10.253.0.2/30)\n", b)
	fmt.Printf("Check: sudo ip -n %s route show\n", a)
	fmt.Printf("Test: sudo ip netns exec %s ping -c 3 -W 1 10.253.0.2\n", a)
	fmt.Println(labcli.StopCommandsHint)
	fmt.Println("Press Enter or Ctrl+C to delete both lab namespaces.")

	session.WaitForEnter()

	return nil
}
