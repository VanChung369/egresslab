package main

import (
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

	name, err := session.CreateNamespace()
	if err != nil {
		return fmt.Errorf("create lab namespace: %w", err)
	}

	fmt.Printf("Created lab namespace: %s\n", name)
	fmt.Println("From another VM terminal run: sudo ip netns list")
	fmt.Println(labcli.StopCommandsHint)
	fmt.Println("Press Enter or Ctrl+C to clean up this namespace.")

	session.WaitForEnter()

	return nil
}
