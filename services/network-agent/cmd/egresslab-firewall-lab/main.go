package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/VanChung369/egresslab/services/network-agent/internal/agent"
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

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM, syscall.SIGHUP)
	defer stop()

	op := context.WithoutCancel(ctx)

	cleanup := func(name string) {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		if err := manager.Delete(cleanupCtx, name); err != nil {
			resultErr = errors.Join(resultErr, fmt.Errorf("cleanup %s: %w", name, err))
			return
		}

		fmt.Println("Deleted namespace:", name)
	}

	a, err := manager.Create(op)
	if err != nil {
		return fmt.Errorf("create namespace A: %w", err)
	}
	defer cleanup(a)

	b, err := manager.Create(op)
	if err != nil {
		return fmt.Errorf("create namespace B: %w", err)
	}
	defer cleanup(b)

	if err := manager.ConnectLabVeth(op, a, b); err != nil {
		return fmt.Errorf("connect veth pair: %w", err)
	}

	if err := firewall.Seal(op, a); err != nil {
		return fmt.Errorf("seal namespace A: %w", err)
	}

	if err := firewall.Seal(op, b); err != nil {
		return fmt.Errorf("seal namespace B: %w", err)
	}

	reader := bufio.NewReader(os.Stdin)

	fmt.Printf("Namespace A: %s (ev-a = 10.253.0.1/30)\n", a)
	fmt.Printf("Namespace B: %s (ev-b = 10.253.0.2/30)\n", b)
	fmt.Println("Phase 1: SEALED. A -> B ping must fail.")
	fmt.Printf("Test: sudo ip netns exec %s ping -c 2 -W 1 10.253.0.2\n", a)
	fmt.Println("Press Enter to allow peer ICMP, or Ctrl+C to clean up.")

	if !waitForEnter(ctx, reader) {
		return nil
	}

	if err := firewall.PermitPeerICMP(op, a, agent.LabSideA); err != nil {
		return fmt.Errorf("allow peer ICMP in A: %w", err)
	}

	if err := firewall.PermitPeerICMP(op, b, agent.LabSideB); err != nil {
		return fmt.Errorf("allow peer ICMP in B: %w", err)
	}

	fmt.Println("Phase 2: ICMP allowed only between veth peers.")
	fmt.Printf("Test: sudo ip netns exec %s ping -c 2 -W 1 10.253.0.2\n", a)
	fmt.Printf("Rules: sudo ip netns exec %s nft list table inet egresslab_lab\n", a)
	fmt.Println("Press Enter or Ctrl+C to clean up.")

	waitForEnter(ctx, reader)

	return nil
}

func waitForEnter(ctx context.Context, reader *bufio.Reader) bool {
	done := make(chan struct{})

	go func() {
		if _, err := reader.ReadString('\n'); err == nil {
			close(done)
		}
	}()

	select {
	case <-done:
		return ctx.Err() == nil

	case <-ctx.Done():
		return false
	}
}
