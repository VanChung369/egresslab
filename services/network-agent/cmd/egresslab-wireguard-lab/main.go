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

	wg, err := agent.NewWireGuardLab(manager, firewall)
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
		return fmt.Errorf("connect veth: %w", err)
	}

	if err := wg.Setup(op, a, b); err != nil {
		return fmt.Errorf("setup WireGuard: %w", err)
	}

	fmt.Printf("Namespace A: %s (ev-a=10.253.0.1, wg0=10.254.0.1)\n", a)
	fmt.Printf("Namespace B: %s (ev-b=10.253.0.2, wg0=10.254.0.2)\n", b)
	fmt.Printf("Encrypted ping: sudo ip netns exec %s ping -c 3 -W 2 10.254.0.2\n", a)
	fmt.Printf("Handshake: sudo ip netns exec %s wg show wg0 latest-handshakes\n", a)
	fmt.Println("Do not run wg showconf: it may reveal private keys.")
	fmt.Println("Press Enter or Ctrl+C to clean up.")

	waitForEnter(ctx, bufio.NewReader(os.Stdin))

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
