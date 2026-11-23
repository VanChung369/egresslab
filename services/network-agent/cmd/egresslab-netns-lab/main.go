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

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM, syscall.SIGHUP)
	defer stop()

	createCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	name, err := manager.Create(createCtx)
	cancel()

	if err != nil {
		return err
	}

	defer func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cleanupCancel()

		if err := manager.Delete(cleanupCtx, name); err != nil {
			resultErr = errors.Join(resultErr, fmt.Errorf("cleanup %s: %w", name, err))
			return
		}

		fmt.Printf("Deleted lab namespace: %s\n", name)
	}()

	fmt.Printf("Created lab namespace: %s\n", name)
	fmt.Println("From another VM terminal run: sudo ip netns list")
	fmt.Println("Press Enter or Ctrl+C to clean up this namespace.")

	done := make(chan struct{})

	go func() {
		_, _ = bufio.NewReader(os.Stdin).ReadString('\n')
		close(done)
	}()

	select {
	case <-done:
	case <-ctx.Done():
	}

	return nil
}
