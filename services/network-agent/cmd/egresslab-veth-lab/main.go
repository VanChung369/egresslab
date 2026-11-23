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

	ctx, stop := signal.NotifyContext(
		context.Background(),
		os.Interrupt,
		syscall.SIGTERM,
		syscall.SIGHUP,
	)
	defer stop()

	cleanup := func(name string) {
		cleanupCtx, cancel := context.WithTimeout(
			context.Background(),
			5*time.Second,
		)
		defer cancel()

		if err := manager.Delete(
			cleanupCtx,
			name,
		); err != nil {
			resultErr = errors.Join(
				resultErr,
				fmt.Errorf(
					"cleanup %s: %w",
					name,
					err,
				),
			)
			return
		}

		fmt.Println("Deleted:", name)
	}

	a, err := manager.Create(ctx)
	if err != nil {
		return fmt.Errorf(
			"create namespace A: %w",
			err,
		)
	}
	defer cleanup(a)

	b, err := manager.Create(ctx)
	if err != nil {
		return fmt.Errorf(
			"create namespace B: %w",
			err,
		)
	}
	defer cleanup(b)

	if err := manager.ConnectLabVeth(
		ctx,
		a,
		b,
	); err != nil {
		return fmt.Errorf(
			"connect lab namespaces: %w",
			err,
		)
	}

	fmt.Printf(
		"Namespace A: %s (ev-a = 10.253.0.1/30)\n",
		a,
	)

	fmt.Printf(
		"Namespace B: %s (ev-b = 10.253.0.2/30)\n",
		b,
	)

	fmt.Printf(
		"Check: sudo ip -n %s route show\n",
		a,
	)

	fmt.Printf(
		"Test: sudo ip netns exec %s ping -c 3 -W 1 10.253.0.2\n",
		a,
	)

	fmt.Println(
		"Press Enter or Ctrl+C to delete both lab namespaces.",
	)

	done := make(chan struct{})

	go func() {
		_, _ = bufio.NewReader(
			os.Stdin,
		).ReadString('\n')

		close(done)
	}()

	select {
	case <-done:
	case <-ctx.Done():
	}

	return nil
}
