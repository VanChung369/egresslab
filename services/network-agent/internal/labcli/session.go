package labcli

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/VanChung369/egresslab/services/network-agent/internal/agent"
)

const StopCommandsHint = "Stop any commands you started inside the lab namespaces before cleaning up."

var ErrInterrupted = errors.New("lab interrupted")

const cleanupTimeout = 5 * time.Second

type namespaceManager interface {
	Create(ctx context.Context) (string, error)
	Delete(ctx context.Context, name string) error
}

type Session struct {
	ctx      context.Context
	stop     context.CancelFunc
	input    *bufio.Reader
	lines    chan error
	reading  sync.Once
	out      io.Writer
	manager  namespaceManager
	created  []string
	cleanups []cleanup
	busyWait time.Duration
	busyPoll time.Duration
}

type cleanup struct {
	title string
	run   func(context.Context) error
}

func Start(manager namespaceManager) *Session {
	signal.Notify(make(chan os.Signal, 1), syscall.SIGPIPE)
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM, syscall.SIGHUP)

	return newSession(ctx, stop, os.Stdin, os.Stdout, manager)
}

func newSession(
	ctx context.Context,
	stop context.CancelFunc,
	input io.Reader,
	out io.Writer,
	manager namespaceManager,
) *Session {
	return &Session{
		ctx:      ctx,
		stop:     stop,
		input:    bufio.NewReader(input),
		lines:    make(chan error, 1),
		out:      out,
		manager:  manager,
		busyWait: 10 * time.Second,
		busyPoll: 500 * time.Millisecond,
	}
}

func (s *Session) Err() error {
	if s.ctx.Err() != nil {
		return ErrInterrupted
	}

	return nil
}

func (s *Session) CreateNamespace() (string, error) {
	if err := s.Err(); err != nil {
		return "", err
	}

	name, err := s.manager.Create(context.WithoutCancel(s.ctx))
	if err != nil {
		return "", err
	}

	s.created = append(s.created, name)

	return name, s.Err()
}

// OnCleanup registers teardown that runs (last registered first) before namespaces are deleted.
// A cleanup that fails is retried once after the namespaces are gone, because deleting a namespace
// can remove what blocked it (for example the tunnel link inside it).
func (s *Session) OnCleanup(title string, run func(context.Context) error) {
	s.cleanups = append(s.cleanups, cleanup{title: title, run: run})
}

func (s *Session) runCleanups(pending []cleanup) []cleanup {
	var failed []cleanup

	for i := len(pending) - 1; i >= 0; i-- {
		ctx, cancel := context.WithTimeout(context.Background(), cleanupTimeout)
		err := pending[i].run(ctx)
		cancel()

		if err != nil {
			failed = append([]cleanup{pending[i]}, failed...)
			continue
		}

		fmt.Fprintln(s.out, "Cleaned up:", pending[i].title)
	}

	return failed
}

func (s *Session) Step(title string, run func(context.Context) error) error {
	if err := s.Err(); err != nil {
		return err
	}

	if err := run(context.WithoutCancel(s.ctx)); err != nil {
		return fmt.Errorf("%s: %w", title, err)
	}

	return s.Err()
}

func (s *Session) WaitForEnter() bool {
	s.reading.Do(func() { go s.readLines() })

	select {
	case err, open := <-s.lines:
		if !open {
			return false
		}

		if err != nil {
			fmt.Fprintln(s.out, "Input closed; cleaning up.")
			return false
		}

		return s.Err() == nil

	case <-s.ctx.Done():
		return false
	}
}

func (s *Session) readLines() {
	for {
		_, err := s.input.ReadString('\n')
		s.lines <- err

		if err != nil {
			close(s.lines)
			return
		}
	}
}

func (s *Session) Close(result *error) {
	if errors.Is(*result, ErrInterrupted) {
		*result = nil
	}

	if s.ctx.Err() != nil {
		fmt.Fprintln(s.out, "Interrupted; cleaning up.")
	}

	failed := s.runCleanups(s.cleanups)

	for i := len(s.created) - 1; i >= 0; i-- {
		name := s.created[i]

		if err := s.deleteNamespace(name); err != nil {
			*result = errors.Join(*result, fmt.Errorf("cleanup %s: %w", name, err))
			continue
		}

		fmt.Fprintln(s.out, "Deleted namespace:", name)
	}

	for _, c := range failed {
		ctx, cancel := context.WithTimeout(context.Background(), cleanupTimeout)
		err := c.run(ctx)
		cancel()

		if err != nil {
			*result = errors.Join(*result, fmt.Errorf("cleanup %s: %w", c.title, err))
			continue
		}

		fmt.Fprintln(s.out, "Cleaned up:", c.title)
	}

	s.stop()
}

func (s *Session) deleteNamespace(name string) error {
	deadline := time.Now().Add(s.busyWait)
	waiting := false

	for {
		ctx, cancel := context.WithTimeout(context.Background(), cleanupTimeout)
		err := s.manager.Delete(ctx, name)
		cancel()

		if !errors.Is(err, agent.ErrNetNSBusy) {
			return err
		}

		if !time.Now().Before(deadline) {
			return fmt.Errorf("%w; stop them, then run: sudo ip netns delete %s", err, name)
		}

		if !waiting {
			fmt.Fprintf(s.out, "Waiting up to %s for processes in %s to exit...\n", s.busyWait, name)
			waiting = true
		}

		time.Sleep(s.busyPoll)
	}
}
