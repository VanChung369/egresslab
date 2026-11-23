package labcli

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/VanChung369/egresslab/services/network-agent/internal/agent"
)

type fakeManager struct {
	names   []string
	created int
	deletes []string
	busyFor int
	failErr error
}

func (f *fakeManager) Create(context.Context) (string, error) {
	name := f.names[f.created]
	f.created++
	return name, nil
}

func (f *fakeManager) Delete(_ context.Context, name string) error {
	f.deletes = append(f.deletes, name)

	if f.busyFor != 0 {
		if f.busyFor > 0 {
			f.busyFor--
		}
		return fmt.Errorf("namespace %s has processes: %w", name, agent.ErrNetNSBusy)
	}

	return f.failErr
}

func testSession(input io.Reader, manager namespaceManager) (*Session, context.CancelFunc, *bytes.Buffer) {
	ctx, cancel := context.WithCancel(context.Background())
	out := &bytes.Buffer{}
	session := newSession(ctx, cancel, input, out, manager)
	session.busyWait = 20 * time.Millisecond
	session.busyPoll = time.Millisecond

	return session, cancel, out
}

func TestWaitForEnterAdvancesOnlyOnNewline(t *testing.T) {
	session, _, out := testSession(strings.NewReader("\n\npartial"), &fakeManager{})

	for range 2 {
		if !session.WaitForEnter() {
			t.Fatal("newline did not advance")
		}
	}

	if session.WaitForEnter() {
		t.Fatal("input without a newline advanced")
	}

	if session.WaitForEnter() {
		t.Fatal("closed input advanced")
	}

	if !strings.Contains(out.String(), "Input closed") {
		t.Fatalf("missing input closed message: %q", out.String())
	}
}

func TestWaitForEnterStopsOnEmptyInput(t *testing.T) {
	session, _, _ := testSession(strings.NewReader(""), &fakeManager{})

	if session.WaitForEnter() {
		t.Fatal("EOF advanced to the next phase")
	}
}

func TestWaitForEnterStopsOnInterrupt(t *testing.T) {
	reader, writer := io.Pipe()
	defer writer.Close()

	session, cancel, _ := testSession(reader, &fakeManager{})

	go func() {
		time.Sleep(10 * time.Millisecond)
		cancel()
	}()

	done := make(chan bool)
	go func() { done <- session.WaitForEnter() }()

	select {
	case advanced := <-done:
		if advanced {
			t.Fatal("interrupt advanced to the next phase")
		}

	case <-time.After(time.Second):
		t.Fatal("interrupt did not stop waiting")
	}
}

func TestInterruptSkipsRemainingSteps(t *testing.T) {
	manager := &fakeManager{names: []string{"a", "b"}}
	session, cancel, _ := testSession(strings.NewReader(""), manager)

	if _, err := session.CreateNamespace(); err != nil {
		t.Fatal(err)
	}

	ran := false
	err := session.Step("first", func(context.Context) error {
		cancel()
		return nil
	})

	if !errors.Is(err, ErrInterrupted) {
		t.Fatalf("interrupt during a step was not reported: %v", err)
	}

	err = session.Step("second", func(context.Context) error {
		ran = true
		return nil
	})
	if !errors.Is(err, ErrInterrupted) {
		t.Fatalf("unexpected error: %v", err)
	}

	if _, err := session.CreateNamespace(); !errors.Is(err, ErrInterrupted) {
		t.Fatalf("unexpected error: %v", err)
	}

	if ran || manager.created != 1 {
		t.Fatal("work continued after interrupt")
	}
}

func TestStepContextSurvivesInterrupt(t *testing.T) {
	session, cancel, _ := testSession(strings.NewReader(""), &fakeManager{})

	var stepErr error
	err := session.Step("long", func(ctx context.Context) error {
		cancel()
		stepErr = ctx.Err()
		return nil
	})

	if stepErr != nil {
		t.Fatal("interrupt cancelled a running command")
	}

	if !errors.Is(err, ErrInterrupted) {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestStepWrapsErrors(t *testing.T) {
	session, _, _ := testSession(strings.NewReader(""), &fakeManager{})
	cause := errors.New("boom")

	err := session.Step("seal namespace A", func(context.Context) error { return cause })
	if !errors.Is(err, cause) || !strings.HasPrefix(err.Error(), "seal namespace A: ") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestCloseDeletesInReverseOrderAndClearsInterrupt(t *testing.T) {
	manager := &fakeManager{names: []string{"a", "b"}}
	session, cancel, out := testSession(strings.NewReader(""), manager)

	for range 2 {
		if _, err := session.CreateNamespace(); err != nil {
			t.Fatal(err)
		}
	}

	cancel()

	result := error(ErrInterrupted)
	session.Close(&result)

	if result != nil {
		t.Fatalf("interrupt reported as failure: %v", result)
	}

	if !reflect.DeepEqual(manager.deletes, []string{"b", "a"}) {
		t.Fatalf("unexpected deletes: %v", manager.deletes)
	}

	for _, want := range []string{"Interrupted; cleaning up.", "Deleted namespace: b", "Deleted namespace: a"} {
		if !strings.Contains(out.String(), want) {
			t.Fatalf("missing %q in %q", want, out.String())
		}
	}
}

func TestCloseKeepsOtherErrorsAndCleansEverything(t *testing.T) {
	manager := &fakeManager{names: []string{"a", "b"}, failErr: errors.New("delete failed")}
	session, _, _ := testSession(strings.NewReader(""), manager)

	for range 2 {
		if _, err := session.CreateNamespace(); err != nil {
			t.Fatal(err)
		}
	}

	setupErr := errors.New("setup failed")
	result := setupErr
	session.Close(&result)

	message := result.Error()
	if !errors.Is(result, setupErr) || !strings.Contains(message, "cleanup a") || !strings.Contains(message, "cleanup b") {
		t.Fatalf("unexpected result: %v", result)
	}

	if len(manager.deletes) != 2 {
		t.Fatalf("not every namespace was attempted: %v", manager.deletes)
	}
}

func TestCloseWaitsForBusyNamespace(t *testing.T) {
	manager := &fakeManager{names: []string{"a"}, busyFor: 2}
	session, _, out := testSession(strings.NewReader(""), manager)

	if _, err := session.CreateNamespace(); err != nil {
		t.Fatal(err)
	}

	var result error
	session.Close(&result)

	if result != nil {
		t.Fatalf("busy namespace was not retried: %v", result)
	}

	if len(manager.deletes) != 3 {
		t.Fatalf("unexpected delete attempts: %v", manager.deletes)
	}

	if !strings.Contains(out.String(), "Waiting up to") || !strings.Contains(out.String(), "Deleted namespace: a") {
		t.Fatalf("unexpected output: %q", out.String())
	}
}

func TestCloseGivesUpOnPersistentlyBusyNamespace(t *testing.T) {
	manager := &fakeManager{names: []string{"a"}, busyFor: -1}
	session, _, _ := testSession(strings.NewReader(""), manager)

	if _, err := session.CreateNamespace(); err != nil {
		t.Fatal(err)
	}

	var result error
	session.Close(&result)

	if !errors.Is(result, agent.ErrNetNSBusy) || !strings.Contains(result.Error(), "sudo ip netns delete a") {
		t.Fatalf("unexpected result: %v", result)
	}

	if len(manager.deletes) < 2 {
		t.Fatalf("busy namespace was not retried: %v", manager.deletes)
	}
}
