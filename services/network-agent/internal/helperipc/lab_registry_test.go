package helperipc

import (
	"context"
	"errors"
	"fmt"
	"testing"
)

// peek reads a lab for a test's assertions; absent is the zero LabInfo.
func (r *labRegistry) peek(profileID string) LabInfo {
	lab, _ := r.get(profileID)
	return lab
}

// Another operation's labs are never listed before they settle; a settled holder of the lifecycle
// lock leaves the registry readable.
func TestLabRegistrySnapshot(t *testing.T) {
	labs, _, v, mint := newLifecycleFixture(t)
	ctx := context.Background()

	stop := make(chan struct{})
	done := make(chan error, 1)

	go func() {
		for {
			select {
			case <-stop:
				done <- nil
				return
			default:
			}

			items, err := labs.snapshot()
			if errors.Is(err, errLabBusy) {
				continue
			}

			if err != nil || len(items) > 1 || (len(items) == 1 && items[0].State != LabSealed) {
				done <- fmt.Errorf("snapshot during operations: %+v %v", items, err)
				return
			}
		}
	}()

	stopped := false
	stopReader := func() error {
		if stopped {
			return nil
		}

		stopped = true
		close(stop)

		return <-done
	}
	t.Cleanup(func() { _ = stopReader() })

	// The reader's own brief holds make an operation busy; a busy refusal consumes nothing.
	execute := func(req Request) (LabInfo, error) {
		for {
			lab, err := labs.execute(ctx, req, v)
			if !errors.Is(err, errLabBusy) {
				return lab, err
			}
		}
	}

	for range 50 {
		lab, err := execute(mint(lifecycleProfile))
		if err != nil {
			t.Fatal(err)
		}

		if _, err := execute(existingLabRequest(OpDeleteLab, lab)); err != nil {
			t.Fatal(err)
		}
	}

	if err := stopReader(); err != nil {
		t.Fatal(err)
	}

	lab, err := labs.execute(ctx, mint(lifecycleProfile), v)
	if err != nil {
		t.Fatal(err)
	}

	labs.mu.Lock()
	_, busyErr := labs.snapshot()
	labs.labs.settle(true)
	items, err := labs.snapshot()
	labs.labs.settle(false)
	labs.mu.Unlock()

	if !errors.Is(busyErr, errLabBusy) {
		t.Fatalf("snapshot during another operation: %v", busyErr)
	}

	if err != nil || len(items) != 1 || items[0] != lab {
		t.Fatalf("snapshot during a settled hold: %+v %v", items, err)
	}

	// A settled holder may still fault a lab while the registry is read.
	labs.mu.Lock()
	labs.labs.settle(true)

	reads := make(chan error, 1)

	go func() {
		for range 1000 {
			if _, err := labs.snapshot(); err != nil {
				reads <- err
				return
			}
		}

		reads <- nil
	}()

	faulted := lab
	faulted.State = LabFaulted

	for range 1000 {
		labs.labs.set(lab.ProfileID, faulted)
	}

	readErr := <-reads

	labs.labs.settle(false)
	labs.mu.Unlock()

	if readErr != nil {
		t.Fatalf("snapshot while a lab is faulted: %v", readErr)
	}

	_ = labs.Close()

	if _, err := labs.snapshot(); !errors.Is(err, errLabUnavailable) {
		t.Fatalf("snapshot after close: %v", err)
	}
}
