package agent

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
)

const sampleLabName = "egresslab-lab-0123456789abcdef"

type fakeNetNS struct {
	calls     [][]string
	present   map[string]bool
	failAdd   bool
	failPids  bool
	failDel   bool
	pidsOut   string
	existsErr error
}

func newFakeNetNS() *fakeNetNS {
	return &fakeNetNS{present: map[string]bool{}}
}

func (f *fakeNetNS) run(_ context.Context, args ...string) ([]byte, error) {
	f.calls = append(f.calls, append([]string(nil), args...))
	name := args[len(args)-1]

	switch args[1] {
	case "add":
		f.present[name] = true
		if f.failAdd {
			return nil, errors.New("signal: killed")
		}

	case "pids":
		if f.failPids || !f.present[name] {
			return nil, errors.New("no such namespace")
		}
		return []byte(f.pidsOut), nil

	case "delete":
		if !f.present[name] {
			return nil, errors.New("no such namespace")
		}
		delete(f.present, name)
		if f.failDel {
			return nil, errors.New("signal: killed")
		}
	}

	return nil, nil
}

func (f *fakeNetNS) exists(name string) (bool, error) {
	if f.existsErr != nil {
		return false, f.existsErr
	}

	return f.present[name], nil
}

func (f *fakeNetNS) manager() *NetNSLabManager {
	return newNetNSLabManager(f.run, func() (string, error) { return sampleLabName, nil }, f.exists)
}

func TestNetNSLabLifecycle(t *testing.T) {
	fake := newFakeNetNS()
	manager := fake.manager()

	name, err := manager.Create(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	if name != sampleLabName {
		t.Fatalf("unexpected name: %s", name)
	}

	if err := manager.Delete(context.Background(), name); err != nil {
		t.Fatal(err)
	}

	expected := [][]string{
		{"netns", "add", sampleLabName},
		{"netns", "pids", sampleLabName},
		{"netns", "delete", sampleLabName},
	}

	if !reflect.DeepEqual(fake.calls, expected) {
		t.Fatalf("unexpected commands: %#v", fake.calls)
	}
}

func TestNetNSLabRejectsForeignDeletion(t *testing.T) {
	fake := newFakeNetNS()

	if err := fake.manager().Delete(context.Background(), sampleLabName); err == nil {
		t.Fatal("expected deletion to be refused")
	}

	if len(fake.calls) != 0 {
		t.Fatal("external command was executed")
	}
}

func TestNetNSLabRejectsMalformedDeleteName(t *testing.T) {
	fake := newFakeNetNS()

	if err := fake.manager().Delete(context.Background(), "../default"); err == nil {
		t.Fatal("expected invalid name rejection")
	}

	if len(fake.calls) != 0 {
		t.Fatal("external command was executed")
	}
}

func TestNetNSLabValidatesGeneratedName(t *testing.T) {
	fake := newFakeNetNS()
	manager := newNetNSLabManager(fake.run, func() (string, error) { return "../default", nil }, fake.exists)

	if _, err := manager.Create(context.Background()); err == nil {
		t.Fatal("expected invalid name rejection")
	}

	if len(fake.calls) != 0 {
		t.Fatal("external command was executed")
	}
}

func TestNetNSLabRejectsRunningProcesses(t *testing.T) {
	fake := newFakeNetNS()
	fake.pidsOut = "123\n"
	manager := fake.manager()

	name, err := manager.Create(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	err = manager.Delete(context.Background(), name)
	if err == nil || !strings.Contains(err.Error(), "has processes") {
		t.Fatalf("unexpected error: %v", err)
	}

	expected := [][]string{
		{"netns", "add", sampleLabName},
		{"netns", "pids", sampleLabName},
	}

	if !reflect.DeepEqual(fake.calls, expected) {
		t.Fatalf("unexpected commands: %#v", fake.calls)
	}
}

func TestNetNSLabDoesNotClaimFailedCreation(t *testing.T) {
	fake := newFakeNetNS()
	manager := newNetNSLabManager(
		func(_ context.Context, args ...string) ([]byte, error) {
			fake.calls = append(fake.calls, args)
			return nil, errors.New("operation not permitted")
		},
		func() (string, error) { return sampleLabName, nil },
		fake.exists,
	)

	if _, err := manager.Create(context.Background()); err == nil {
		t.Fatal("expected creation error")
	}

	if err := manager.Delete(context.Background(), sampleLabName); err == nil {
		t.Fatal("failed creation must not grant ownership")
	}

	if len(fake.calls) != 1 {
		t.Fatalf("unexpected commands: %#v", fake.calls)
	}
}

func TestNetNSLabLeavesUncertainNamespaceAlone(t *testing.T) {
	fake := newFakeNetNS()
	fake.failAdd = true
	manager := fake.manager()

	_, err := manager.Create(context.Background())
	if !errors.Is(err, ErrNetNSStateUncertain) {
		t.Fatalf("expected uncertain state error, got %v", err)
	}

	if !strings.Contains(err.Error(), sampleLabName) {
		t.Errorf("error does not name the namespace: %v", err)
	}

	if !fake.present[sampleLabName] {
		t.Fatal("namespace with uncertain ownership was removed")
	}

	expected := [][]string{
		{"netns", "add", sampleLabName},
	}

	if !reflect.DeepEqual(fake.calls, expected) {
		t.Fatalf("unexpected commands: %#v", fake.calls)
	}

	if err := manager.Delete(context.Background(), sampleLabName); err == nil {
		t.Fatal("namespace with uncertain ownership must not be claimed")
	}
}

func TestNetNSLabReportsUnknownStateAfterFailedCreation(t *testing.T) {
	fake := newFakeNetNS()
	fake.failAdd = true
	fake.existsErr = errors.New("permission denied")
	manager := fake.manager()

	_, err := manager.Create(context.Background())
	if !errors.Is(err, ErrNetNSStateUncertain) || !strings.Contains(err.Error(), "permission denied") {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(fake.calls) != 1 {
		t.Fatalf("unexpected commands: %#v", fake.calls)
	}

	if err := manager.Delete(context.Background(), sampleLabName); err == nil {
		t.Fatal("namespace with uncertain ownership must not be claimed")
	}
}

func TestNetNSLabRetainsOwnershipOnDeleteFailure(t *testing.T) {
	fake := newFakeNetNS()
	manager := fake.manager()

	name, err := manager.Create(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	fake.failPids = true

	if err := manager.Delete(context.Background(), name); err == nil {
		t.Fatal("expected deletion error")
	}

	fake.failPids = false

	if err := manager.Delete(context.Background(), name); err != nil {
		t.Fatal(err)
	}
}

func TestNetNSLabForgetsNamespaceDeletedDespiteError(t *testing.T) {
	fake := newFakeNetNS()
	fake.failDel = true
	manager := fake.manager()

	name, err := manager.Create(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	if err := manager.Delete(context.Background(), name); err != nil {
		t.Fatalf("namespace is gone, delete should succeed: %v", err)
	}

	if err := manager.Delete(context.Background(), name); err == nil {
		t.Fatal("deleted namespace must not stay owned")
	}
}

func TestNetNSLabForgetsNamespaceRemovedExternally(t *testing.T) {
	fake := newFakeNetNS()
	manager := fake.manager()

	name, err := manager.Create(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	delete(fake.present, name)

	if err := manager.Delete(context.Background(), name); err != nil {
		t.Fatalf("namespace is gone, delete should succeed: %v", err)
	}
}
