package agent

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"testing"
)

func TestConnectLabVethCommandSequence(t *testing.T) {
	ctx := context.Background()

	a := "egresslab-lab-0000000000000001"
	b := "egresslab-lab-0000000000000002"

	var calls [][]string
	nextName := 0
	names := []string{a, b}

	manager := newNetNSLabManager(
		func(
			_ context.Context,
			args ...string,
		) ([]byte, error) {
			calls = append(
				calls,
				append([]string(nil), args...),
			)
			return nil, nil
		},
		func() (string, error) {
			name := names[nextName]
			nextName++
			return name, nil
		},
		func(string) (bool, error) {
			return false, nil
		},
	)

	first, err := manager.Create(ctx)
	if err != nil {
		t.Fatal(err)
	}

	second, err := manager.Create(ctx)
	if err != nil {
		t.Fatal(err)
	}

	if err := manager.ConnectLabVeth(
		ctx,
		first,
		second,
	); err != nil {
		t.Fatal(err)
	}

	expected := [][]string{
		{"netns", "add", a},
		{"netns", "add", b},

		{
			"link", "add",
			"ev-a", "netns", a,
			"type", "veth",
			"peer", "name", "ev-b", "netns", b,
		},

		{
			"-n", a, "addr", "add",
			"10.253.0.1/30", "dev", "ev-a",
		},

		{
			"-n", b, "addr", "add",
			"10.253.0.2/30", "dev", "ev-b",
		},

		{"-n", a, "link", "set", "lo", "up"},
		{"-n", b, "link", "set", "lo", "up"},

		{"-n", a, "link", "set", "ev-a", "up"},
		{"-n", b, "link", "set", "ev-b", "up"},
	}

	if !reflect.DeepEqual(calls, expected) {
		t.Fatalf(
			"unexpected command sequence:\n%#v",
			calls,
		)
	}
}

func TestConnectLabVethRejectsForeignNamespace(t *testing.T) {
	calls := 0

	manager := newNetNSLabManager(
		func(
			context.Context,
			...string,
		) ([]byte, error) {
			calls++
			return nil, nil
		},
		nil,
		nil,
	)

	err := manager.ConnectLabVeth(
		context.Background(),
		"egresslab-lab-0000000000000001",
		"egresslab-lab-0000000000000002",
	)

	if err == nil {
		t.Fatal("expected ownership rejection")
	}

	if calls != 0 {
		t.Fatal("unexpected network command")
	}
}

func TestConnectLabVethRejectsSameNamespace(t *testing.T) {
	manager := newNetNSLabManager(
		nil,
		nil,
		nil,
	)

	name := "egresslab-lab-0000000000000001"

	if err := manager.ConnectLabVeth(
		context.Background(),
		name,
		name,
	); err == nil {
		t.Fatal("expected duplicate namespace rejection")
	}
}

func TestConnectLabVethStopsOnFailure(t *testing.T) {
	ctx := context.Background()

	a := "egresslab-lab-0000000000000001"
	b := "egresslab-lab-0000000000000002"

	names := []string{a, b}
	nextName := 0
	commandCount := 0

	manager := newNetNSLabManager(
		func(
			_ context.Context,
			args ...string,
		) ([]byte, error) {
			commandCount++

			// Fail the first address configuration.
			if commandCount == 4 {
				return nil, errors.New("simulated failure")
			}

			return nil, nil
		},
		func() (string, error) {
			if nextName >= len(names) {
				return "", fmt.Errorf("no more names")
			}

			name := names[nextName]
			nextName++
			return name, nil
		},
		func(string) (bool, error) {
			return false, nil
		},
	)

	first, err := manager.Create(ctx)
	if err != nil {
		t.Fatal(err)
	}

	second, err := manager.Create(ctx)
	if err != nil {
		t.Fatal(err)
	}

	if err := manager.ConnectLabVeth(
		ctx,
		first,
		second,
	); err == nil {
		t.Fatal("expected setup failure")
	}

	// Two namespace creations,
	// one veth creation,
	// one failed address assignment.
	if commandCount != 4 {
		t.Fatalf(
			"unexpected command count: %d",
			commandCount,
		)
	}
}
