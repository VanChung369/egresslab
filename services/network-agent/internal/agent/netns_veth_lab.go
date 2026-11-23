package agent

import (
	"context"
	"errors"
	"fmt"
)

const (
	labVethA = "ev-a"
	labVethB = "ev-b"

	labAddressA = "10.253.0.1/30"
	labAddressB = "10.253.0.2/30"
)

func (m *NetNSLabManager) ConnectLabVeth(
	ctx context.Context,
	a string,
	b string,
) error {

	if a == b ||
		!labNamePattern.MatchString(a) ||
		!labNamePattern.MatchString(b) {

		return errors.New(
			"two distinct valid lab namespace names are required",
		)
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	// Both namespaces must belong to this lab session.
	if _, ok := m.owned[a]; !ok {
		return fmt.Errorf(
			"namespace %s is not owned by this lab session",
			a,
		)
	}

	if _, ok := m.owned[b]; !ok {
		return fmt.Errorf(
			"namespace %s is not owned by this lab session",
			b,
		)
	}

	commands := [][]string{

		{
			"link", "add",
			labVethA, "netns", a,
			"type", "veth",
			"peer", "name", labVethB, "netns", b,
		},

		{
			"-n", a,
			"addr", "add",
			labAddressA,
			"dev", labVethA,
		},

		{
			"-n", b,
			"addr", "add",
			labAddressB,
			"dev", labVethB,
		},

		{
			"-n", a,
			"link", "set", "lo", "up",
		},

		{
			"-n", b,
			"link", "set", "lo", "up",
		},

		{
			"-n", a,
			"link", "set", labVethA, "up",
		},

		{
			"-n", b,
			"link", "set", labVethB, "up",
		},
	}

	for i, args := range commands {

		commandCtx, cancel := context.WithTimeout(
			ctx,
			netNSCommandTimeout,
		)

		_, err := m.run(
			commandCtx,
			args...,
		)

		cancel()

		if err != nil {
			return fmt.Errorf(
				"configure lab veth step %d/%d: %w",
				i+1,
				len(commands),
				err,
			)
		}
	}

	return nil
}
