package agent

import (
	"context"
	"errors"
	"fmt"
	"testing"
)

func TestValidateLoopbackOnly(t *testing.T) {
	tests := []struct {
		name string
		json string
		ok   bool
	}{
		{"valid loopback", `[{"ifname":"lo","ifindex":1,"link_type":"loopback"}]`, true},
		{"unexpected WireGuard interface", `[
			{"ifname":"lo","ifindex":1,"link_type":"loopback"},
			{"ifname":"wg0","ifindex":2,"link_type":"none"}]`, false},
		{"unexpected ethernet", `[
			{"ifname":"lo","ifindex":1,"link_type":"loopback"},
			{"ifname":"eth0","ifindex":2,"link_type":"ether"}]`, false},
		{"fake loopback", `[{"ifname":"lo","ifindex":1,"link_type":"ether"}]`, false},
		{"renamed loopback", `[{"ifname":"wg0","ifindex":1,"link_type":"loopback"}]`, false},
		{"missing index", `[{"ifname":"lo","link_type":"loopback"}]`, false},
		{"empty", `[]`, false},
		{"invalid JSON", `broken`, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateLoopbackOnly([]byte(tt.json))

			if tt.ok {
				if err != nil {
					t.Fatal(err)
				}

				return
			}

			if !errors.Is(err, ErrLabNotLoopbackOnly) {
				t.Fatalf("unsafe topology accepted: %v", err)
			}
		})
	}
}

const loopbackOnlyLinks = `[{"ifname":"lo","ifindex":1,"link_type":"loopback"}]`

// fakeSealedKernel models "ip netns add|pids|delete" and "ip -n <ns> ... link show".
type fakeSealedKernel struct {
	present map[string]bool
	links   map[string]string // namespace -> link listing; loopback only when unset
	calls   [][]string
	next    int
	ipv6    *fakeNamespaceIPv6
}

func (k *fakeSealedKernel) run(_ context.Context, args ...string) ([]byte, error) {
	k.calls = append(k.calls, append([]string(nil), args...))

	if args[0] == "-n" {
		if !k.present[args[1]] {
			return nil, errors.New("Cannot open network namespace: No such file or directory")
		}

		if links, ok := k.links[args[1]]; ok {
			return []byte(links), nil
		}

		return []byte(loopbackOnlyLinks), nil
	}

	name := args[len(args)-1]

	switch args[1] {
	case "add":
		k.present[name] = true

	case "pids":
		if !k.present[name] {
			return nil, errors.New("no such namespace")
		}

	case "delete":
		if !k.present[name] {
			return nil, errors.New("no such namespace")
		}

		delete(k.present, name)
	}

	return nil, nil
}

func (k *fakeSealedKernel) ran(verb string) int {
	count := 0

	for _, call := range k.calls {
		if len(call) > 1 && call[0] == "netns" && call[1] == verb {
			count++
		}
	}

	return count
}

func sealedBackendFixture(t *testing.T) (*SealedLabBackend, *fakeSealedKernel, *fakeKernel) {
	t.Helper()

	kernel := &fakeSealedKernel{present: map[string]bool{}, links: map[string]string{}, ipv6: &fakeNamespaceIPv6{}}
	names := func() (string, error) {
		kernel.next++
		return fmt.Sprintf("egresslab-lab-%016x", kernel.next), nil
	}

	manager := newNetNSLabManager(kernel.ipv6.wrap(kernel.run), names, func(name string) (bool, error) {
		return kernel.present[name], nil
	})

	nft := &fakeKernel{t: t}

	return &SealedLabBackend{
		manager:    manager,
		firewall:   newVerifyingLabFirewall(manager, nft.run, nft.list),
		sysctlPath: testSysctlPath,
	}, kernel, nft
}

func requireForgotten(t *testing.T, b *SealedLabBackend, name string) {
	t.Helper()

	_, owned := b.manager.owned[name]
	_, applied := b.firewall.applied[name]
	_, baseline := b.firewall.baseline[name]

	if owned || b.firewall.sealed[name] || applied || baseline || b.firewall.drifted[name] {
		t.Fatalf("%s still tracked after deletion", name)
	}
}

func TestSealedLabBackendLifecycle(t *testing.T) {
	b, kernel, nft := sealedBackendFixture(t)
	ctx := context.Background()

	name, err := b.Create(ctx)
	if err != nil {
		t.Fatal(err)
	}

	if err := b.Seal(ctx, name); err != nil {
		t.Fatal(err)
	}

	if len(nft.applied) != 1 || nft.applied[0] != sealLabRules {
		t.Fatalf("unexpected firewall scripts: %q", nft.applied)
	}

	if err := b.Verify(ctx, name); err != nil {
		t.Fatal(err)
	}

	nft.ruleset = withObject(t, nft.ruleset, extraICMPRule)
	if err := b.Verify(ctx, name); !errors.Is(err, ErrFirewallDrift) {
		t.Fatalf("drift not reported: %v", err)
	}

	if len(nft.applied) != 1 {
		t.Fatal("Verify changed the firewall")
	}

	if err := b.Delete(ctx, name); err != nil {
		t.Fatal(err)
	}

	if kernel.present[name] || kernel.ran("delete") != 1 {
		t.Fatal("namespace not deleted")
	}

	requireForgotten(t, b, name)
}

func TestSealedLabBackendRefusesExtraLinks(t *testing.T) {
	b, kernel, nft := sealedBackendFixture(t)
	ctx := context.Background()

	name, err := b.Create(ctx)
	if err != nil {
		t.Fatal(err)
	}

	extra := `[{"ifname":"lo","ifindex":1,"link_type":"loopback"},{"ifname":"ev-a","ifindex":2,"link_type":"ether"}]`

	kernel.links[name] = extra
	if err := b.Seal(ctx, name); !errors.Is(err, ErrLabNotLoopbackOnly) {
		t.Fatalf("seal with an extra link: %v", err)
	}

	if len(nft.applied) != 0 {
		t.Fatal("firewall applied to a namespace with an extra link")
	}

	delete(kernel.links, name)
	if err := b.Seal(ctx, name); err != nil {
		t.Fatal(err)
	}

	kernel.links[name] = extra
	if err := b.Verify(ctx, name); !errors.Is(err, ErrLabNotLoopbackOnly) {
		t.Fatalf("verify with an extra link: %v", err)
	}

	if err := b.Delete(ctx, name); !errors.Is(err, ErrLabNotLoopbackOnly) {
		t.Fatalf("delete with an extra link: %v", err)
	}

	if kernel.ran("delete") != 0 || !kernel.present[name] {
		t.Fatal("namespace with an extra link was deleted")
	}

	if _, owned := b.manager.owned[name]; !owned {
		t.Fatal("refused namespace was forgotten")
	}

	delete(kernel.links, name)
	if err := b.Delete(ctx, name); err != nil {
		t.Fatal(err)
	}

	requireForgotten(t, b, name)
}

func TestSealedLabBackendRefusesUnownedNamespace(t *testing.T) {
	b, kernel, nft := sealedBackendFixture(t)
	ctx := context.Background()

	kernel.present[sampleLabName] = true

	for what, err := range map[string]error{
		"seal":   b.Seal(ctx, sampleLabName),
		"verify": b.Verify(ctx, sampleLabName),
		"delete": b.Delete(ctx, sampleLabName),
	} {
		if err == nil {
			t.Fatalf("%s of an unowned namespace accepted", what)
		}
	}

	if len(kernel.calls) != 0 || len(nft.applied) != 0 || !kernel.present[sampleLabName] {
		t.Fatal("unowned namespace reached the kernel")
	}

	if err := b.Seal(ctx, "../default"); err == nil {
		t.Fatal("invalid name accepted")
	}
}

func TestSealedLabBackendForgetsVanishedNamespace(t *testing.T) {
	b, kernel, _ := sealedBackendFixture(t)
	ctx := context.Background()

	name, err := b.Create(ctx)
	if err != nil {
		t.Fatal(err)
	}

	if err := b.Seal(ctx, name); err != nil {
		t.Fatal(err)
	}

	delete(kernel.present, name)

	if err := b.Verify(ctx, name); !errors.Is(err, ErrLabNotLoopbackOnly) {
		t.Fatalf("verify of a vanished namespace: %v", err)
	}

	if err := b.Delete(ctx, name); err != nil {
		t.Fatalf("vanished namespace cannot be released: %v", err)
	}

	if kernel.ran("delete") != 0 {
		t.Fatal("deleted a namespace that does not exist")
	}

	requireForgotten(t, b, name)
}
