package agent

import (
	"context"
	"errors"
	"net/netip"
	"strings"
	"testing"
)

const testSysctlPath = "/usr/sbin/sysctl"

// fakeNamespaceIPv6 models the IPv6 switches of each namespace, reached through
// "ip netns exec <ns> sysctl". With ignoreWrites, a write succeeds but changes nothing.
type fakeNamespaceIPv6 struct {
	values map[string]string

	writes       int
	ignoreWrites bool
	readErr      bool
	writeErr     bool
}

func (f *fakeNamespaceIPv6) set(ns, key, value string) {
	if f.values == nil {
		f.values = make(map[string]string)
	}

	f.values[ns+"|"+key] = value
}

func (f *fakeNamespaceIPv6) get(ns, key string) string {
	if value, ok := f.values[ns+"|"+key]; ok {
		return value
	}

	return "0"
}

func (f *fakeNamespaceIPv6) wrap(base netNSCommand) netNSCommand {
	return func(ctx context.Context, args ...string) ([]byte, error) {
		if len(args) < 4 || args[0] != "netns" || args[1] != "exec" || args[3] != testSysctlPath {
			return base(ctx, args...)
		}

		ns, a := args[2], args[4:]

		switch {
		case len(a) >= 3 && a[0] == "-q" && a[1] == "-w":
			f.writes++

			if f.writeErr {
				return nil, errors.New("sysctl write failed")
			}

			for _, assignment := range a[2:] {
				key, value, ok := strings.Cut(assignment, "=")
				if !ok || value != "1" || (key != ipv6DefaultKey && key != ipv6LoopbackKey && key != ipv6WireGuardKey) {
					return nil, errors.New("unexpected sysctl assignment")
				}

				if !f.ignoreWrites {
					f.set(ns, key, value)
				}
			}

			return nil, nil

		case len(a) >= 2 && a[0] == "-n":
			if f.readErr {
				return nil, errors.New("sysctl read failed")
			}

			var values []string
			for _, key := range a[1:] {
				values = append(values, f.get(ns, key))
			}

			return []byte(strings.Join(values, "\n") + "\n"), nil
		}

		return nil, errors.New("unexpected sysctl command")
	}
}

func TestSealedIPv6Isolation(t *testing.T) {
	b, kernel, _ := sealedBackendFixture(t)
	ctx := context.Background()

	ns, err := b.Create(ctx)
	if err != nil {
		t.Fatal(err)
	}

	if err := b.Seal(ctx, ns); err != nil {
		t.Fatal(err)
	}

	if kernel.ipv6.get(ns, ipv6DefaultKey) != "1" || kernel.ipv6.get(ns, ipv6LoopbackKey) != "1" {
		t.Fatal("IPv6 policy was not applied")
	}

	if err := b.Verify(ctx, ns); err != nil {
		t.Fatal(err)
	}

	writes := kernel.ipv6.writes

	for _, key := range []string{ipv6DefaultKey, ipv6LoopbackKey} {
		kernel.ipv6.set(ns, key, "0")

		if err := b.Verify(ctx, ns); !errors.Is(err, ErrIPv6Isolation) {
			t.Fatalf("%s drift accepted: %v", key, err)
		}

		kernel.ipv6.set(ns, key, "1")
	}

	if kernel.ipv6.writes != writes {
		t.Fatal("verification silently repaired drift")
	}

	// Delete never depends on IPv6 verification.
	kernel.ipv6.readErr = true

	if err := b.Delete(ctx, ns); err != nil {
		t.Fatal(err)
	}

	requireForgotten(t, b, ns)
}

func TestSealedIPv6RequiresReadback(t *testing.T) {
	for name, setup := range map[string]func(*fakeNamespaceIPv6){
		"write not applied": func(f *fakeNamespaceIPv6) { f.ignoreWrites = true },
		"write failed":      func(f *fakeNamespaceIPv6) { f.writeErr = true },
		"read failed":       func(f *fakeNamespaceIPv6) { f.readErr = true },
	} {
		t.Run(name, func(t *testing.T) {
			b, kernel, _ := sealedBackendFixture(t)
			ctx := context.Background()

			ns, err := b.Create(ctx)
			if err != nil {
				t.Fatal(err)
			}

			setup(kernel.ipv6)

			if err := b.Seal(ctx, ns); !errors.Is(err, ErrIPv6Isolation) {
				t.Fatalf("unconfirmed IPv6 isolation accepted: %v", err)
			}

			if err := b.Delete(ctx, ns); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestSealedIPv6NeverTouchesOtherNamespaces(t *testing.T) {
	b, kernel, _ := sealedBackendFixture(t)
	ctx := context.Background()

	kernel.present[sampleLabName] = true

	b.manager.mu.Lock()
	err := b.disableIPv6Locked(ctx, sampleLabName, false)
	b.manager.mu.Unlock()

	if !errors.Is(err, ErrIPv6Isolation) || kernel.ipv6.writes != 0 {
		t.Fatalf("sysctl ran in an unowned namespace: %v", err)
	}

	b.sysctlPath = ""

	ns, err := b.Create(ctx)
	if err != nil {
		t.Fatal(err)
	}

	if err := b.Seal(ctx, ns); !errors.Is(err, ErrIPv6Isolation) || kernel.ipv6.writes != 0 {
		t.Fatalf("seal without sysctl: %v", err)
	}
}

func TestManagedTunnelIPv6Isolation(t *testing.T) {
	b, kernel := newManagedTunnelFixture(t)
	ctx := context.Background()

	if err := b.connectConfig(ctx, vpnTestNS, vpnTestConfig(t)); err != nil {
		t.Fatal(err)
	}

	if kernel.ipv6.get(vpnTestNS, ipv6WireGuardKey) != "1" {
		t.Fatal("WireGuard IPv6 was not disabled")
	}

	writes := kernel.ipv6.writes

	kernel.ipv6.set(vpnTestNS, ipv6WireGuardKey, "0")

	if err := b.VerifyConfigured(ctx, vpnTestNS); !errors.Is(err, ErrIPv6Isolation) {
		t.Fatalf("IPv6 drift accepted: %v", err)
	}

	if b.active == nil || !b.active.faulted {
		t.Fatal("tunnel was not marked faulted")
	}

	if kernel.ipv6.writes != writes {
		t.Fatal("drift was silently repaired")
	}

	if err := b.CleanupStage(ctx, vpnTestNS); err != nil {
		t.Fatal(err)
	}
}

func TestManagedTunnelIPv6RejectsBeforeMutation(t *testing.T) {
	b, kernel := newManagedTunnelFixture(t)

	kernel.ipv6.set(vpnTestNS, ipv6DefaultKey, "0")

	lookups := 0
	b.lookupEndpoint = func(ctx context.Context, network, host string) ([]netip.Addr, error) {
		lookups++
		return fixedLookup("8.8.8.8")(ctx, network, host)
	}

	err := b.connectConfig(context.Background(), vpnTestNS, mustParse(t, demoConfig()))
	if !errors.Is(err, ErrIPv6Isolation) {
		t.Fatalf("unexpected error: %v", err)
	}

	requireUntouched(t, b, kernel)

	if kernel.ipv6.writes != 0 || lookups != 0 {
		t.Fatal("namespace policy modified or endpoint resolved before the IPv6 check")
	}
}

func TestManagedTunnelIPv6WriteFailureRollback(t *testing.T) {
	b, kernel := newManagedTunnelFixture(t)
	kernel.ipv6.writeErr = true

	if err := b.connectConfig(context.Background(), vpnTestNS, vpnTestConfig(t)); !errors.Is(err, ErrIPv6Isolation) {
		t.Fatalf("unexpected error: %v", err)
	}

	if kernel.peerCalls != 0 {
		t.Fatal("peer configured without IPv6 isolation")
	}

	if b.active != nil || kernel.name != "" || kernel.tableRemovals != 1 {
		t.Fatal("rollback incomplete")
	}
}

func TestManagedTunnelIPv6ReadFailure(t *testing.T) {
	b, kernel := newManagedTunnelFixture(t)
	ctx := context.Background()

	if err := b.connectConfig(ctx, vpnTestNS, vpnTestConfig(t)); err != nil {
		t.Fatal(err)
	}

	kernel.ipv6.readErr = true

	if err := b.VerifyConfigured(ctx, vpnTestNS); !errors.Is(err, ErrIPv6Isolation) {
		t.Fatalf("readback failure accepted: %v", err)
	}

	if b.active == nil || !b.active.faulted {
		t.Fatal("fault not retained")
	}
}
