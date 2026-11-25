package agent

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

// managedTestKernel models one tunnel link moving from the root namespace into the lab namespace.
type managedTestKernel struct {
	name      string
	alias     string
	namespace string

	failAdd      bool
	failRename   bool
	failDelete   bool
	failUnderlay bool
	wrongMark    bool

	outsideExtra []managedLink
	insideExtra  []managedLink

	mutations     int
	peerCalls     int
	tableCreates  int
	tableRemovals int

	peerInstalled bool
	wgReadError   string            // a "wg show" property that fails to read
	wgOverrides   map[string]string // "wg show" property -> value the kernel reports instead

	mtu              string            // set by "link set wg0 mtu"; empty means the WireGuard default
	networkReadError string            // an "ip -4 -json" readback that fails
	networkOverrides map[string]string // "ip -4 -json" readback -> value the kernel reports instead
}

func newManagedTunnelFixture(t *testing.T) (*ManagedTunnelBackend, *managedTestKernel) {
	t.Helper()

	vpn, _ := testVPNLab(true)
	kernel := &managedTestKernel{wgOverrides: make(map[string]string), networkOverrides: make(map[string]string)}

	sealed := &SealedLabBackend{manager: vpn.manager, firewall: vpn.firewall}
	backend := &ManagedTunnelBackend{sealed: sealed, vpn: vpn}

	firewallData := encodeRuleset(t, sealedRulesetFixture(t))

	baseline, err := labRulesetFingerprint(firewallData)
	if err != nil {
		t.Fatal(err)
	}

	vpn.firewall.baseline[vpnTestNS] = baseline
	vpn.firewall.list = func(context.Context, string) ([]byte, error) {
		return firewallData, nil
	}

	vpn.rootNFT.list = func(context.Context, string) ([]byte, error) {
		return underlayListing(t, "198.51.100.7:51820", 0xabcd, "accept"), nil
	}

	vpn.rootNFT.run = func(_ context.Context, script string, checkOnly bool) error {
		switch {
		case strings.HasPrefix(script, "create table"):
			if kernel.failUnderlay {
				return errors.New("nft failed")
			}

			if !checkOnly {
				kernel.tableCreates++
			}

		case strings.HasPrefix(script, "delete table") && !checkOnly:
			if kernel.name != "" {
				t.Fatal("underlay removed before the tunnel link")
			}

			kernel.tableRemovals++
		}

		return nil
	}

	// demoConfig: private key demoKey(1), peer demoKey(2), keepalive 25. demoKey(3) stands for the
	// public key wg derives from demoKey(1).
	vpn.runWG = func(_ context.Context, namespace string, stdin []byte, args ...string) (string, error) {
		if len(args) == 1 && args[0] == "pubkey" {
			if namespace != "" || string(stdin) != demoKey(1) {
				return "", errors.New("invalid public key derivation")
			}

			return demoKey(3), nil
		}

		if len(args) == 3 && args[0] == "show" && args[1] == labWGInterface {
			property := args[2]

			if property == kernel.wgReadError {
				return "", errors.New("kernel readback failed")
			}

			if value, exists := kernel.wgOverrides[property]; exists {
				return value, nil
			}

			switch property {
			case "fwmark":
				if kernel.wrongMark {
					return "off", nil
				}
				return "0xabcd", nil
			case "public-key":
				return demoKey(3), nil
			case "peers":
				if !kernel.peerInstalled {
					return "", nil
				}
				return demoKey(2), nil
			case "endpoints":
				return demoKey(2) + "\t198.51.100.7:51820", nil
			case "allowed-ips":
				return demoKey(2) + "\t0.0.0.0/0", nil
			case "persistent-keepalive":
				return demoKey(2) + "\t25", nil
			default:
				return "", errors.New("unexpected WireGuard readback property")
			}
		}

		if len(args) >= 3 && args[0] == "set" && args[2] == "peer" {
			kernel.peerCalls++
			kernel.peerInstalled = true
		}

		return "", nil
	}

	vpn.manager.run = kernel.runIP

	return backend, kernel
}

func (k *managedTestKernel) runIP(_ context.Context, args ...string) ([]byte, error) {
	namespace := ""
	if len(args) >= 2 && args[0] == "-n" {
		namespace, args = args[1], args[2:]
	}

	if strings.Join(args, " ") == "-details -json link show" {
		links := []managedLink{{Name: "lo", Index: 1, Type: "loopback"}}
		if namespace == "" {
			links = append(links, k.outsideExtra...)
		} else {
			links = append(links, k.insideExtra...)
		}

		if k.name != "" && k.namespace == namespace {
			link := managedLink{Name: k.name, Index: 20, Type: "none", Alias: k.alias}
			link.LinkInfo.Kind = "wireguard"
			links = append(links, link)
		}

		return json.Marshal(links)
	}

	command := strings.Join(args, " ")

	if fixture, exists := managedNetworkReadbacks[command]; exists {
		if namespace != vpnTestNS || k.name != labWGInterface || k.namespace != namespace {
			return nil, errors.New("tunnel not configured")
		}

		if command == k.networkReadError {
			return nil, errors.New("network readback failed")
		}

		if override, exists := k.networkOverrides[command]; exists {
			return []byte(override), nil
		}

		mtu := k.mtu
		if mtu == "" {
			mtu = "1420"
		}

		return []byte(strings.Replace(fixture, `"mtu":1280`, `"mtu":`+mtu, 1)), nil
	}

	k.mutations++

	switch {
	case len(args) == 5 && args[0] == "link" && args[1] == "add":
		k.name, k.namespace = args[2], ""

		if k.failAdd {
			return nil, errors.New("ambiguous link creation")
		}

	case len(args) == 6 && args[0] == "link" && args[1] == "set" && args[4] == "alias":
		k.alias = args[5]

	case len(args) == 5 && args[0] == "link" && args[1] == "set" && args[3] == "netns":
		k.namespace = args[4]

	case len(args) == 5 && args[0] == "link" && args[1] == "set" && args[3] == "name":
		if k.failRename {
			return nil, errors.New("rename failed")
		}

		k.name = args[4]

	case len(args) == 5 && args[0] == "link" && args[1] == "set" && args[2] == labWGInterface && args[3] == "mtu":
		k.mtu = args[4]

	case len(args) == 4 && args[0] == "link" && args[1] == "del":
		if k.failDelete {
			return nil, errors.New("delete failed")
		}

		if k.namespace != namespace || k.name != args[3] {
			return nil, errors.New("unexpected link deletion")
		}

		k.name, k.alias, k.namespace, k.mtu = "", "", "", ""
		k.peerInstalled = false
	}

	return nil, nil
}

func requireUntouched(t *testing.T, b *ManagedTunnelBackend, k *managedTestKernel) {
	t.Helper()

	if k.mutations != 0 || k.tableCreates != 0 || k.peerCalls != 0 || b.active != nil {
		t.Fatalf("kernel changed: %d link commands, %d tables, %d peers", k.mutations, k.tableCreates, k.peerCalls)
	}
}

func TestManagedTunnelConnectAndDisconnect(t *testing.T) {
	b, kernel := newManagedTunnelFixture(t)
	ctx := context.Background()

	if err := b.connectConfig(ctx, vpnTestNS, vpnTestConfig(t)); err != nil {
		t.Fatal(err)
	}

	if kernel.name != labWGInterface || kernel.namespace != vpnTestNS || kernel.peerCalls == 0 || b.active == nil ||
		!strings.HasPrefix(kernel.alias, managedTunnelAliasPrefix+vpnTestNS+":") {
		t.Fatal("tunnel not configured")
	}

	if err := b.VerifyConfigured(ctx, vpnTestNS); err != nil {
		t.Fatal(err)
	}

	if err := b.connectConfig(ctx, vpnTestNS, vpnTestConfig(t)); !errors.Is(err, ErrManagedTunnelBusy) {
		t.Fatalf("second tunnel: %v", err)
	}

	if err := b.Disconnect(ctx, "egresslab-lab-00000000000000bb"); !errors.Is(err, ErrNoManagedTunnel) {
		t.Fatalf("other namespace: %v", err)
	}

	if err := b.Disconnect(ctx, vpnTestNS); err != nil {
		t.Fatal(err)
	}

	if b.active != nil || kernel.name != "" || kernel.tableRemovals != 1 {
		t.Fatal("incomplete disconnect")
	}

	if err := b.VerifyConfigured(ctx, vpnTestNS); !errors.Is(err, ErrNoManagedTunnel) {
		t.Fatalf("verify after disconnect: %v", err)
	}
}

func TestManagedTunnelRejectsWrongMarkBeforePeer(t *testing.T) {
	b, kernel := newManagedTunnelFixture(t)
	kernel.wrongMark = true

	if err := b.connectConfig(context.Background(), vpnTestNS, vpnTestConfig(t)); err == nil || kernel.peerCalls != 0 {
		t.Fatal("peer configured before mark verification")
	}

	if b.active != nil || kernel.name != "" || kernel.tableRemovals != 1 {
		t.Fatal("verification failure not rolled back")
	}
}

func TestManagedTunnelRollsBackBeforeRename(t *testing.T) {
	b, kernel := newManagedTunnelFixture(t)
	kernel.failRename = true

	if err := b.connectConfig(context.Background(), vpnTestNS, vpnTestConfig(t)); err == nil {
		t.Fatal("rename failure accepted")
	}

	if b.active != nil || kernel.name != "" || kernel.tableRemovals != 1 {
		t.Fatal("unrenamed tunnel not rolled back")
	}
}

func TestManagedTunnelKeepsUnknownRootLink(t *testing.T) {
	b, kernel := newManagedTunnelFixture(t)
	kernel.failAdd = true

	if err := b.connectConfig(context.Background(), vpnTestNS, vpnTestConfig(t)); !errors.Is(err, ErrManagedTunnelUncertain) {
		t.Fatalf("unexpected error: %v", err)
	}

	if b.active == nil || !b.active.faulted || kernel.name == "" || kernel.tableRemovals != 0 {
		t.Fatal("uncertain resources were forgotten")
	}

	if err := b.connectConfig(context.Background(), vpnTestNS, vpnTestConfig(t)); !errors.Is(err, ErrManagedTunnelUncertain) {
		t.Fatalf("new tunnel while uncertain: %v", err)
	}
}

func TestManagedTunnelKeepsUnderlayOnDeleteFailure(t *testing.T) {
	b, kernel := newManagedTunnelFixture(t)
	ctx := context.Background()

	if err := b.connectConfig(ctx, vpnTestNS, vpnTestConfig(t)); err != nil {
		t.Fatal(err)
	}

	kernel.failDelete = true

	if err := b.Disconnect(ctx, vpnTestNS); err == nil {
		t.Fatal("failed deletion accepted")
	}

	if kernel.tableRemovals != 0 || b.active == nil || !b.active.faulted {
		t.Fatal("underlay or fault state lost")
	}

	if err := b.VerifyConfigured(ctx, vpnTestNS); !errors.Is(err, ErrManagedTunnelUncertain) {
		t.Fatalf("faulted tunnel verified: %v", err)
	}

	kernel.failDelete = false

	if err := b.Disconnect(ctx, vpnTestNS); err != nil {
		t.Fatal(err)
	}

	if b.active != nil || kernel.tableRemovals != 1 {
		t.Fatal("cleanup retry incomplete")
	}
}

func TestManagedTunnelKeepsUnconfirmedUnderlay(t *testing.T) {
	b, kernel := newManagedTunnelFixture(t)
	kernel.failUnderlay = true

	if err := b.connectConfig(context.Background(), vpnTestNS, vpnTestConfig(t)); !errors.Is(err, ErrManagedTunnelUncertain) {
		t.Fatalf("unexpected error: %v", err)
	}

	if kernel.mutations != 0 || b.active == nil || !b.active.faulted {
		t.Fatal("failed underlay install was forgotten or a link was created")
	}
}

func TestManagedTunnelKeepsUnderlayWhenLinkVanishes(t *testing.T) {
	b, kernel := newManagedTunnelFixture(t)
	ctx := context.Background()

	if err := b.connectConfig(ctx, vpnTestNS, vpnTestConfig(t)); err != nil {
		t.Fatal(err)
	}

	kernel.name, kernel.alias, kernel.namespace = "", "", ""

	if err := b.VerifyConfigured(ctx, vpnTestNS); !errors.Is(err, ErrManagedTunnelUncertain) {
		t.Fatalf("vanished link verified: %v", err)
	}

	if err := b.Disconnect(ctx, vpnTestNS); !errors.Is(err, ErrManagedTunnelUncertain) {
		t.Fatalf("vanished link treated as removed: %v", err)
	}

	if kernel.tableRemovals != 0 || b.active == nil {
		t.Fatal("underlay released without a confirmed removal")
	}
}

func TestManagedTunnelRefusesForeignDevices(t *testing.T) {
	wireguard := func(name, alias string) managedLink {
		link := managedLink{Name: name, Index: 30, Type: "none", Alias: alias}
		link.LinkInfo.Kind = "wireguard"
		return link
	}

	t.Run("leftover root tunnel", func(t *testing.T) {
		b, kernel := newManagedTunnelFixture(t)
		kernel.outsideExtra = []managedLink{wireguard("egwg12345678", "")}

		if err := b.connectConfig(context.Background(), vpnTestNS, vpnTestConfig(t)); !errors.Is(err, ErrRecoveryRequired) {
			t.Fatalf("unexpected error: %v", err)
		}

		requireUntouched(t, b, kernel)
	})

	t.Run("renamed managed link in the root namespace", func(t *testing.T) {
		b, kernel := newManagedTunnelFixture(t)
		kernel.outsideExtra = []managedLink{wireguard("vpn0", managedTunnelAliasPrefix+"x")}

		if err := b.connectConfig(context.Background(), vpnTestNS, vpnTestConfig(t)); !errors.Is(err, ErrRecoveryRequired) {
			t.Fatalf("unexpected error: %v", err)
		}

		requireUntouched(t, b, kernel)
	})

	t.Run("device in the lab before connect", func(t *testing.T) {
		b, kernel := newManagedTunnelFixture(t)
		kernel.insideExtra = []managedLink{wireguard(labWGInterface, "")}

		if err := b.connectConfig(context.Background(), vpnTestNS, vpnTestConfig(t)); !errors.Is(err, ErrLabNotLoopbackOnly) {
			t.Fatalf("unexpected error: %v", err)
		}

		requireUntouched(t, b, kernel)
	})

	t.Run("device added to the lab while connected", func(t *testing.T) {
		b, kernel := newManagedTunnelFixture(t)
		ctx := context.Background()

		if err := b.connectConfig(ctx, vpnTestNS, vpnTestConfig(t)); err != nil {
			t.Fatal(err)
		}

		kernel.insideExtra = []managedLink{{Name: "veth0", Index: 31, Type: "ether"}}

		if err := b.Disconnect(ctx, vpnTestNS); err == nil || kernel.name == "" || kernel.tableRemovals != 0 {
			t.Fatalf("disconnect went ahead around a foreign device: %v", err)
		}
	})
}

func TestManagedTunnelRequiresIntendedFirewall(t *testing.T) {
	b, kernel := newManagedTunnelFixture(t)

	// The session baseline matches the kernel, but neither is the intended sealed policy.
	tampered := encodeRuleset(t, withObject(t, sealedRulesetFixture(t), extraICMPRule))

	baseline, err := labRulesetFingerprint(tampered)
	if err != nil {
		t.Fatal(err)
	}

	b.sealed.firewall.baseline[vpnTestNS] = baseline
	b.sealed.firewall.list = func(context.Context, string) ([]byte, error) { return tampered, nil }

	if err := b.connectConfig(context.Background(), vpnTestNS, vpnTestConfig(t)); !errors.Is(err, ErrFirewallDrift) {
		t.Fatalf("unexpected error: %v", err)
	}

	requireUntouched(t, b, kernel)

	if !b.sealed.firewall.drifted[vpnTestNS] {
		t.Fatal("namespace not marked drifted")
	}
}

func TestManagedTunnelConnectStageBinding(t *testing.T) {
	path, _ := writeVaultFixture(t, "198.51.100.7")

	vault := NewWireGuardConfigVault()
	defer vault.Close()

	old, err := vault.StageFile(vaultProfileA, path)
	if err != nil {
		t.Fatal(err)
	}

	current, err := vault.StageFile(vaultProfileA, path)
	if err != nil {
		t.Fatal(err)
	}

	b, kernel := newManagedTunnelFixture(t)
	b.vault = vault
	b.sealed.kernelCheck = func() error { return nil }
	ctx := context.Background()

	for name, call := range map[string]func() error{
		"another profile": func() error { return b.ConnectStage(ctx, vaultProfileB, vpnTestNS, current.StageID) },
		"replaced stage":  func() error { return b.ConnectStage(ctx, vaultProfileA, vpnTestNS, old.StageID) },
		"malformed stage": func() error { return b.ConnectStage(ctx, vaultProfileA, vpnTestNS, "wgstage_x") },
	} {
		if err := call(); !errors.Is(err, ErrWGStageNotFound) {
			t.Errorf("%s: %v", name, err)
		}
	}

	if err := b.ConnectStage(ctx, vaultProfileA, "egresslab-lab-x", current.StageID); err == nil {
		t.Error("invalid namespace accepted")
	}

	// The right stage reaches the recovery gate, which refuses: this fixture has no scanner.
	if err := b.ConnectStage(ctx, vaultProfileA, vpnTestNS, current.StageID); !errors.Is(err, ErrRecoveryRequired) {
		t.Errorf("recovery gate skipped: %v", err)
	}

	requireUntouched(t, b, kernel)
}

func TestManagedTunnelCleanupStage(t *testing.T) {
	ctx := context.Background()

	t.Run("nothing tracked", func(t *testing.T) {
		b, kernel := newManagedTunnelFixture(t)

		if err := b.CleanupStage(ctx, vpnTestNS); err != nil {
			t.Fatal(err)
		}

		requireUntouched(t, b, kernel)
	})

	t.Run("not owned", func(t *testing.T) {
		b, _ := newManagedTunnelFixture(t)

		if err := b.CleanupStage(ctx, "egresslab-lab-00000000000000bb"); !errors.Is(err, ErrManagedTunnelUncertain) {
			t.Fatalf("unowned namespace: %v", err)
		}
	})

	t.Run("tracked tunnel", func(t *testing.T) {
		b, kernel := newManagedTunnelFixture(t)

		if err := b.connectConfig(ctx, vpnTestNS, vpnTestConfig(t)); err != nil {
			t.Fatal(err)
		}

		other := "egresslab-lab-00000000000000bb"
		b.sealed.manager.owned[other] = struct{}{}

		if err := b.CleanupStage(ctx, other); !errors.Is(err, ErrManagedTunnelUncertain) || b.active == nil {
			t.Fatalf("cleanup of another namespace: %v", err)
		}

		kernel.failDelete = true

		if err := b.CleanupStage(ctx, vpnTestNS); err == nil || b.active == nil || !b.active.faulted {
			t.Fatalf("failed cleanup forgot the tunnel: %v", err)
		}

		kernel.failDelete = false

		if err := b.CleanupStage(ctx, vpnTestNS); err != nil || b.active != nil || kernel.name != "" || kernel.tableRemovals != 1 {
			t.Fatalf("cleanup incomplete: %v", err)
		}
	})

	t.Run("after a clean rollback", func(t *testing.T) {
		b, kernel := newManagedTunnelFixture(t)
		kernel.failRename = true

		if err := b.connectConfig(ctx, vpnTestNS, vpnTestConfig(t)); err == nil || b.active != nil {
			t.Fatalf("rollback: %v", err)
		}

		if err := b.CleanupStage(ctx, vpnTestNS); err != nil {
			t.Fatal(err)
		}
	})
}
