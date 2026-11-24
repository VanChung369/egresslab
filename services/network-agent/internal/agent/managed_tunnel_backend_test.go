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
}

func newManagedTunnelFixture(t *testing.T) (*ManagedTunnelBackend, *managedTestKernel) {
	t.Helper()

	vpn, _ := testVPNLab(true)
	kernel := &managedTestKernel{}

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

	vpn.runWG = func(_ context.Context, _ string, _ []byte, args ...string) (string, error) {
		if args[0] == "show" && args[len(args)-1] == "fwmark" {
			if kernel.wrongMark {
				return "off", nil
			}

			return "0xabcd", nil
		}

		if len(args) >= 3 && args[0] == "set" && args[2] == "peer" {
			kernel.peerCalls++
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

	case len(args) == 4 && args[0] == "link" && args[1] == "del":
		if k.failDelete {
			return nil, errors.New("delete failed")
		}

		if k.namespace != namespace || k.name != args[3] {
			return nil, errors.New("unexpected link deletion")
		}

		k.name, k.alias, k.namespace = "", "", ""
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
