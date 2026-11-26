//go:build linux

// Command egresslab-helper is the lab bootstrap of the privileged network helper. It listens on
// /run/egresslab/helper.sock, accepts only the configured agent UID (SO_PEERCRED) and answers
// read-only operations: Ping, RecoverScan and HelperInfo. With -auth-public-key-file it also
// answers the AuthorizeCheck dry-run, under a random helper ID (epoch) generated at every start.
// With -enable-lab-lifecycle as well, it creates (signed), verifies and deletes sealed lab
// namespaces; -enable-vault adds the managed WireGuard vault (StageInfo), and -enable-tunnel the
// signed ConnectTunnel and Disconnect of a vault stage in a sealed lab (one tunnel per helper), and
// -enable-probe (with -probe-uid and -probe-gid) the signed PermitProbe, one diagnostic egress probe
// run by an unprivileged worker. -enable-multi-probe (with the same IDs, and instead of
// -enable-probe) enables the signed, generation-bound PermitMultiProbeV2, MultiProbePolicy and
// MultiProbeTarget instead, with the ident.me pin read from /etc/egresslab/multi-probe-pin at
// startup. The offline commands vault-init, vault-stage and vault-revoke administer the vault, and
// check-multi-probe-pin applies the startup rules to a staged pin file. Proxy operations are not
// implemented.
//
// In this step it runs as root under sudo; the production design keeps only CAP_NET_ADMIN.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"net/netip"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/VanChung369/egresslab/services/network-agent/internal/agent"
	"github.com/VanChung369/egresslab/services/network-agent/internal/helperauth"
	"github.com/VanChung369/egresslab/services/network-agent/internal/helperipc"
)

func main() {
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "vault-init", "vault-stage", "vault-revoke":
			if err := runVaultAdmin(os.Args[1:]); err != nil {
				log.Fatal(err)
			}
			return

		case "check-multi-probe-pin":
			pin, err := checkMultiProbePinCommand(os.Args[2:])
			if err != nil {
				log.Fatal(err)
			}

			fmt.Println(pin)
			return
		}
	}

	uid := flag.Int("uid", -1, "allowed unprivileged agent UID")
	gid := flag.Int("gid", -1, "agent's primary group ID (gets socket access)")
	publicKeyFile := flag.String("auth-public-key-file", "",
		"root-owned file with the controller's Ed25519 public key (64 hex characters); enables AuthorizeCheck")
	enableLifecycle := flag.Bool("enable-lab-lifecycle", false,
		"enable signed sealed lab lifecycle operations (requires -auth-public-key-file)")
	enableVault := flag.Bool("enable-vault", false, "enable the root-managed WireGuard vault (requires -enable-lab-lifecycle)")
	enableTunnel := flag.Bool("enable-tunnel", false, "enable the managed WireGuard tunnel lifecycle (requires -enable-vault)")
	enableProbe := flag.Bool("enable-probe", false, "enable signed managed egress probes (requires -enable-tunnel)")
	enableMultiProbe := flag.Bool("enable-multi-probe", false,
		"enable signed multi-source egress verification (requires -enable-tunnel; excludes -enable-probe)")
	probeUID := flag.Int("probe-uid", -1, "dedicated unprivileged probe UID")
	probeGID := flag.Int("probe-gid", -1, "dedicated unprivileged probe GID")
	enableProxy := flag.Bool("enable-proxy", false,
		"enable signed proxy streams through the kernel-timed traffic gate (requires -enable-multi-probe)")
	proxyUID := flag.Int("proxy-uid", -1, "dedicated unprivileged proxy UID")
	proxyGID := flag.Int("proxy-gid", -1, "dedicated unprivileged proxy GID")
	flag.Parse()

	if os.Geteuid() != 0 || *uid <= 0 || *gid <= 0 || flag.NArg() != 0 {
		log.Fatal("usage: sudo egresslab-helper -uid <non-root UID> -gid <non-root GID> " +
			"[-auth-public-key-file <path> [-enable-lab-lifecycle [-enable-vault [-enable-tunnel\n" +
			"       [(-enable-probe | -enable-multi-probe) -probe-uid <UID> -probe-gid <GID>\n" +
			"       [-enable-proxy -proxy-uid <UID> -proxy-gid <GID>]]]]]\n" +
			"       sudo egresslab-helper vault-init | vault-stage PROFILE_ID | vault-revoke PROFILE_ID\n" +
			"       sudo egresslab-helper check-multi-probe-pin PATH")
	}

	if err := run(*uid, *gid, *publicKeyFile, *enableLifecycle, *enableVault, *enableTunnel, *enableProbe,
		*probeUID, *probeGID, *enableMultiProbe, proxyFlags{*enableProxy, *proxyUID, *proxyGID}); err != nil {
		log.Fatal(err)
	}
}

// validID accepts a non-root ID that fits uid_t/gid_t, excluding (uid_t)-1.
func validID(id int) bool {
	return id > 0 && uint64(id) < uint64(^uint32(0))
}

// validateProbeFlags allows one probe mode at most. The probe worker never shares the agent's
// identity: it needs neither the socket nor the vault. The agent's IDs are bounded first, so a
// value beyond 32 bits cannot compare unequal here and still name the worker once truncated.
func validateProbeFlags(uid, gid int, enableTunnel, enableProbe, enableMultiProbe bool, probeUID, probeGID int) error {
	if !validID(uid) || !validID(gid) {
		return errors.New("agent UID and GID must be non-root 32-bit IDs")
	}

	if enableProbe && enableMultiProbe {
		return errors.New("single-source and multi-source probe modes are mutually exclusive")
	}

	if !enableProbe && !enableMultiProbe {
		if probeUID != -1 || probeGID != -1 {
			return errors.New("probe UID and GID require -enable-probe or -enable-multi-probe")
		}

		return nil
	}

	if !enableTunnel {
		return errors.New("managed probe requires managed tunnel")
	}

	if !validID(probeUID) || !validID(probeGID) || probeUID == uid || probeGID == gid {
		return errors.New("managed probe requires a separate non-root UID and GID")
	}

	return nil
}

type proxyFlags struct {
	enable   bool
	uid, gid int
}

// validateProxyFlags: the proxy user is neither root, the agent nor the probe worker, and exists only
// on top of the generation-bound multi-source verification.
func validateProxyFlags(p proxyFlags, uid, gid int, enableMultiProbe bool, probeUID, probeGID int) error {
	if !p.enable {
		if p.uid != -1 || p.gid != -1 {
			return errors.New("proxy UID and GID require -enable-proxy")
		}

		return nil
	}

	if !enableMultiProbe {
		return errors.New("proxy streams require -enable-multi-probe")
	}

	if !validID(p.uid) || !validID(p.gid) || p.uid == uid || p.gid == gid || p.uid == probeUID || p.gid == probeGID {
		return errors.New("proxy requires a separate non-root UID and GID")
	}

	return nil
}

func run(
	uid, gid int,
	publicKeyFile string,
	enableLifecycle, enableVault, enableTunnel, enableProbe bool,
	probeUID, probeGID int,
	enableMultiProbe bool,
	proxy proxyFlags,
) error {
	if err := validateProbeFlags(uid, gid, enableTunnel, enableProbe, enableMultiProbe, probeUID, probeGID); err != nil {
		return err
	}

	if err := validateProxyFlags(proxy, uid, gid, enableMultiProbe, probeUID, probeGID); err != nil {
		return err
	}

	// The worker binary is verified before anything else starts.
	var proxyDial helperipc.ProxyDialer

	if proxy.enable {
		dial, err := agent.NewProxyDialer(uint32(proxy.uid), uint32(proxy.gid))
		if err != nil {
			return fmt.Errorf("proxy dial worker: %w", err)
		}

		proxyDial = helperipc.ProxyDialer(dial)
	}

	if enableTunnel && !enableVault {
		return errors.New("managed tunnel requires managed vault")
	}

	if enableVault && !enableLifecycle {
		return errors.New("managed vault requires authorized lab lifecycle")
	}

	// The trusted source policy is read before the key, the socket, the vault or the kernel: a
	// missing or unsafe pin refuses the start, with no fallback to the single-source probe.
	var identPin netip.Addr

	if enableMultiProbe {
		pin, err := loadMultiProbePin()
		if err != nil {
			return fmt.Errorf("multi-source probe configuration: %w", err)
		}

		identPin = pin
	}

	// Load the key before touching /run/egresslab, so a bad configuration changes nothing.
	verifier, err := loadAuthVerifier(publicKeyFile)
	if err != nil {
		return fmt.Errorf("authorization configuration: %w", err)
	}

	var labs *helperipc.LabLifecycle
	var backend labBackend

	if enableLifecycle {
		if verifier == nil {
			return errors.New("lab lifecycle requires a configured authorization public key")
		}

		// Read-only: EgressLab never changes this sysctl or loads/unloads modules.
		if err := agent.CheckSealedLabKernel(); err != nil {
			return fmt.Errorf("lab lifecycle: %w", err)
		}

		sealed, err := agent.NewSealedLabBackend()
		if err != nil {
			return fmt.Errorf("initialize sealed lab backend: %w", err)
		}

		backend = labBackend{sealed}
		labs = helperipc.NewLabLifecycle(backend)
	}

	var readStage helperipc.StageReader

	if enableVault {
		if !enableLifecycle || verifier == nil {
			return errors.New("managed vault requires authorized lab lifecycle")
		}

		// Held for the helper's lifetime: the offline vault commands are refused meanwhile.
		vault, err := managedLayout.open()
		if err != nil {
			return fmt.Errorf("managed vault: %w", err)
		}
		defer vault.Close()

		readStage = vault.readStage

		if enableTunnel {
			var tunnels *agent.ManagedTunnelBackend

			switch {
			case enableMultiProbe:
				tunnels, err = agent.NewManagedMultiProbeTunnelBackend(backend.SealedLabBackend,
					vault.WireGuardConfigVault, probeUID, probeGID, identPin)
			case enableProbe:
				tunnels, err = agent.NewManagedProbeTunnelBackend(backend.SealedLabBackend, vault.WireGuardConfigVault,
					probeUID, probeGID)
			default:
				tunnels, err = agent.NewManagedTunnelBackend(backend.SealedLabBackend, vault.WireGuardConfigVault)
			}

			if err != nil {
				return fmt.Errorf("initialize managed tunnel: %w", err)
			}

			switch {
			case enableMultiProbe:
				labs = helperipc.NewGenerationProbeLifecycle(backend, tunnelBackend{tunnels})
			case enableProbe:
				labs = helperipc.NewProbeLifecycle(backend, tunnelBackend{tunnels})
			default:
				labs = helperipc.NewTunnelLifecycle(backend, tunnelBackend{tunnels})
			}
		}
	}

	runtimeID, err := runtimeIDFrom(machineIDPath)
	if err != nil {
		log.Printf("no runtime ID (%v); the controller will not trust this runtime", err)
	}

	if enableTunnel && runtimeID == "" {
		return errors.New("managed tunnel requires a valid runtime identity")
	}

	// The vault lock is still held; without a committed witness the socket is never created. A
	// start that would be refused at the socket records no epoch.
	if enableMultiProbe {
		if err := checkSocketPath(); err != nil {
			return err
		}

		helperID, fingerprint := verifier.Identity()

		if err := registerHelperEpochLocked(managedLayout, runtimeID, helperID, fingerprint); err != nil {
			return fmt.Errorf("persistent helper epoch registration: %w", err)
		}

		log.Printf("Persistent boot-bound helper epoch witness committed: %s", helperID)
	}

	listener, cleanup, err := prepareSocket(gid)
	if err != nil {
		return err
	}
	defer cleanup()

	// SIGHUP too: closing the terminal must not leave a stale socket behind.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM, syscall.SIGHUP)
	defer stop()

	mode := "read-only operations; AuthorizeCheck disabled"
	if verifier != nil {
		helperID, fingerprint := verifier.Identity()
		mode = "read-only operations; AuthorizeCheck dry-run enabled"

		log.Printf("Helper epoch: %s; controller public-key SHA256: %s", helperID, fingerprint)
	}

	if labs != nil {
		mode = "signed sealed lab lifecycle enabled; VPN operations disabled"
		if enableTunnel {
			mode = "signed sealed lab lifecycle and managed tunnel enabled; probe and proxy disabled"
		}

		if enableProbe {
			mode = "signed sealed lab, managed tunnel and diagnostic probe enabled; proxy disabled"
		}

		if enableMultiProbe {
			mode = "signed generation-bound multi-source verification enabled; V1, single-source probe and proxy disabled"
			if proxy.enable {
				mode = "signed generation-bound multi-source verification and proxy streams enabled; V1 and single-source probe disabled"
			}

			log.Printf("Multi-source policy: %s; ident.me pin: %s", helperauth.OpPermitMultiProbeV2, identPin)
		}

		if err := backend.Preflight(ctx); err != nil {
			log.Printf("CreateLab is refused until this is resolved: %v", err)
		}
	}

	if runtimeID != "" {
		log.Printf("Runtime ID: %s", runtimeID)
	}

	// Only an epoch whose own witness is committed answers a reboot-bound recovery.
	var readEpochRecovery helperipc.EpochRecoveryReader

	if enableMultiProbe {
		readEpochRecovery = func(originalID, currentID, runtimeID, fingerprint string) (string, string, error) {
			return readEpochRecoveryLocked(managedLayout, originalID, currentID, runtimeID, fingerprint)
		}
	}

	// The monitor stops before the labs close and the vault is released.
	var stopMonitor context.CancelFunc
	var monitorDone chan struct{}

	if enableMultiProbe {
		var monitorCtx context.Context

		monitorCtx, stopMonitor = context.WithCancel(ctx)
		monitorDone = make(chan struct{})

		go func() {
			defer close(monitorDone)
			labs.RunEgressMonitor(monitorCtx)
		}()
	}

	log.Printf("EgressLab helper listening on %s (UID %d; %s)", helperipc.SocketPath, uid, mode)

	err = helperipc.ServeWith(ctx, listener, uint32(uid), helperipc.ServerOptions{
		Scan:              scanRecovery,
		Verifier:          verifier,
		Labs:              labs,
		RuntimeID:         runtimeID,
		ReadStage:         readStage,
		ReadEpochRecovery: readEpochRecovery,
		ProxyUID:          proxyUID(proxy),
		ProxyDial:         proxyDial,
	})

	if stopMonitor != nil {
		stopMonitor()
		<-monitorDone
	}

	// Labs that cannot be deleted stay, with their markers, for egresslab-lab-recover.
	if labs != nil {
		err = errors.Join(err, labs.Close())
	}

	log.Print("EgressLab helper stopped")

	return err
}

// prepareSocket creates the helper socket.
//
// The directory is root-owned, group-traversable and not writable by the agent. The socket is
// root-owned with group read/write; SO_PEERCRED still checks the caller's UID.
func prepareSocket(gid int) (*net.UnixListener, func(), error) {
	if err := checkSocketPath(); err != nil {
		return nil, nil, err
	}

	dir := filepath.Dir(helperipc.SocketPath)

	if err := os.Chown(dir, 0, gid); err != nil {
		return nil, nil, err
	}

	if err := os.Chmod(dir, 0o750); err != nil {
		return nil, nil, err
	}

	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: helperipc.SocketPath, Net: "unix"})
	if err != nil {
		return nil, nil, err
	}

	// Cleanup unlinks the path only if it still names the socket created here.
	listener.SetUnlinkOnClose(false)

	created, err := os.Lstat(helperipc.SocketPath)
	if err != nil || created.Mode()&os.ModeSocket == 0 {
		listener.Close()
		return nil, nil, errors.New("new helper socket could not be inspected")
	}

	cleanup := func() {
		listener.Close()

		current, err := os.Lstat(helperipc.SocketPath)
		if err == nil && os.SameFile(created, current) {
			_ = os.Remove(helperipc.SocketPath)
		}
	}

	if err := os.Chown(helperipc.SocketPath, 0, gid); err != nil {
		cleanup()
		return nil, nil, err
	}

	if err := os.Chmod(helperipc.SocketPath, 0o660); err != nil {
		cleanup()
		return nil, nil, err
	}

	return listener, cleanup, nil
}

// checkSocketPath creates the socket directory if needed and refuses an unsafe directory or an
// existing socket path.
func checkSocketPath() error {
	dir := filepath.Dir(helperipc.SocketPath)

	if err := os.Mkdir(dir, 0o750); err != nil && !errors.Is(err, os.ErrExist) {
		return err
	}

	info, err := os.Lstat(dir)
	if err != nil {
		return err
	}

	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.IsDir() || stat.Uid != 0 || info.Mode().Perm()&0o022 != 0 {
		return errors.New("helper socket directory must be root owned and not writable by other users")
	}

	// Never unlink an existing path: it may belong to a live helper. Check before touching the
	// directory, so a refused start cannot re-group it under a running helper.
	if _, err := os.Lstat(helperipc.SocketPath); err == nil {
		return fmt.Errorf(
			"%s already exists; if no egresslab-helper process is running (pidof egresslab-helper prints nothing), remove it by hand",
			helperipc.SocketPath,
		)
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}

	return nil
}

// scanRecovery reuses the read-only LabRecovery.Scan. Clean/delete and shell commands are not
// reachable from here.
func scanRecovery(ctx context.Context) ([]helperipc.RecoveryItem, error) {
	items, err := scanLabResources(ctx)
	if err != nil {
		// The client only sees "recovery scan failed"; the operator sees the cause.
		log.Printf("recovery scan failed: %v", err)
		return nil, err
	}

	out := make([]helperipc.RecoveryItem, 0, len(items))
	for _, item := range items {
		out = append(out, helperipc.RecoveryItem{
			Kind:   item.Kind,
			Name:   item.Name,
			State:  item.State,
			Detail: item.Detail,
		})
	}

	return out, nil
}

func scanLabResources(ctx context.Context) ([]agent.LabRecoveryItem, error) {
	manager, err := agent.NewNetNSLabManager()
	if err != nil {
		return nil, err
	}

	recovery, err := agent.NewLabRecovery(manager)
	if err != nil {
		return nil, err
	}

	return recovery.Scan(ctx)
}

func proxyUID(p proxyFlags) uint32 {
	if !p.enable {
		return 0
	}

	return uint32(p.uid)
}
