//go:build linux

// Command egresslab-helper is the lab bootstrap of the privileged network helper. It listens on
// /run/egresslab/helper.sock, accepts only the configured agent UID (SO_PEERCRED) and answers
// read-only operations: Ping, RecoverScan and HelperInfo. With -auth-public-key-file it also
// answers the AuthorizeCheck dry-run, under a random helper ID (epoch) generated at every start.
// With -enable-lab-lifecycle as well, it creates (signed), verifies and deletes sealed lab
// namespaces; -enable-vault adds the managed WireGuard vault (StageInfo), and -enable-tunnel the
// signed ConnectTunnel and Disconnect of a vault stage in a sealed lab (one tunnel per helper), and
// -enable-probe (with -probe-uid and -probe-gid) the signed PermitProbe, one diagnostic egress probe
// run by an unprivileged worker. The offline commands vault-init, vault-stage and vault-revoke
// administer the vault. Proxy operations are not implemented.
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
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/VanChung369/egresslab/services/network-agent/internal/agent"
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
	probeUID := flag.Int("probe-uid", -1, "dedicated unprivileged probe UID")
	probeGID := flag.Int("probe-gid", -1, "dedicated unprivileged probe GID")
	flag.Parse()

	if os.Geteuid() != 0 || *uid <= 0 || *gid <= 0 || flag.NArg() != 0 {
		log.Fatal("usage: sudo egresslab-helper -uid <non-root UID> -gid <non-root GID> " +
			"[-auth-public-key-file <path> [-enable-lab-lifecycle [-enable-vault [-enable-tunnel\n" +
			"       [-enable-probe -probe-uid <UID> -probe-gid <GID>]]]]]\n" +
			"       sudo egresslab-helper vault-init | vault-stage PROFILE_ID | vault-revoke PROFILE_ID")
	}

	if err := run(*uid, *gid, *publicKeyFile, *enableLifecycle, *enableVault, *enableTunnel, *enableProbe,
		*probeUID, *probeGID); err != nil {
		log.Fatal(err)
	}
}

func run(
	uid, gid int,
	publicKeyFile string,
	enableLifecycle, enableVault, enableTunnel, enableProbe bool,
	probeUID, probeGID int,
) error {
	// The probe worker never shares the agent's identity: it needs neither the socket nor the vault.
	if enableProbe {
		if !enableTunnel {
			return errors.New("managed probe requires managed tunnel")
		}

		if probeUID <= 0 || probeGID <= 0 || probeUID == uid || probeGID == gid {
			return errors.New("managed probe requires a separate non-root UID and GID")
		}
	} else if probeUID != -1 || probeGID != -1 {
		return errors.New("probe UID and GID require -enable-probe")
	}

	if enableTunnel && !enableVault {
		return errors.New("managed tunnel requires managed vault")
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

			if enableProbe {
				tunnels, err = agent.NewManagedProbeTunnelBackend(backend.SealedLabBackend, vault.WireGuardConfigVault,
					probeUID, probeGID)
			} else {
				tunnels, err = agent.NewManagedTunnelBackend(backend.SealedLabBackend, vault.WireGuardConfigVault)
			}

			if err != nil {
				return fmt.Errorf("initialize managed tunnel: %w", err)
			}

			if enableProbe {
				labs = helperipc.NewProbeLifecycle(backend, tunnelBackend{tunnels})
			} else {
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

		if err := backend.Preflight(ctx); err != nil {
			log.Printf("CreateLab is refused until this is resolved: %v", err)
		}
	}

	if runtimeID != "" {
		log.Printf("Runtime ID: %s", runtimeID)
	}

	log.Printf("EgressLab helper listening on %s (UID %d; %s)", helperipc.SocketPath, uid, mode)

	err = helperipc.ServeWith(ctx, listener, uint32(uid), helperipc.ServerOptions{
		Scan:      scanRecovery,
		Verifier:  verifier,
		Labs:      labs,
		RuntimeID: runtimeID,
		ReadStage: readStage,
	})

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
	dir := filepath.Dir(helperipc.SocketPath)

	if err := os.Mkdir(dir, 0o750); err != nil && !errors.Is(err, os.ErrExist) {
		return nil, nil, err
	}

	info, err := os.Lstat(dir)
	if err != nil {
		return nil, nil, err
	}

	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.IsDir() || stat.Uid != 0 || info.Mode().Perm()&0o022 != 0 {
		return nil, nil, errors.New("helper socket directory must be root owned and not writable by other users")
	}

	// Never unlink an existing path: it may belong to a live helper. Check before touching the
	// directory, so a refused start cannot re-group it under a running helper.
	if _, err := os.Lstat(helperipc.SocketPath); err == nil {
		return nil, nil, fmt.Errorf(
			"%s already exists; if no egresslab-helper process is running (pidof egresslab-helper prints nothing), remove it by hand",
			helperipc.SocketPath,
		)
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, nil, err
	}

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
