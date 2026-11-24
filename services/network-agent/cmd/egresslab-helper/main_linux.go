//go:build linux

// Command egresslab-helper is the lab bootstrap of the privileged network helper. It listens on
// /run/egresslab/helper.sock, accepts only the configured agent UID (SO_PEERCRED) and answers
// read-only operations: Ping, RecoverScan and HelperInfo. With -auth-public-key-file it also
// answers the AuthorizeCheck dry-run, under a random helper ID (epoch) generated at every start.
// With -enable-lab-lifecycle as well, it creates (signed), verifies and deletes sealed lab
// namespaces. Tunnel and probe operations are not implemented.
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
	uid := flag.Int("uid", -1, "allowed unprivileged agent UID")
	gid := flag.Int("gid", -1, "agent's primary group ID (gets socket access)")
	publicKeyFile := flag.String("auth-public-key-file", "",
		"root-owned file with the controller's Ed25519 public key (64 hex characters); enables AuthorizeCheck")
	enableLifecycle := flag.Bool("enable-lab-lifecycle", false,
		"enable signed sealed lab lifecycle operations (requires -auth-public-key-file)")
	flag.Parse()

	if os.Geteuid() != 0 || *uid <= 0 || *gid <= 0 || flag.NArg() != 0 {
		log.Fatal("usage: sudo egresslab-helper -uid <non-root UID> -gid <non-root GID> " +
			"[-auth-public-key-file <path> [-enable-lab-lifecycle]]")
	}

	if err := run(*uid, *gid, *publicKeyFile, *enableLifecycle); err != nil {
		log.Fatal(err)
	}
}

func run(uid, gid int, publicKeyFile string, enableLifecycle bool) error {
	// Load the key before touching /run/egresslab, so a bad configuration changes nothing.
	verifier, err := loadAuthVerifier(publicKeyFile)
	if err != nil {
		return fmt.Errorf("authorization configuration: %w", err)
	}

	var labs *helperipc.LabLifecycle

	if enableLifecycle {
		if verifier == nil {
			return errors.New("lab lifecycle requires a configured authorization public key")
		}

		backend, err := agent.NewSealedLabBackend()
		if err != nil {
			return fmt.Errorf("initialize sealed lab backend: %w", err)
		}

		labs = helperipc.NewLabLifecycle(backend)
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
	}

	log.Printf("EgressLab helper listening on %s (UID %d; %s)", helperipc.SocketPath, uid, mode)

	err = helperipc.ServeLifecycle(ctx, listener, uint32(uid), scanRecovery, verifier, labs)

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
