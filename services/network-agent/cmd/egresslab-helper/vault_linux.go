//go:build linux

package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"syscall"

	"github.com/VanChung369/egresslab/services/network-agent/internal/agent"
	"github.com/VanChung369/egresslab/services/network-agent/internal/helperauth"
	"github.com/VanChung369/egresslab/services/network-agent/internal/helperipc"
)

// vaultLayout fixes every vault path; nothing reaches the helper as a path from a client.
type vaultLayout struct {
	keyDir  string
	dataDir string
	root    string // directories are checked from the vault up to and including root
	owner   uint32
}

var managedLayout = vaultLayout{keyDir: "/etc/egresslab/vault", dataDir: "/var/lib/egresslab/vault", root: "/", owner: 0}

func (l vaultLayout) keyPath() string    { return filepath.Join(l.keyDir, "wg-vault.key") }
func (l vaultLayout) dataPath() string   { return filepath.Join(l.dataDir, "wg-vault.json") }
func (l vaultLayout) lockPath() string   { return filepath.Join(l.dataDir, "vault.lock") }
func (l vaultLayout) importPath() string { return filepath.Join(l.dataDir, "import.conf") }

type managedVault struct {
	*agent.WireGuardConfigVault
	lock *os.File
}

func (l vaultLayout) checkDir(path string) error {
	if err := checkDirChain(path, l.root, l.owner); err != nil {
		return fmt.Errorf("unsafe vault directory: %w", err)
	}

	info, err := os.Lstat(path)
	if err != nil {
		return err
	}

	if info.Mode().Perm() != 0o700 {
		return fmt.Errorf("vault directory must be mode 0700: %s", path)
	}

	return nil
}

func (l vaultLayout) validateFile(info os.FileInfo) error {
	stat, ok := info.Sys().(*syscall.Stat_t)

	if !ok || !info.Mode().IsRegular() || stat.Uid != l.owner || stat.Nlink != 1 || info.Mode().Perm() != 0o600 {
		return errors.New("vault file must be root-owned, regular, mode 0600, without hard links")
	}

	return nil
}

func (l vaultLayout) fileExists(path string) (bool, error) {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}

	if err := l.validateFile(info); err != nil {
		return false, fmt.Errorf("%s: %w", path, err)
	}

	return true, nil
}

// lock takes the exclusive flock shared by the helper and the offline admin commands. The kernel
// releases it when the holder exits, crash included; never remove vault.lock to get around it.
func (l vaultLayout) lock() (*os.File, error) {
	for _, dir := range []string{l.keyDir, l.dataDir} {
		if err := l.checkDir(dir); err != nil {
			return nil, err
		}
	}

	file, err := os.OpenFile(l.lockPath(), os.O_CREATE|os.O_RDWR|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0o600)
	if err != nil {
		return nil, err
	}

	info, err := file.Stat()
	if err == nil {
		err = l.validateFile(info)
	}

	if err != nil {
		file.Close()
		return nil, err
	}

	if err := syscall.Flock(int(file.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		file.Close()
		return nil, errors.New("vault is in use; stop the helper before changing configs")
	}

	return file, nil
}

func (l vaultLayout) initialize() error {
	lock, err := l.lock()
	if err != nil {
		return err
	}
	defer lock.Close()

	for _, path := range []string{l.keyPath(), l.dataPath()} {
		exists, err := l.fileExists(path)
		if err != nil {
			return err
		}

		if exists {
			return errors.New("vault already initialized, or existing data needs recovery")
		}
	}

	return agent.GenerateVaultKeyFile(l.keyPath())
}

func (l vaultLayout) open() (*managedVault, error) {
	lock, err := l.lock()
	if err != nil {
		return nil, err
	}

	success := false
	defer func() {
		if !success {
			_ = lock.Close()
		}
	}()

	exists, err := l.fileExists(l.keyPath())
	if err != nil {
		return nil, err
	}
	if !exists {
		return nil, errors.New("vault key missing; run vault-init")
	}

	if _, err := l.fileExists(l.dataPath()); err != nil {
		return nil, err
	}

	store, err := agent.OpenSealedWireGuardStore(l.dataPath(), l.keyPath())
	if err != nil {
		return nil, err
	}

	vault, err := agent.OpenPersistentWireGuardConfigVault(store)
	if err != nil {
		return nil, err
	}

	success = true

	return &managedVault{WireGuardConfigVault: vault, lock: lock}, nil
}

func (v *managedVault) Close() {
	v.WireGuardConfigVault.Close()
	_ = v.lock.Close()
}

func (v *managedVault) readStage(profileID string) (helperipc.StageInfo, error) {
	status, err := v.Status(profileID)
	if errors.Is(err, agent.ErrWGStageNotFound) {
		return helperipc.StageInfo{}, helperipc.ErrStageNotFound
	}
	if err != nil {
		return helperipc.StageInfo{}, err
	}

	if status.State != "staged_encrypted_at_rest" {
		return helperipc.StageInfo{}, errors.New("unexpected vault storage state")
	}

	return helperipc.StageInfo{ProfileID: status.ProfileID, StageID: status.StageID, Compatible: status.Config.VPNLabCompatible}, nil
}

// runVaultAdmin runs the local, root-only vault commands. They are never reachable through the
// helper socket.
func runVaultAdmin(args []string) error {
	if os.Geteuid() != 0 {
		return errors.New("vault administration requires root")
	}

	return managedLayout.admin(args, os.Stdout)
}

func (l vaultLayout) admin(args []string, stdout io.Writer) error {
	if len(args) == 1 && args[0] == "vault-init" {
		if err := l.initialize(); err != nil {
			return err
		}

		_, err := fmt.Fprintln(stdout, "Managed WireGuard vault initialized")
		return err
	}

	if len(args) != 2 || !helperauth.ValidProfileID(args[1]) || (args[0] != "vault-stage" && args[0] != "vault-revoke") {
		return errors.New("usage: egresslab-helper vault-init | vault-stage PROFILE_ID | vault-revoke PROFILE_ID")
	}

	vault, err := l.open()
	if err != nil {
		return err
	}
	defer vault.Close()

	profileID := args[1]

	if args[0] == "vault-revoke" {
		return vault.Revoke(profileID)
	}

	exists, err := l.fileExists(l.importPath())
	if err != nil {
		return err
	}
	if !exists {
		return fmt.Errorf("%s is missing", l.importPath())
	}

	// Importer errors name a line and a cause, never config content.
	if _, err := vault.StageFile(profileID, l.importPath()); err != nil {
		return fmt.Errorf("WireGuard config staging failed: %w", err)
	}

	// The plaintext copy is consumed; the vault keeps only the encrypted config.
	if err := os.Remove(l.importPath()); err != nil {
		return fmt.Errorf("staged, but could not remove %s: %w", l.importPath(), err)
	}

	info, err := vault.readStage(profileID)
	if err != nil {
		return err
	}

	encoder := json.NewEncoder(stdout)
	encoder.SetIndent("", "  ")

	return encoder.Encode(info)
}
