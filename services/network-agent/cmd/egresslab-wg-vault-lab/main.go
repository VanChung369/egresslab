package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"

	"github.com/VanChung369/egresslab/services/network-agent/internal/agent"
)

func main() {
	path := flag.String("file", "", "local WireGuard .conf path")
	profileID := flag.String("profile", "", "routing profile ID")
	store := flag.String("store", "", "opt-in: encrypted vault file (persists the stage); requires -key")
	key := flag.String("key", "", "opt-in: 32-byte vault key file (0600) in a different directory than -store")
	generateKey := flag.Bool("generate-key", false, "create the -key file first if it does not exist")
	flag.Parse()

	if *path == "" || *profileID == "" || flag.NArg() != 0 || (*store == "") != (*key == "") {
		fmt.Fprintln(os.Stderr, "usage: egresslab-wg-vault-lab -profile profile_0123456789abcdef -file /path/to/vpn.conf")
		fmt.Fprintln(os.Stderr, "       [-store /var/lib/egresslab/wg-vault.json -key /etc/egresslab/wg-vault.key [-generate-key]]")
		os.Exit(2)
	}

	if err := run(*profileID, *path, *store, *key, *generateKey); err != nil {
		fmt.Fprintln(os.Stderr, "vault lab:", err)
		os.Exit(1)
	}
}

func openVault(storePath, keyPath string, generateKey bool) (*agent.WireGuardConfigVault, error) {
	if storePath == "" {
		return agent.NewWireGuardConfigVault(), nil
	}

	if generateKey {
		if err := agent.GenerateVaultKeyFile(keyPath); err != nil && !errors.Is(err, os.ErrExist) {
			return nil, err
		}
	}

	store, err := agent.OpenSealedWireGuardStore(storePath, keyPath)
	if err != nil {
		return nil, err
	}

	return agent.OpenPersistentWireGuardConfigVault(store)
}

func run(profileID, path, storePath, keyPath string, generateKey bool) error {
	vault, err := openVault(storePath, keyPath, generateKey)
	if err != nil {
		return fmt.Errorf("open vault: %w", err)
	}
	defer vault.Close()

	status, err := vault.StageFile(profileID, path)
	if err != nil {
		return fmt.Errorf("stage rejected: %w", err)
	}

	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")

	if err := encoder.Encode(status); err != nil {
		return fmt.Errorf("could not print safe status: %w", err)
	}

	if storePath == "" {
		fmt.Println("Staged in memory only; no VPN connected and no secret persisted.")
	} else {
		fmt.Printf("Staged and encrypted at rest in %s (AES-256-GCM, key %s); no VPN connected.\n", storePath, keyPath)
	}

	fmt.Println("Press Enter to revoke this stage and exit (Ctrl+C keeps a persisted stage).")

	_, _ = bufio.NewReader(os.Stdin).ReadString('\n')

	if err := vault.Revoke(profileID); err != nil {
		return fmt.Errorf("revoke stage: %w", err)
	}

	fmt.Println("Stage revoked.")

	return nil
}
