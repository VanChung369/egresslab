package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/VanChung369/egresslab/services/network-agent/internal/agent"
)

func main() {
	path := flag.String("file", "", "local WireGuard .conf path")
	profileID := flag.String("profile", "", "routing profile ID")
	flag.Parse()

	if *path == "" || *profileID == "" || flag.NArg() != 0 {
		fmt.Fprintln(os.Stderr, "usage: egresslab-wg-vault-lab -profile profile_0123456789abcdef -file /path/to/vpn.conf")
		os.Exit(2)
	}

	if err := run(*profileID, *path); err != nil {
		fmt.Fprintln(os.Stderr, "vault lab:", err)
		os.Exit(1)
	}
}

func run(profileID, path string) error {
	vault := agent.NewWireGuardConfigVault()
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

	fmt.Println("Staged in memory only; no VPN connected and no secret persisted.")
	fmt.Println("Press Enter to revoke this stage and exit.")

	_, _ = bufio.NewReader(os.Stdin).ReadString('\n')

	if err := vault.Revoke(profileID); err != nil {
		return fmt.Errorf("revoke stage: %w", err)
	}

	fmt.Println("Stage revoked.")

	return nil
}
