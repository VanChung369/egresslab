package agent

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
)

const (
	vaultProfileA = "profile_0123456789abcdef"
	vaultProfileB = "profile_fedcba9876543210"
)

func writeVaultFixture(t *testing.T, host string) (string, string) {
	t.Helper()

	secret := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{7}, 32))
	public := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{9}, 32))

	config := fmt.Sprintf(`[Interface]
PrivateKey = %s
Address = 10.2.0.2/32
DNS = 10.2.0.1

[Peer]
PublicKey = %s
Endpoint = %s:51820
AllowedIPs = 0.0.0.0/0, ::/0
`, secret, public, host)

	path := filepath.Join(t.TempDir(), "vpn.conf")
	if err := os.WriteFile(path, []byte(config), 0o600); err != nil {
		t.Fatal(err)
	}

	return path, secret
}

func writeRawFixture(t *testing.T, content string, mode os.FileMode) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), "raw.conf")
	if err := os.WriteFile(path, []byte(content), mode); err != nil {
		t.Fatal(err)
	}

	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}

	return path
}

func TestWGVaultStageAndRevoke(t *testing.T) {
	file, _ := writeVaultFixture(t, "vpn.example.com")

	vault := NewWireGuardConfigVault()
	defer vault.Close()

	staged, err := vault.StageFile(vaultProfileA, file)
	if err != nil {
		t.Fatal(err)
	}

	if staged.State != "staged_in_memory" || staged.NetworkReady || staged.Config.NetworkReady ||
		!strings.HasPrefix(staged.StageID, "wgstage_") || len(staged.StageID) != len("wgstage_")+32 {
		t.Fatalf("invalid stage status: %+v", staged)
	}

	got, err := vault.Status(vaultProfileA)
	if err != nil || got.StageID != staged.StageID {
		t.Fatalf("unexpected status: %+v; %v", got, err)
	}

	all, err := vault.List()
	if err != nil || len(all) != 1 {
		t.Fatalf("unexpected list: %v; %v", all, err)
	}

	saved := vault.entries[vaultProfileA].cfg

	if err := vault.Revoke(vaultProfileA); err != nil {
		t.Fatal(err)
	}

	if saved.privateKey != "" || saved.peerPresharedKey != "" || saved.addresses != nil {
		t.Fatal("references to keys not dropped")
	}

	if _, err := vault.Status(vaultProfileA); !errors.Is(err, ErrWGStageNotFound) {
		t.Fatalf("revoked stage still present: %v", err)
	}

	if err := vault.Revoke(vaultProfileA); !errors.Is(err, ErrWGStageNotFound) {
		t.Fatalf("second revoke returned %v", err)
	}
}

func TestWGVaultReplacementKeepsOldOnInvalidImport(t *testing.T) {
	first, _ := writeVaultFixture(t, "vpn.example.com")
	second, _ := writeVaultFixture(t, "other.example.com")

	vault := NewWireGuardConfigVault()
	defer vault.Close()

	old, err := vault.StageFile(vaultProfileA, first)
	if err != nil {
		t.Fatal(err)
	}

	oldPtr := vault.entries[vaultProfileA].cfg

	rejected := []string{
		writeRawFixture(t, "invalid", 0o600),
		writeRawFixture(t, "[Interface]\nPostUp = touch /tmp/x\n", 0o600),
		filepath.Join(t.TempDir(), "missing.conf"),
	}

	if runtime.GOOS != "windows" {
		readable, _ := writeVaultFixture(t, "readable.example.com")
		if err := os.Chmod(readable, 0o644); err != nil {
			t.Fatal(err)
		}
		rejected = append(rejected, readable)
	}

	for _, path := range rejected {
		if _, err := vault.StageFile(vaultProfileA, path); err == nil {
			t.Fatalf("%s accepted", path)
		}
	}

	current, err := vault.Status(vaultProfileA)
	if err != nil || current.StageID != old.StageID || current.Config.EndpointHost != "vpn.example.com" {
		t.Fatal("invalid import replaced old stage")
	}

	next, err := vault.StageFile(vaultProfileA, second)
	if err != nil {
		t.Fatal(err)
	}

	if next.StageID == old.StageID || next.Config.EndpointHost != "other.example.com" {
		t.Fatalf("replacement failed: %+v", next)
	}

	if oldPtr.privateKey != "" {
		t.Fatal("old key reference was retained")
	}
}

func TestWGVaultListIsSorted(t *testing.T) {
	file, _ := writeVaultFixture(t, "vpn.example.com")

	vault := NewWireGuardConfigVault()
	defer vault.Close()

	for _, profile := range []string{vaultProfileB, vaultProfileA} {
		if _, err := vault.StageFile(profile, file); err != nil {
			t.Fatal(err)
		}
	}

	all, err := vault.List()
	if err != nil || len(all) != 2 || all[0].ProfileID != vaultProfileA || all[1].ProfileID != vaultProfileB {
		t.Fatalf("unexpected list: %+v; %v", all, err)
	}

	if all[0].StageID == all[1].StageID {
		t.Fatal("stage IDs repeated across profiles")
	}
}

func TestWGVaultClosedAndInvalidProfile(t *testing.T) {
	file, _ := writeVaultFixture(t, "vpn.example.com")

	vault := NewWireGuardConfigVault()

	for _, profile := range []string{"bad-id", "profile_0123456789ABCDEF", ""} {
		if _, err := vault.StageFile(profile, file); err == nil {
			t.Fatalf("profile %q accepted", profile)
		}
	}

	if _, err := vault.StageFile(vaultProfileB, file); err != nil {
		t.Fatal(err)
	}

	saved := vault.entries[vaultProfileB].cfg

	vault.Close()
	vault.Close()

	if saved.privateKey != "" {
		t.Fatal("close kept key references")
	}

	if _, err := vault.Status(vaultProfileB); !errors.Is(err, ErrWGVaultClosed) {
		t.Fatalf("closed status returned %v", err)
	}

	if _, err := vault.StageFile(vaultProfileB, file); !errors.Is(err, ErrWGVaultClosed) {
		t.Fatalf("closed stage returned %v", err)
	}

	if err := vault.Revoke(vaultProfileB); !errors.Is(err, ErrWGVaultClosed) {
		t.Fatalf("closed revoke returned %v", err)
	}

	if _, err := vault.List(); !errors.Is(err, ErrWGVaultClosed) {
		t.Fatalf("closed list returned %v", err)
	}
}

func TestWGVaultNilReceiver(t *testing.T) {
	var vault *WireGuardConfigVault

	if _, err := vault.StageFile(vaultProfileA, "x"); err == nil {
		t.Fatal("nil vault staged a file")
	}

	if _, err := vault.Status(vaultProfileA); err == nil {
		t.Fatal("nil vault returned status")
	}

	if _, err := vault.List(); err == nil {
		t.Fatal("nil vault returned a list")
	}

	if err := vault.Revoke(vaultProfileA); err == nil {
		t.Fatal("nil vault revoked")
	}

	vault.Close()
}

func TestWGVaultSafeMetadataAndLogging(t *testing.T) {
	file, secret := writeVaultFixture(t, "vpn.example.com")

	vault := NewWireGuardConfigVault()
	defer vault.Close()

	status, err := vault.StageFile(vaultProfileA, file)
	if err != nil {
		t.Fatal(err)
	}

	payload, err := json.Marshal(status)
	if err != nil {
		t.Fatal(err)
	}

	if strings.Contains(string(payload), secret) || !strings.Contains(string(payload), `"network_ready":false`) {
		t.Fatalf("unsafe status payload: %s", payload)
	}

	for _, value := range []any{vault, map[string]any{"vault": vault}} {
		if payload, err := json.Marshal(value); err == nil {
			t.Fatalf("vault was serialized: %s", payload)
		}
	}

	output := ""
	for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%d", "%x"} {
		output += fmt.Sprintf(verb, vault)
	}

	if strings.Contains(output, secret) || !strings.Contains(output, "redacted") {
		t.Fatalf("unsafe vault formatting: %s", output)
	}
}

func TestWGVaultConcurrentReplacement(t *testing.T) {
	file, _ := writeVaultFixture(t, "vpn.example.com")

	vault := NewWireGuardConfigVault()
	defer vault.Close()

	const n = 8

	var wg sync.WaitGroup
	errs := make(chan error, 2*n)
	ids := make(chan string, n)

	for range n {
		wg.Add(2)

		go func() {
			defer wg.Done()

			status, err := vault.StageFile(vaultProfileA, file)
			errs <- err
			ids <- status.StageID
		}()

		go func() {
			defer wg.Done()

			if _, err := vault.Status(vaultProfileA); err != nil && !errors.Is(err, ErrWGStageNotFound) {
				errs <- err
			}
		}()
	}

	wg.Wait()
	close(errs)
	close(ids)

	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}

	seen := map[string]bool{}
	for id := range ids {
		if seen[id] {
			t.Fatalf("stage ID %s issued twice", id)
		}
		seen[id] = true
	}

	all, err := vault.List()
	if err != nil || len(all) != 1 || all[0].NetworkReady || !seen[all[0].StageID] {
		t.Fatalf("unexpected concurrent state: %+v, %v", all, err)
	}
}
