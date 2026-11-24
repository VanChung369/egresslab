package agent

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
)

type storePaths struct {
	data string
	key  string
}

func newStorePaths(t *testing.T) storePaths {
	t.Helper()

	root := t.TempDir()
	paths := storePaths{
		data: filepath.Join(root, "data", "wg-vault.json"),
		key:  filepath.Join(root, "keys", "wg-vault.key"),
	}

	if err := GenerateVaultKeyFile(paths.key); err != nil {
		t.Fatal(err)
	}

	return paths
}

func openStore(t *testing.T, paths storePaths) *SealedWireGuardStore {
	t.Helper()

	store, err := OpenSealedWireGuardStore(paths.data, paths.key)
	if err != nil {
		t.Fatal(err)
	}

	return store
}

func TestRenderWireGuardConfigRoundTrips(t *testing.T) {
	src := strings.Replace(demoConfig(), "PersistentKeepalive = 25",
		"PersistentKeepalive = 25\nPresharedKey = "+demoKey(3), 1)
	original := mustParse(t, src)

	rendered := renderWireGuardConfig(original)
	defer clear(rendered)

	again, err := parseWireGuardBytes(rendered)
	if err != nil {
		t.Fatalf("rendered config does not re-parse: %v\n%s", err, rendered)
	}

	if !reflect.DeepEqual(original.Summary(), again.Summary()) ||
		!bytes.Equal(original.privateKey, again.privateKey) ||
		!bytes.Equal(original.peerPresharedKey, again.peerPresharedKey) ||
		original.peerPublicKey != again.peerPublicKey {
		t.Fatal("round trip changed the config")
	}

	ipv6 := mustParse(t, replaced("vpn.example.com:51820", "[2001:db8::42]:51820"))
	if _, err := parseWireGuardBytes(renderWireGuardConfig(ipv6)); err != nil {
		t.Fatalf("IPv6 endpoint does not round trip: %v", err)
	}
}

func TestPersistentVaultSurvivesRestartEncrypted(t *testing.T) {
	paths := newStorePaths(t)
	configPath, secret := writeVaultFixture(t, "198.51.100.7")

	vault, err := OpenPersistentWireGuardConfigVault(openStore(t, paths))
	if err != nil {
		t.Fatal(err)
	}

	staged, err := vault.StageFile(vaultProfileA, configPath)
	if err != nil {
		t.Fatal(err)
	}

	if staged.State != "staged_encrypted_at_rest" {
		t.Fatalf("unexpected state %q", staged.State)
	}

	vault.Close()

	raw, err := os.ReadFile(paths.data)
	if err != nil {
		t.Fatal(err)
	}

	if bytes.Contains(raw, []byte(secret)) || bytes.Contains(raw, []byte("PrivateKey")) ||
		bytes.Contains(raw, []byte("198.51.100.7")) {
		t.Fatal("store file contains plaintext config data")
	}

	if runtime.GOOS != "windows" {
		for _, path := range []string{paths.data, paths.key} {
			info, err := os.Stat(path)
			if err != nil || info.Mode().Perm() != 0o600 {
				t.Fatalf("%s mode %v %v", path, info.Mode().Perm(), err)
			}
		}
	}

	reopened, err := OpenPersistentWireGuardConfigVault(openStore(t, paths))
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()

	status, err := reopened.Status(vaultProfileA)
	if err != nil || status.StageID != staged.StageID || status.Config.EndpointHost != "198.51.100.7" {
		t.Fatalf("stage not restored: %+v %v", status, err)
	}

	if err := reopened.Revoke(vaultProfileA); err != nil {
		t.Fatal(err)
	}

	empty, err := OpenPersistentWireGuardConfigVault(openStore(t, paths))
	if err != nil {
		t.Fatal(err)
	}

	if _, err := empty.Status(vaultProfileA); !errors.Is(err, ErrWGStageNotFound) {
		t.Fatalf("revocation not persisted: %v", err)
	}
}

func TestSealedStoreRejectsWrongKeyAndTampering(t *testing.T) {
	paths := newStorePaths(t)
	configPath, _ := writeVaultFixture(t, "198.51.100.7")

	vault, err := OpenPersistentWireGuardConfigVault(openStore(t, paths))
	if err != nil {
		t.Fatal(err)
	}

	for _, profile := range []string{vaultProfileA, vaultProfileB} {
		if _, err := vault.StageFile(profile, configPath); err != nil {
			t.Fatal(err)
		}
	}
	vault.Close()

	original, err := os.ReadFile(paths.data)
	if err != nil {
		t.Fatal(err)
	}

	otherKey := filepath.Join(t.TempDir(), "other", "wg-vault.key")
	if err := GenerateVaultKeyFile(otherKey); err != nil {
		t.Fatal(err)
	}

	wrong, err := OpenSealedWireGuardStore(paths.data, otherKey)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := OpenPersistentWireGuardConfigVault(wrong); !errors.Is(err, ErrSealedStoreCorrupt) {
		t.Fatalf("wrong key accepted: %v", err)
	}

	var file sealedStoreFile
	if err := json.Unmarshal(original, &file); err != nil {
		t.Fatal(err)
	}

	tamper := map[string]func(f *sealedStoreFile){
		"swapped profiles": func(f *sealedStoreFile) {
			f.Entries[0].ProfileID, f.Entries[1].ProfileID = f.Entries[1].ProfileID, f.Entries[0].ProfileID
		},
		"flipped ciphertext": func(f *sealedStoreFile) {
			c := []byte(f.Entries[0].Ciphertext)
			if c[10] == 'A' {
				c[10] = 'B'
			} else {
				c[10] = 'A'
			}
			f.Entries[0].Ciphertext = string(c)
		},
		"changed stage id": func(f *sealedStoreFile) { f.Entries[0].StageID = "wgstage_" + strings.Repeat("0", 32) },
		"version":          func(f *sealedStoreFile) { f.Version = 2 },
		"duplicate profile": func(f *sealedStoreFile) {
			f.Entries[1] = f.Entries[0]
		},
	}

	for name, change := range tamper {
		t.Run(name, func(t *testing.T) {
			copied := sealedStoreFile{Version: file.Version, Entries: append([]sealedStoreEntry(nil), file.Entries...)}
			change(&copied)

			data, err := json.Marshal(copied)
			if err != nil {
				t.Fatal(err)
			}

			if err := os.WriteFile(paths.data, data, 0o600); err != nil {
				t.Fatal(err)
			}

			if _, err := OpenPersistentWireGuardConfigVault(openStore(t, paths)); !errors.Is(err, ErrSealedStoreCorrupt) {
				t.Fatalf("tampered store accepted: %v", err)
			}
		})
	}
}

func TestSealedStoreKeyRules(t *testing.T) {
	root := t.TempDir()
	key := filepath.Join(root, "keys", "wg.key")

	if err := GenerateVaultKeyFile(key); err != nil {
		t.Fatal(err)
	}

	if err := GenerateVaultKeyFile(key); err == nil {
		t.Fatal("existing key file overwritten")
	}

	if _, err := OpenSealedWireGuardStore(filepath.Join(root, "keys", "vault.json"), key); err == nil {
		t.Fatal("data file next to the key accepted")
	}

	short := filepath.Join(root, "short", "wg.key")
	if err := os.MkdirAll(filepath.Dir(short), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(short, []byte("too short"), 0o600); err != nil {
		t.Fatal(err)
	}

	if _, err := OpenSealedWireGuardStore(filepath.Join(root, "data", "vault.json"), short); err == nil {
		t.Fatal("short key accepted")
	}

	if runtime.GOOS != "windows" {
		if err := os.Chmod(key, 0o644); err != nil {
			t.Fatal(err)
		}

		if _, err := OpenSealedWireGuardStore(filepath.Join(root, "data", "vault.json"), key); err == nil {
			t.Fatal("world-readable key accepted")
		}
	}
}

func TestPersistFailureLeavesVaultUnchanged(t *testing.T) {
	paths := newStorePaths(t)
	configPath, _ := writeVaultFixture(t, "198.51.100.7")

	store := openStore(t, paths)
	vault, err := OpenPersistentWireGuardConfigVault(store)
	if err != nil {
		t.Fatal(err)
	}

	first, err := vault.StageFile(vaultProfileA, configPath)
	if err != nil {
		t.Fatal(err)
	}

	// Make the data path unwritable by turning its directory into a file.
	if err := os.RemoveAll(filepath.Dir(paths.data)); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Dir(paths.data), nil, 0o600); err != nil {
		t.Fatal(err)
	}

	if _, err := vault.StageFile(vaultProfileA, configPath); err == nil {
		t.Fatal("restage succeeded without persisting")
	}

	if status, err := vault.Status(vaultProfileA); err != nil || status.StageID != first.StageID {
		t.Fatalf("failed restage replaced the stage: %+v %v", status, err)
	}

	if err := vault.Revoke(vaultProfileA); err == nil {
		t.Fatal("revoke succeeded without persisting")
	}

	if _, err := vault.Status(vaultProfileA); err != nil {
		t.Fatal("failed revoke removed the stage from memory")
	}
}

func TestSealedStoreRefusesOversizedWrite(t *testing.T) {
	paths := newStorePaths(t)
	store := openStore(t, paths)
	cfg := vpnTestConfig(t)
	stage := "wgstage_" + strings.Repeat("a", 32)

	if err := store.save(map[string]wireGuardStage{vaultProfileA: {id: stage, cfg: cfg}}); err != nil {
		t.Fatal(err)
	}

	before, err := os.ReadFile(paths.data)
	if err != nil {
		t.Fatal(err)
	}

	// An entry takes about 540 bytes, so 10000 of them pass the 4 MiB that load accepts.
	large := make(map[string]wireGuardStage, 10000)
	for i := range 10000 {
		large[fmt.Sprintf("profile_%016x", i)] = wireGuardStage{id: stage, cfg: cfg}
	}

	if err := store.save(large); err == nil || !strings.Contains(err.Error(), "exceed") {
		t.Fatalf("oversized store written: %v", err)
	}

	after, err := os.ReadFile(paths.data)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatalf("store file changed: %v", err)
	}

	if entries, err := store.load(); err != nil || len(entries) != 1 {
		t.Fatalf("store no longer opens: %d %v", len(entries), err)
	}
}

func TestVaultStillRefusesJSON(t *testing.T) {
	paths := newStorePaths(t)

	vault, err := OpenPersistentWireGuardConfigVault(openStore(t, paths))
	if err != nil {
		t.Fatal(err)
	}

	if _, err := json.Marshal(vault); err == nil {
		t.Fatal("persistent vault serialized to JSON")
	}
}
