//go:build linux

package main

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/VanChung369/egresslab/services/network-agent/internal/helperipc"
)

const vaultTestProfile = "profile_0123456789abcdef"

// testLayout builds root/etc/vault and root/var/vault, owned by the current user.
func testLayout(t *testing.T) vaultLayout {
	t.Helper()

	root := t.TempDir()
	l := vaultLayout{
		keyDir:  filepath.Join(root, "etc", "vault"),
		dataDir: filepath.Join(root, "var", "vault"),
		root:    root,
		owner:   uint32(os.Getuid()),
	}

	for _, dir := range []string{l.keyDir, l.dataDir} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}

	return l
}

// writeImport writes a single-peer config with an IPv4 endpoint and returns its private key.
func writeImport(t *testing.T, l vaultLayout) string {
	t.Helper()

	key := func() string {
		raw := make([]byte, 32)
		if _, err := rand.Read(raw); err != nil {
			t.Fatal(err)
		}
		return base64.StdEncoding.EncodeToString(raw)
	}

	private := key()
	config := fmt.Sprintf("[Interface]\nPrivateKey = %s\nAddress = 10.2.0.2/32\n\n[Peer]\nPublicKey = %s\n"+
		"Endpoint = 198.51.100.7:51820\nAllowedIPs = 0.0.0.0/0, ::/0\n", private, key())

	writeMode(t, l.importPath(), config, 0o600)

	return private
}

func writeMode(t *testing.T, path, content string, mode os.FileMode) {
	t.Helper()

	if err := os.WriteFile(path, []byte(content), mode); err != nil {
		t.Fatal(err)
	}

	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
}

func stageViaAdmin(t *testing.T, l vaultLayout) (helperipc.StageInfo, string) {
	t.Helper()

	var out bytes.Buffer
	if err := l.admin([]string{"vault-stage", vaultTestProfile}, &out); err != nil {
		t.Fatal(err)
	}

	var info helperipc.StageInfo
	if err := json.Unmarshal(out.Bytes(), &info); err != nil {
		t.Fatalf("stage output: %v", err)
	}

	return info, out.String()
}

func TestVaultInitStageRevoke(t *testing.T) {
	l := testLayout(t)
	var out bytes.Buffer

	if err := l.admin([]string{"vault-init"}, &out); err != nil || !strings.Contains(out.String(), "initialized") {
		t.Fatalf("init: %v %s", err, out.String())
	}

	if info, err := os.Stat(l.keyPath()); err != nil || info.Mode().Perm() != 0o600 || info.Size() != 32 {
		t.Fatalf("key file: %v", err)
	}

	if err := l.admin([]string{"vault-init"}, &out); err == nil || !strings.Contains(err.Error(), "already initialized") {
		t.Fatalf("second init: %v", err)
	}

	if err := l.admin([]string{"vault-stage", vaultTestProfile}, &out); err == nil || !strings.Contains(err.Error(), "missing") {
		t.Fatalf("stage without import: %v", err)
	}

	private := writeImport(t, l)
	first, printed := stageViaAdmin(t, l)

	if first.ProfileID != vaultTestProfile || !first.Compatible || !strings.HasPrefix(first.StageID, "wgstage_") {
		t.Fatalf("stage info: %+v", first)
	}

	if strings.Contains(printed, private) || strings.Contains(printed, "198.51.100.7") || strings.Contains(printed, "10.2.0.2") {
		t.Fatal("stage output reveals the config")
	}

	if _, err := os.Lstat(l.importPath()); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("plaintext import kept after staging")
	}

	stored, err := os.ReadFile(l.dataPath())
	if err != nil || bytes.Contains(stored, []byte(private)) || bytes.Contains(stored, []byte("198.51.100.7")) {
		t.Fatalf("store holds plaintext: %v", err)
	}

	writeImport(t, l)
	second, _ := stageViaAdmin(t, l)
	if second.StageID == first.StageID {
		t.Fatal("re-staging kept the stage ID")
	}

	// A failed stage keeps the import for the operator to fix.
	writeMode(t, l.importPath(), "[Interface]\nPrivateKey = broken\n", 0o600)
	if err := l.admin([]string{"vault-stage", vaultTestProfile}, &out); err == nil || !strings.Contains(err.Error(), "staging failed") {
		t.Fatalf("bad config staged: %v", err)
	}

	if _, err := os.Lstat(l.importPath()); err != nil {
		t.Fatal("failed import removed")
	}

	vault, err := l.open()
	if err != nil {
		t.Fatal(err)
	}

	if info, err := vault.readStage(vaultTestProfile); err != nil || info != second {
		t.Fatalf("reopened stage: %+v %v", info, err)
	}

	vault.Close()

	if err := l.admin([]string{"vault-revoke", vaultTestProfile}, &out); err != nil {
		t.Fatal(err)
	}

	vault, err = l.open()
	if err != nil {
		t.Fatal(err)
	}
	defer vault.Close()

	if _, err := vault.readStage(vaultTestProfile); !errors.Is(err, helperipc.ErrStageNotFound) {
		t.Fatalf("revoked stage: %v", err)
	}
}

func TestVaultLockIsExclusive(t *testing.T) {
	l := testLayout(t)
	if err := l.initialize(); err != nil {
		t.Fatal(err)
	}

	vault, err := l.open()
	if err != nil {
		t.Fatal(err)
	}

	writeImport(t, l)

	for _, args := range [][]string{{"vault-init"}, {"vault-stage", vaultTestProfile}, {"vault-revoke", vaultTestProfile}} {
		if err := l.admin(args, &bytes.Buffer{}); err == nil || !strings.Contains(err.Error(), "vault is in use") {
			t.Fatalf("%q while the vault is open: %v", args, err)
		}
	}

	if _, err := os.Lstat(l.importPath()); err != nil {
		t.Fatal("refused stage touched the import")
	}

	vault.Close()

	lock, err := l.lock()
	if err != nil {
		t.Fatalf("lock not released on close: %v", err)
	}
	lock.Close()
}

func TestVaultLayoutRejectsUnsafeFiles(t *testing.T) {
	initialized := func(t *testing.T) vaultLayout {
		t.Helper()
		l := testLayout(t)
		if err := l.initialize(); err != nil {
			t.Fatal(err)
		}
		return l
	}

	cases := map[string]struct {
		setup func(t *testing.T) vaultLayout
		want  string
	}{
		"vault directory 0755": {func(t *testing.T) vaultLayout {
			l := initialized(t)
			chmod(t, l.dataDir, 0o755)
			return l
		}, "mode 0700"},
		"group-writable ancestor": {func(t *testing.T) vaultLayout {
			l := initialized(t)
			chmod(t, filepath.Dir(l.keyDir), 0o775)
			return l
		}, "unsafe vault directory"},
		"symlinked data directory": {func(t *testing.T) vaultLayout {
			l := initialized(t)
			moved := l.dataDir + ".real"
			if err := os.Rename(l.dataDir, moved); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(moved, l.dataDir); err != nil {
				t.Fatal(err)
			}
			return l
		}, "unsafe vault directory"},
		"key file 0644": {func(t *testing.T) vaultLayout {
			l := initialized(t)
			chmod(t, l.keyPath(), 0o644)
			return l
		}, "mode 0600"},
		"hard-linked key": {func(t *testing.T) vaultLayout {
			l := initialized(t)
			if err := os.Link(l.keyPath(), filepath.Join(l.keyDir, "copy")); err != nil {
				t.Fatal(err)
			}
			return l
		}, "hard links"},
		"symlinked lock": {func(t *testing.T) vaultLayout {
			l := initialized(t)
			if err := os.Remove(l.lockPath()); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(filepath.Join(l.dataDir, "elsewhere"), l.lockPath()); err != nil {
				t.Fatal(err)
			}
			return l
		}, "symbolic links"},
		"another owner": {func(t *testing.T) vaultLayout {
			l := initialized(t)
			l.owner++
			return l
		}, "unsafe vault directory"},
		// The walk passes the stop root and reaches /tmp (mode 1777), which is refused.
		"outside the root": {func(t *testing.T) vaultLayout {
			l := initialized(t)
			l.root = filepath.Join(l.root, "elsewhere")
			return l
		}, "unsafe vault directory"},
	}

	for name, tt := range cases {
		t.Run(name, func(t *testing.T) {
			l := tt.setup(t)

			if _, err := l.open(); err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("got %v, want %q", err, tt.want)
			}
		})
	}
}

func TestVaultAdminUsage(t *testing.T) {
	l := testLayout(t)

	for _, args := range [][]string{
		{"vault-stage"},
		{"vault-stage", "profile_x"},
		{"vault-export", vaultTestProfile},
		{"vault-init", "extra"},
	} {
		if err := l.admin(args, &bytes.Buffer{}); err == nil || !strings.Contains(err.Error(), "usage") {
			t.Errorf("%q: %v", args, err)
		}
	}
}

func chmod(t *testing.T, path string, mode os.FileMode) {
	t.Helper()

	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
}
