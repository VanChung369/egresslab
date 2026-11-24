//go:build unix && !darwin

package keystore

import (
	"crypto/ed25519"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestFileKeyStore(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "data")

	keys, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := keys.PublicKey(); !errors.Is(err, ErrNoKey) {
		t.Fatalf("before init: %v", err)
	}

	if err := keys.Initialize(); err != nil {
		t.Fatal(err)
	}

	path := filepath.Join(dir, keyFileName)

	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("key file mode: %v %v", info.Mode(), err)
	}

	public, err := keys.PublicKey()
	if err != nil {
		t.Fatal(err)
	}

	signature, err := keys.Sign([]byte("message"))
	if err != nil || !ed25519.Verify(public, []byte("message"), signature) {
		t.Fatalf("signature: %v", err)
	}

	if err := keys.Initialize(); !errors.Is(err, ErrKeyExists) {
		t.Fatalf("existing key overwritten: %v", err)
	}

	if again, err := keys.PublicKey(); err != nil || string(again) != string(public) {
		t.Fatalf("key changed after a refused init: %v", err)
	}
}

func TestFileKeyStoreRejectsUnsafeFiles(t *testing.T) {
	setup := func(t *testing.T) (KeyStore, string) {
		t.Helper()

		dir := filepath.Join(t.TempDir(), "data")
		keys, err := Open(dir)
		if err != nil {
			t.Fatal(err)
		}

		if err := keys.Initialize(); err != nil {
			t.Fatal(err)
		}

		return keys, dir
	}

	cases := map[string]func(t *testing.T, dir string){
		"group-readable key": func(t *testing.T, dir string) {
			chmod(t, filepath.Join(dir, keyFileName), 0o640)
		},
		"world-writable directory": func(t *testing.T, dir string) {
			chmod(t, dir, 0o777)
		},
		"symlinked key": func(t *testing.T, dir string) {
			path := filepath.Join(dir, keyFileName)
			if err := os.Rename(path, path+".real"); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(path+".real", path); err != nil {
				t.Fatal(err)
			}
		},
		"truncated key": func(t *testing.T, dir string) {
			write(t, filepath.Join(dir, keyFileName), strings.Repeat("ab", 16)+"\n")
		},
		"non-hex key": func(t *testing.T, dir string) {
			write(t, filepath.Join(dir, keyFileName), strings.Repeat("zz", 32)+"\n")
		},
		"oversized key": func(t *testing.T, dir string) {
			write(t, filepath.Join(dir, keyFileName), strings.Repeat("ab", 32)+"\n\n\n")
		},
	}

	for name, damage := range cases {
		t.Run(name, func(t *testing.T) {
			keys, dir := setup(t)
			damage(t, dir)

			if _, err := keys.Sign([]byte("m")); err == nil {
				t.Fatal("unsafe key file used")
			}
		})
	}
}

func chmod(t *testing.T, path string, mode os.FileMode) {
	t.Helper()

	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
}

func write(t *testing.T, path, content string) {
	t.Helper()

	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}
