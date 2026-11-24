//go:build windows

package keystore

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestDPAPIKeyStore(t *testing.T) {
	dir := t.TempDir()

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

	store := dpapiStore{path: filepath.Join(dir, dpapiFileName)}

	first, err := store.load()
	if err != nil {
		t.Fatal(err)
	}
	defer clear(first)

	protected, err := os.ReadFile(store.path)
	if err != nil {
		t.Fatal(err)
	}

	if len(first) != ed25519.SeedSize || bytes.Contains(protected, first) {
		t.Fatal("plaintext seed found in the protected file")
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

	again, err := store.load()
	if err != nil || !bytes.Equal(first, again) {
		t.Fatalf("seed changed after a refused init: %v", err)
	}

	if err := os.WriteFile(store.path, []byte("invalid protected data"), 0o600); err != nil {
		t.Fatal(err)
	}

	if _, err := keys.PublicKey(); err == nil {
		t.Fatal("corrupt protected key accepted")
	}

	if _, err := Open("relative"); err == nil {
		t.Fatal("relative data directory accepted")
	}
}
