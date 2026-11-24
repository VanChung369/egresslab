//go:build darwin

package keystore

import (
	"crypto/ed25519"
	"errors"
	"os"
	"os/exec"
	"testing"
)

// Opt-in: CI keychains can be locked and prompt. Run with EGRESSLAB_TEST_KEYCHAIN=1.
func TestKeychainKeyStore(t *testing.T) {
	if os.Getenv("EGRESSLAB_TEST_KEYCHAIN") != "1" {
		t.Skip("set EGRESSLAB_TEST_KEYCHAIN=1 to use the login Keychain")
	}

	dir := t.TempDir()

	store, err := platformStore(dir)
	if err != nil {
		t.Fatal(err)
	}

	account := store.(keychainStore).account
	t.Cleanup(func() {
		_ = exec.Command(securityPath, "delete-generic-password", "-a", account, "-s", keychainService).Run()
	})

	keys := seedKeyStore{store}

	if _, err := keys.PublicKey(); !errors.Is(err, ErrNoKey) {
		t.Fatalf("before init: %v", err)
	}

	if err := keys.Initialize(); err != nil {
		t.Fatal(err)
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
		t.Fatalf("existing key replaced: %v", err)
	}

	if again, err := keys.PublicKey(); err != nil || string(again) != string(public) {
		t.Fatalf("key changed: %v", err)
	}
}
