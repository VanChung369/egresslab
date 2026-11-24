package keystore

import (
	"crypto/ed25519"
	"errors"
	"testing"
)

type memoryStore struct{ seed []byte }

func (m *memoryStore) create(seed []byte) error {
	if m.seed != nil {
		return ErrKeyExists
	}

	m.seed = append([]byte(nil), seed...)

	return nil
}

func (m *memoryStore) load() ([]byte, error) {
	if m.seed == nil {
		return nil, ErrNoKey
	}

	return append([]byte(nil), m.seed...), nil
}

func TestSeedKeyStore(t *testing.T) {
	store := &memoryStore{}
	keys := seedKeyStore{store}

	if _, err := keys.PublicKey(); !errors.Is(err, ErrNoKey) {
		t.Fatalf("public key before init: %v", err)
	}

	if _, err := keys.Sign([]byte("m")); !errors.Is(err, ErrNoKey) {
		t.Fatalf("sign before init: %v", err)
	}

	if err := keys.Initialize(); err != nil {
		t.Fatal(err)
	}

	first := append([]byte(nil), store.seed...)

	if err := keys.Initialize(); !errors.Is(err, ErrKeyExists) {
		t.Fatalf("second init: %v", err)
	}

	if string(store.seed) != string(first) {
		t.Fatal("seed replaced")
	}

	public, err := keys.PublicKey()
	if err != nil || len(public) != ed25519.PublicKeySize {
		t.Fatalf("public key: %v", err)
	}

	signature, err := keys.Sign([]byte("message"))
	if err != nil || !ed25519.Verify(public, []byte("message"), signature) {
		t.Fatalf("signature does not verify: %v", err)
	}

	store.seed = store.seed[:10]
	if _, err := keys.Sign([]byte("m")); err == nil {
		t.Fatal("truncated seed used")
	}
}
