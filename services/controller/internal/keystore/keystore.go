// Package keystore keeps the controller's Ed25519 signing seed in the platform's secret storage:
// DPAPI on Windows, the login Keychain on macOS, a 0600 file elsewhere. Only the public key and
// signatures leave it.
package keystore

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
)

var (
	ErrKeyExists = errors.New("signing key already exists; it is never replaced")
	ErrNoKey     = errors.New("signing key not initialized; run init-key")
)

type KeyStore interface {
	Initialize() error
	PublicKey() (ed25519.PublicKey, error)
	Sign(message []byte) ([]byte, error)
}

// seedStore is the platform part. create must return ErrKeyExists rather than replace a seed;
// load returns ErrNoKey when there is none.
type seedStore interface {
	create(seed []byte) error
	load() ([]byte, error)
}

// Open returns the platform key store for the controller data directory.
func Open(dataDir string) (KeyStore, error) {
	store, err := platformStore(dataDir)
	if err != nil {
		return nil, err
	}

	return seedKeyStore{store}, nil
}

// Backend names the platform storage, for messages.
func Backend() string { return backendName }

type seedKeyStore struct{ store seedStore }

func (k seedKeyStore) Initialize() error {
	seed := make([]byte, ed25519.SeedSize)
	defer clear(seed)

	if _, err := rand.Read(seed); err != nil {
		return err
	}

	return k.store.create(seed)
}

func (k seedKeyStore) withKey(use func(ed25519.PrivateKey)) error {
	seed, err := k.store.load()
	if err != nil {
		return err
	}
	defer clear(seed)

	if len(seed) != ed25519.SeedSize {
		return errors.New("invalid stored signing seed")
	}

	private := ed25519.NewKeyFromSeed(seed)
	defer clear(private)

	use(private)

	return nil
}

func (k seedKeyStore) PublicKey() (ed25519.PublicKey, error) {
	var public ed25519.PublicKey

	err := k.withKey(func(private ed25519.PrivateKey) {
		public = append(ed25519.PublicKey(nil), private.Public().(ed25519.PublicKey)...)
	})

	return public, err
}

func (k seedKeyStore) Sign(message []byte) ([]byte, error) {
	var signature []byte

	err := k.withKey(func(private ed25519.PrivateKey) {
		signature = ed25519.Sign(private, message)
	})

	return signature, err
}
