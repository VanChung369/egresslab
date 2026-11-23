package agent

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strconv"
)

// SealedWireGuardStore is the opt-in persistent backend for WireGuardConfigVault. Each staged
// config is encrypted with AES-256-GCM under a 32-byte key read from a separate 0600 key file.
// The profile and stage IDs are bound as associated data, so entries cannot be swapped between
// profiles. Nothing is persisted unless a caller opens a store explicitly.
//
// Threat model: this protects configs at rest (backups, copies of the data directory, another
// unprivileged user). It does not protect against root on the VM, which can read the key file.
const (
	sealedStoreVersion  = 1
	vaultKeyBytes       = 32
	maxSealedStoreBytes = 4 << 20
	sealedStoreAADLabel = "egresslab/wg-vault/v1"
	renderedConfigCap   = 16 << 10
)

var ErrSealedStoreCorrupt = errors.New("sealed WireGuard store cannot be decrypted or is malformed")

type SealedWireGuardStore struct {
	path string
	aead cipher.AEAD
}

type sealedStoreFile struct {
	Version int                `json:"version"`
	Entries []sealedStoreEntry `json:"entries"`
}

type sealedStoreEntry struct {
	ProfileID  string `json:"profile_id"`
	StageID    string `json:"stage_id"`
	Nonce      string `json:"nonce"`
	Ciphertext string `json:"ciphertext"`
}

func (*SealedWireGuardStore) String() string { return "<sealed WireGuard store>" }

// GenerateVaultKeyFile creates a new random key file readable only by its owner. It never
// overwrites an existing file.
func GenerateVaultKeyFile(path string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}

	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("create vault key file: %w", err)
	}

	var key [vaultKeyBytes]byte
	defer clear(key[:])

	if _, err := rand.Read(key[:]); err != nil {
		file.Close()
		os.Remove(path)
		return fmt.Errorf("generate vault key: %w", err)
	}

	err = errors.Join(writeAll(file, key[:]), file.Sync(), file.Close())
	if err != nil {
		os.Remove(path)
		return fmt.Errorf("write vault key file: %w", err)
	}

	return nil
}

// OpenSealedWireGuardStore opens (or prepares) the encrypted store at dataPath. The key file must
// already exist, be 0600 and live in a different directory than the data file.
func OpenSealedWireGuardStore(dataPath, keyPath string) (*SealedWireGuardStore, error) {
	dataPath, keyPath = filepath.Clean(dataPath), filepath.Clean(keyPath)

	if dataPath == "." || keyPath == "." || dataPath == keyPath {
		return nil, errors.New("sealed store needs distinct data and key paths")
	}

	if filepath.Dir(dataPath) == filepath.Dir(keyPath) {
		return nil, errors.New("keep the vault key file outside the data directory")
	}

	key, err := readPrivateFile(keyPath, vaultKeyBytes+1)
	if err != nil {
		return nil, fmt.Errorf("read vault key: %w", err)
	}
	defer clear(key)

	if len(key) != vaultKeyBytes {
		return nil, fmt.Errorf("vault key file must contain exactly %d bytes", vaultKeyBytes)
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	return &SealedWireGuardStore{path: dataPath, aead: aead}, nil
}

func sealedAAD(profileID, stageID string) []byte {
	return []byte(sealedStoreAADLabel + "\x00" + profileID + "\x00" + stageID)
}

// load decrypts every entry. Any malformed or undecryptable entry fails the whole load.
func (s *SealedWireGuardStore) load() (map[string]wireGuardStage, error) {
	entries := make(map[string]wireGuardStage)

	data, err := readPrivateFile(s.path, maxSealedStoreBytes)
	if errors.Is(err, os.ErrNotExist) {
		return entries, nil
	}

	if err != nil {
		return nil, fmt.Errorf("read sealed store: %w", err)
	}

	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()

	var file sealedStoreFile
	if err := decoder.Decode(&file); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrSealedStoreCorrupt, err)
	}

	var extra json.RawMessage
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("%w: trailing data", ErrSealedStoreCorrupt)
	}

	if file.Version != sealedStoreVersion {
		return nil, fmt.Errorf("%w: unsupported version %d", ErrSealedStoreCorrupt, file.Version)
	}

	fail := func(format string, args ...any) (map[string]wireGuardStage, error) {
		for _, stage := range entries {
			releaseWireGuardConfig(stage.cfg)
		}

		return nil, fmt.Errorf("%w: "+format, append([]any{ErrSealedStoreCorrupt}, args...)...)
	}

	for i, entry := range file.Entries {
		if !profileIDPattern.MatchString(entry.ProfileID) || !stageIDPattern.MatchString(entry.StageID) {
			return fail("entry %d has invalid IDs", i)
		}

		if _, dup := entries[entry.ProfileID]; dup {
			return fail("entry %d duplicates a profile", i)
		}

		nonce, err := base64.StdEncoding.DecodeString(entry.Nonce)
		if err != nil || len(nonce) != s.aead.NonceSize() {
			return fail("entry %d has an invalid nonce", i)
		}

		ciphertext, err := base64.StdEncoding.DecodeString(entry.Ciphertext)
		if err != nil {
			return fail("entry %d has invalid ciphertext encoding", i)
		}

		plain, err := s.aead.Open(nil, nonce, ciphertext, sealedAAD(entry.ProfileID, entry.StageID))
		if err != nil {
			return fail("entry %d does not decrypt with this key", i)
		}

		cfg, err := parseWireGuardBytes(plain)
		clear(plain)

		if err != nil {
			return fail("entry %d: %v", i, err)
		}

		entries[entry.ProfileID] = wireGuardStage{id: entry.StageID, cfg: cfg}
	}

	return entries, nil
}

// save encrypts every entry with a fresh nonce and atomically replaces the store file.
func (s *SealedWireGuardStore) save(entries map[string]wireGuardStage) error {
	file := sealedStoreFile{Version: sealedStoreVersion, Entries: []sealedStoreEntry{}}

	for profileID, stage := range entries {
		nonce := make([]byte, s.aead.NonceSize())
		if _, err := rand.Read(nonce); err != nil {
			return fmt.Errorf("generate nonce: %w", err)
		}

		plain := renderWireGuardConfig(stage.cfg)
		ciphertext := s.aead.Seal(nil, nonce, plain, sealedAAD(profileID, stage.id))
		clear(plain)

		file.Entries = append(file.Entries, sealedStoreEntry{
			ProfileID:  profileID,
			StageID:    stage.id,
			Nonce:      base64.StdEncoding.EncodeToString(nonce),
			Ciphertext: base64.StdEncoding.EncodeToString(ciphertext),
		})
	}

	sort.Slice(file.Entries, func(i, j int) bool { return file.Entries[i].ProfileID < file.Entries[j].ProfileID })

	data, err := json.MarshalIndent(file, "", "  ")
	if err != nil {
		return err
	}

	return writePrivateFile(s.path, append(data, '\n'))
}

// renderWireGuardConfig produces a config that parseWireGuardBytes accepts and that is equivalent
// to cfg. It appends into one pre-sized buffer (no reallocation leaves stray key copies); the
// caller must clear the result.
func renderWireGuardConfig(cfg *ImportedWireGuardConfig) []byte {
	out := make([]byte, 0, renderedConfigCap)

	line := func(key string, value []byte) {
		out = append(out, key...)
		out = append(out, " = "...)
		out = append(out, value...)
		out = append(out, '\n')
	}

	list := func(key string, values []string) {
		if len(values) == 0 {
			return
		}

		joined := []byte{}
		for i, value := range values {
			if i > 0 {
				joined = append(joined, ", "...)
			}
			joined = append(joined, value...)
		}

		line(key, joined)
	}

	out = append(out, "[Interface]\n"...)
	line("PrivateKey", cfg.privateKey)

	addresses := make([]string, len(cfg.addresses))
	for i, a := range cfg.addresses {
		addresses[i] = a.String()
	}
	list("Address", addresses)

	dns := make([]string, len(cfg.dns))
	for i, a := range cfg.dns {
		dns[i] = a.String()
	}
	list("DNS", dns)

	if cfg.mtu > 0 {
		line("MTU", []byte(strconv.Itoa(cfg.mtu)))
	}

	out = append(out, "\n[Peer]\n"...)
	line("PublicKey", []byte(cfg.peerPublicKey))

	if len(cfg.peerPresharedKey) != 0 {
		line("PresharedKey", cfg.peerPresharedKey)
	}

	allowed := make([]string, len(cfg.allowedIPs))
	for i, p := range cfg.allowedIPs {
		allowed[i] = p.String()
	}
	list("AllowedIPs", allowed)

	line("Endpoint", []byte(net.JoinHostPort(cfg.endpointHost, strconv.Itoa(int(cfg.endpointPort)))))

	if cfg.keepalive > 0 {
		line("PersistentKeepalive", []byte(strconv.Itoa(int(cfg.keepalive))))
	}

	return out
}
