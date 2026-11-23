package agent

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"regexp"
	"sort"
	"sync"
)

var stageIDPattern = regexp.MustCompile(`^wgstage_[0-9a-f]{32}$`)

var (
	ErrWGVaultClosed   = errors.New("WireGuard vault is closed")
	ErrWGStageNotFound = errors.New("staged WireGuard configuration not found")
)

const redactedWGVault = "<WireGuard config vault: redacted>"

type WireGuardStageStatus struct {
	StageID      string                 `json:"stage_id"`
	ProfileID    string                 `json:"profile_id"`
	State        string                 `json:"state"`
	Config       WireGuardImportSummary `json:"config"`
	NetworkReady bool                   `json:"network_ready"`
}

type wireGuardStage struct {
	id  string
	cfg *ImportedWireGuardConfig
}

// WireGuardConfigVault keeps staged configs in process memory; never expose it over HTTP. By
// default nothing is persisted. OpenPersistentWireGuardConfigVault adds an opt-in encrypted
// SealedWireGuardStore; JSON and fmt output stay redacted either way.
type WireGuardConfigVault struct {
	mu      sync.RWMutex
	closed  bool
	entries map[string]wireGuardStage
	store   *SealedWireGuardStore
}

func NewWireGuardConfigVault() *WireGuardConfigVault {
	return &WireGuardConfigVault{entries: make(map[string]wireGuardStage)}
}

// OpenPersistentWireGuardConfigVault loads every config from the encrypted store and writes each
// later change back to it before the change takes effect in memory.
func OpenPersistentWireGuardConfigVault(store *SealedWireGuardStore) (*WireGuardConfigVault, error) {
	if store == nil {
		return nil, errors.New("nil sealed store")
	}

	entries, err := store.load()
	if err != nil {
		return nil, err
	}

	return &WireGuardConfigVault{entries: entries, store: store}, nil
}

// persistLocked writes next to the store (if any). The in-memory map is changed only after this
// succeeds, so memory and disk never disagree about what is staged.
func (v *WireGuardConfigVault) persistLocked(next map[string]wireGuardStage) error {
	if v.store == nil {
		return nil
	}

	if err := v.store.save(next); err != nil {
		return fmt.Errorf("persist WireGuard vault: %w", err)
	}

	return nil
}

func (v *WireGuardConfigVault) withEntry(profileID string, record *wireGuardStage) map[string]wireGuardStage {
	next := make(map[string]wireGuardStage, len(v.entries)+1)
	for id, entry := range v.entries {
		next[id] = entry
	}

	if record == nil {
		delete(next, profileID)
	} else {
		next[profileID] = *record
	}

	return next
}

func (*WireGuardConfigVault) String() string {
	return redactedWGVault
}

func (*WireGuardConfigVault) GoString() string {
	return redactedWGVault
}

func (*WireGuardConfigVault) Format(f fmt.State, _ rune) {
	_, _ = io.WriteString(f, redactedWGVault)
}

func (*WireGuardConfigVault) MarshalJSON() ([]byte, error) {
	return nil, errors.New("WireGuard vault must not be serialized")
}

func (v *WireGuardConfigVault) StageFile(profileID, path string) (WireGuardStageStatus, error) {
	if v == nil {
		return WireGuardStageStatus{}, errors.New("nil WireGuard vault")
	}

	if !profileIDPattern.MatchString(profileID) {
		return WireGuardStageStatus{}, errors.New("invalid profile ID")
	}

	v.mu.RLock()
	closed := v.closed
	v.mu.RUnlock()

	if closed {
		return WireGuardStageStatus{}, ErrWGVaultClosed
	}

	cfg, err := LoadWireGuardConfig(path)
	if err != nil {
		return WireGuardStageStatus{}, err
	}

	var randomID [16]byte
	if _, err := rand.Read(randomID[:]); err != nil {
		releaseWireGuardConfig(cfg)
		return WireGuardStageStatus{}, errors.New("cannot generate stage ID")
	}

	record := wireGuardStage{id: "wgstage_" + hex.EncodeToString(randomID[:]), cfg: cfg}

	v.mu.Lock()
	defer v.mu.Unlock()

	if v.closed {
		releaseWireGuardConfig(cfg)
		return WireGuardStageStatus{}, ErrWGVaultClosed
	}

	if err := v.persistLocked(v.withEntry(profileID, &record)); err != nil {
		releaseWireGuardConfig(cfg)
		return WireGuardStageStatus{}, err
	}

	if old, ok := v.entries[profileID]; ok {
		releaseWireGuardConfig(old.cfg)
	}

	v.entries[profileID] = record

	return v.stageStatus(profileID, record), nil
}

func (v *WireGuardConfigVault) stageStatus(profileID string, record wireGuardStage) WireGuardStageStatus {
	state := "staged_in_memory"
	if v.store != nil {
		state = "staged_encrypted_at_rest"
	}

	return WireGuardStageStatus{
		StageID:   record.id,
		ProfileID: profileID,
		State:     state,
		Config:    record.cfg.Summary(),
	}
}

func (v *WireGuardConfigVault) Status(profileID string) (WireGuardStageStatus, error) {
	if v == nil {
		return WireGuardStageStatus{}, errors.New("nil WireGuard vault")
	}

	v.mu.RLock()
	defer v.mu.RUnlock()

	if v.closed {
		return WireGuardStageStatus{}, ErrWGVaultClosed
	}

	entry, ok := v.entries[profileID]
	if !ok {
		return WireGuardStageStatus{}, ErrWGStageNotFound
	}

	return v.stageStatus(profileID, entry), nil
}

func (v *WireGuardConfigVault) List() ([]WireGuardStageStatus, error) {
	if v == nil {
		return nil, errors.New("nil WireGuard vault")
	}

	v.mu.RLock()
	defer v.mu.RUnlock()

	if v.closed {
		return nil, ErrWGVaultClosed
	}

	out := make([]WireGuardStageStatus, 0, len(v.entries))
	for profileID, entry := range v.entries {
		out = append(out, v.stageStatus(profileID, entry))
	}

	sort.Slice(out, func(i, j int) bool { return out[i].ProfileID < out[j].ProfileID })

	return out, nil
}

func (v *WireGuardConfigVault) Revoke(profileID string) error {
	if v == nil {
		return errors.New("nil WireGuard vault")
	}

	v.mu.Lock()
	defer v.mu.Unlock()

	if v.closed {
		return ErrWGVaultClosed
	}

	old, ok := v.entries[profileID]
	if !ok {
		return ErrWGStageNotFound
	}

	if err := v.persistLocked(v.withEntry(profileID, nil)); err != nil {
		return err
	}

	delete(v.entries, profileID)
	releaseWireGuardConfig(old.cfg)

	return nil
}

func (v *WireGuardConfigVault) Close() {
	if v == nil {
		return
	}

	v.mu.Lock()
	defer v.mu.Unlock()

	if v.closed {
		return
	}

	for profileID, entry := range v.entries {
		releaseWireGuardConfig(entry.cfg)
		delete(v.entries, profileID)
	}

	v.closed = true
}

// releaseWireGuardConfig overwrites the key material the config owns, then drops everything.
//
// Limits (Go cannot guarantee erasure): the kernel and wg(8) keep their own copies once a tunnel
// is configured, the Go runtime may have copied stack frames, and memory is not locked, so it can
// reach swap or a core dump. Within this process, the importer, the vault and the encrypted store
// never create a string copy of a private or preshared key.
func releaseWireGuardConfig(cfg *ImportedWireGuardConfig) {
	if cfg == nil {
		return
	}

	clear(cfg.privateKey)
	clear(cfg.peerPresharedKey)
	clear(cfg.addresses)
	clear(cfg.dns)
	clear(cfg.allowedIPs)

	*cfg = ImportedWireGuardConfig{}
}
