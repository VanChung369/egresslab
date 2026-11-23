package agent

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"sort"
	"sync"
)

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

// WireGuardConfigVault keeps staged configs in process memory only; never expose it over HTTP or persist it.
type WireGuardConfigVault struct {
	mu      sync.RWMutex
	closed  bool
	entries map[string]wireGuardStage
}

func NewWireGuardConfigVault() *WireGuardConfigVault {
	return &WireGuardConfigVault{entries: make(map[string]wireGuardStage)}
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

	if old, ok := v.entries[profileID]; ok {
		releaseWireGuardConfig(old.cfg)
	}

	v.entries[profileID] = record

	return stageStatus(profileID, record), nil
}

func stageStatus(profileID string, record wireGuardStage) WireGuardStageStatus {
	return WireGuardStageStatus{
		StageID:   record.id,
		ProfileID: profileID,
		State:     "staged_in_memory",
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

	return stageStatus(profileID, entry), nil
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
		out = append(out, stageStatus(profileID, entry))
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

// Best effort only: Go strings are immutable, so earlier copies may remain in memory.
func releaseWireGuardConfig(cfg *ImportedWireGuardConfig) {
	if cfg == nil {
		return
	}

	clear(cfg.addresses)
	clear(cfg.dns)
	clear(cfg.allowedIPs)

	*cfg = ImportedWireGuardConfig{}
}
