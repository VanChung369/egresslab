//go:build linux

package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
)

const (
	kernelBootIDPath     = "/proc/sys/kernel/random/boot_id"
	epochWitnessFile     = "helper-epochs.json"
	epochWitnessVersion  = 1
	maxEpochWitnesses    = 4096
	maxEpochWitnessBytes = 2 * 1024 * 1024
)

var (
	witnessBootIDPattern      = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	witnessHelperPattern      = regexp.MustCompile(`^helper_[0-9a-f]{32}$`)
	witnessRuntimePattern     = regexp.MustCompile(`^runtime_[0-9a-f]{32}$`)
	witnessFingerprintPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

// epochWitness binds one helper lifetime to one Linux kernel boot. It authorizes nothing by itself.
type epochWitness struct {
	HelperID        string `json:"helper_id"`
	RuntimeID       string `json:"runtime_id"`
	BootID          string `json:"boot_id"`
	PublicKeySHA256 string `json:"public_key_sha256"`
}

type epochWitnessLedger struct {
	Version int            `json:"version"`
	Entries []epochWitness `json:"entries"`
}

// epochWitnessRecord is the stored form; its SHA-256 over the ledger detects a value changed into
// another well-formed one.
type epochWitnessRecord struct {
	Version int            `json:"version"`
	Entries []epochWitness `json:"entries"`
	SHA256  string         `json:"sha256"`
}

func validWitnessBootID(id string) bool {
	return witnessBootIDPattern.MatchString(id) && id != "00000000-0000-0000-0000-000000000000"
}

func parseKernelBootID(data []byte) (string, error) {
	if len(data) != 37 || data[len(data)-1] != '\n' {
		return "", errors.New("invalid kernel boot ID")
	}

	id := strings.TrimSuffix(string(data), "\n")
	if !validWitnessBootID(id) {
		return "", errors.New("invalid kernel boot ID")
	}

	return id, nil
}

// readKernelBootID trusts only the kernel: no boot ID ever comes from a client, flag or file.
func readKernelBootID() (string, error) {
	data, err := os.ReadFile(kernelBootIDPath)
	if err != nil {
		return "", fmt.Errorf("read kernel boot ID: %w", err)
	}

	return parseKernelBootID(data)
}

func (w epochWitness) valid() bool {
	return witnessHelperPattern.MatchString(w.HelperID) &&
		witnessRuntimePattern.MatchString(w.RuntimeID) &&
		validWitnessBootID(w.BootID) &&
		witnessFingerprintPattern.MatchString(w.PublicKeySHA256)
}

func (l epochWitnessLedger) valid() bool {
	if l.Version != epochWitnessVersion || len(l.Entries) == 0 || len(l.Entries) > maxEpochWitnesses {
		return false
	}

	seen := make(map[string]struct{}, len(l.Entries))

	for _, entry := range l.Entries {
		if !entry.valid() {
			return false
		}

		if _, exists := seen[entry.HelperID]; exists {
			return false
		}

		seen[entry.HelperID] = struct{}{}
	}

	return true
}

func (l epochWitnessLedger) find(helperID string) (epochWitness, bool) {
	for _, entry := range l.Entries {
		if entry.HelperID == helperID {
			return entry, true
		}
	}

	return epochWitness{}, false
}

func (l vaultLayout) epochWitnessPath() string { return filepath.Join(l.dataDir, epochWitnessFile) }

func encodeEpochWitnessLedger(ledger epochWitnessLedger) ([]byte, error) {
	if !ledger.valid() {
		return nil, errors.New("invalid epoch witness ledger")
	}

	body, err := json.Marshal(ledger)
	if err != nil {
		return nil, err
	}

	sum := sha256.Sum256(body)

	data, err := json.Marshal(epochWitnessRecord{
		Version: ledger.Version,
		Entries: ledger.Entries,
		SHA256:  hex.EncodeToString(sum[:]),
	})
	if err != nil {
		return nil, err
	}

	data = append(data, '\n')

	if len(data) > maxEpochWitnessBytes {
		return nil, errors.New("epoch witness ledger too large")
	}

	return data, nil
}

// decodeEpochWitnessLedger accepts only the canonical encoding with its checksum, which refuses
// unknown or duplicate fields, any other spelling and any changed value.
func decodeEpochWitnessLedger(data []byte) (epochWitnessLedger, error) {
	if len(data) == 0 || len(data) > maxEpochWitnessBytes {
		return epochWitnessLedger{}, errors.New("invalid epoch witness ledger size")
	}

	var record epochWitnessRecord

	if err := json.Unmarshal(data, &record); err != nil {
		return epochWitnessLedger{}, fmt.Errorf("decode epoch witness ledger: %w", err)
	}

	ledger := epochWitnessLedger{Version: record.Version, Entries: record.Entries}

	canonical, err := encodeEpochWitnessLedger(ledger)
	if err != nil || !bytes.Equal(canonical, data) {
		return epochWitnessLedger{}, errors.New("invalid or noncanonical epoch witness ledger")
	}

	return ledger, nil
}

func readEpochWitnessLedger(layout vaultLayout) (epochWitnessLedger, error) {
	if err := layout.checkDir(layout.dataDir); err != nil {
		return epochWitnessLedger{}, err
	}

	path := layout.epochWitnessPath()

	before, err := os.Lstat(path)
	if err != nil {
		return epochWitnessLedger{}, err
	}

	if err := layout.validateFile(before); err != nil {
		return epochWitnessLedger{}, err
	}

	file, err := os.OpenFile(path, os.O_RDWR|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return epochWitnessLedger{}, err
	}
	defer file.Close()

	opened, err := file.Stat()
	if err != nil {
		return epochWitnessLedger{}, err
	}

	if !os.SameFile(before, opened) {
		return epochWitnessLedger{}, errors.New("epoch witness ledger changed during open")
	}

	if err := layout.validateFile(opened); err != nil {
		return epochWitnessLedger{}, err
	}

	if opened.Size() <= 0 || opened.Size() > maxEpochWitnessBytes {
		return epochWitnessLedger{}, errors.New("invalid epoch witness file size")
	}

	// A previous process may have published the file just before a crash.
	if err := file.Sync(); err != nil {
		return epochWitnessLedger{}, err
	}

	data, err := io.ReadAll(io.LimitReader(file, maxEpochWitnessBytes+1))
	if err != nil {
		return epochWitnessLedger{}, err
	}

	return decodeEpochWitnessLedger(data)
}

// writeEpochWitnessLedgerLocked replaces the ledger atomically. The caller holds the vault lock.
func writeEpochWitnessLedgerLocked(layout vaultLayout, ledger epochWitnessLedger) error {
	if err := layout.checkDir(layout.dataDir); err != nil {
		return err
	}

	data, err := encodeEpochWitnessLedger(ledger)
	if err != nil {
		return err
	}

	file, err := os.CreateTemp(layout.dataDir, ".helper-epochs-*")
	if err != nil {
		return err
	}

	tempPath := file.Name()

	defer os.Remove(tempPath)
	defer file.Close()

	if err := file.Chmod(0o600); err != nil {
		return err
	}

	n, err := file.Write(data)
	if err != nil {
		return err
	}

	if n != len(data) {
		return io.ErrShortWrite
	}

	if err := file.Sync(); err != nil {
		return err
	}

	if err := file.Close(); err != nil {
		return err
	}

	if err := os.Rename(tempPath, layout.epochWitnessPath()); err != nil {
		return err
	}

	dir, err := os.Open(layout.dataDir)
	if err != nil {
		return err
	}
	defer dir.Close()

	return dir.Sync()
}

// appendEpochWitnessLocked registers a new helper epoch and keeps every earlier one. The caller
// holds the vault lock for the whole read-modify-write.
func appendEpochWitnessLocked(layout vaultLayout, witness epochWitness) error {
	if !witness.valid() {
		return errors.New("invalid helper epoch witness")
	}

	ledger, err := readEpochWitnessLedger(layout)

	switch {
	case errors.Is(err, os.ErrNotExist):
		ledger = epochWitnessLedger{Version: epochWitnessVersion, Entries: make([]epochWitness, 0, 1)}
	case err != nil:
		return fmt.Errorf("read existing helper epochs: %w", err)
	}

	if _, exists := ledger.find(witness.HelperID); exists {
		return errors.New("helper epoch already registered")
	}

	if len(ledger.Entries) >= maxEpochWitnesses {
		return errors.New("helper epoch history capacity reached")
	}

	ledger.Entries = append(ledger.Entries, witness)

	if err := writeEpochWitnessLedgerLocked(layout, ledger); err != nil {
		return fmt.Errorf("commit helper epoch witness: %w", err)
	}

	return nil
}

func registerHelperEpochLocked(layout vaultLayout, runtimeID, helperID, fingerprint string) error {
	bootID, err := readKernelBootID()
	if err != nil {
		return err
	}

	return appendEpochWitnessLocked(layout, epochWitness{
		HelperID:        helperID,
		RuntimeID:       runtimeID,
		BootID:          bootID,
		PublicKeySHA256: fingerprint,
	})
}

// verifyEpochRecovery proves that the original epoch belonged to an earlier kernel boot of the same
// runtime and key than the current one, which runs on the current kernel.
func verifyEpochRecovery(ledger epochWitnessLedger, originalID, currentID, runtimeID, fingerprint,
	kernelBootID string) (string, string, error) {
	if !ledger.valid() || !validWitnessBootID(kernelBootID) || originalID == currentID {
		return "", "", errors.New("invalid recovery identity")
	}

	original, originalExists := ledger.find(originalID)
	current, currentExists := ledger.find(currentID)

	if !originalExists || !currentExists {
		return "", "", errors.New("helper epoch witness missing")
	}

	if ledger.Entries[len(ledger.Entries)-1] != current {
		return "", "", errors.New("current epoch is not the latest witness")
	}

	if original.RuntimeID != runtimeID || current.RuntimeID != runtimeID ||
		original.PublicKeySHA256 != fingerprint || current.PublicKeySHA256 != fingerprint {
		return "", "", errors.New("epoch witness identity mismatch")
	}

	if current.BootID != kernelBootID {
		return "", "", errors.New("current kernel boot mismatch")
	}

	if original.BootID == current.BootID {
		return "", "", errors.New("kernel reboot not established")
	}

	return original.BootID, current.BootID, nil
}

// readEpochRecoveryLocked runs in the helper, which holds the vault lock for its lifetime.
func readEpochRecoveryLocked(layout vaultLayout, originalID, currentID, runtimeID, fingerprint string) (
	string, string, error) {
	ledger, err := readEpochWitnessLedger(layout)
	if err != nil {
		return "", "", err
	}

	bootID, err := readKernelBootID()
	if err != nil {
		return "", "", err
	}

	return verifyEpochRecovery(ledger, originalID, currentID, runtimeID, fingerprint, bootID)
}
