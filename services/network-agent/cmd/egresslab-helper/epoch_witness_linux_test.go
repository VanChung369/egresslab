//go:build linux

package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const (
	witnessTestBootA = "11111111-2222-4333-8444-555555555555"
	witnessTestBootB = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"
)

func testEpochWitness(number int, bootID string) epochWitness {
	return epochWitness{
		HelperID:        fmt.Sprintf("helper_%032x", number),
		RuntimeID:       "runtime_11111111111111111111111111111111",
		BootID:          bootID,
		PublicKeySHA256: strings.Repeat("a", 64),
	}
}

func lockWitnessTestLayout(t *testing.T) vaultLayout {
	t.Helper()

	layout := testLayout(t)

	lock, err := layout.lock()
	if err != nil {
		t.Fatal(err)
	}

	t.Cleanup(func() { _ = lock.Close() })

	return layout
}

func TestKernelBootIDParsing(t *testing.T) {
	id, err := parseKernelBootID([]byte(witnessTestBootA + "\n"))
	if err != nil || id != witnessTestBootA {
		t.Fatalf("valid boot ID refused: %q %v", id, err)
	}

	for _, input := range []string{
		"",
		witnessTestBootA,
		witnessTestBootA + "\n\n",
		strings.ToUpper(witnessTestBootB) + "\n",
		"00000000-0000-0000-0000-000000000000\n",
		"invalid\n",
	} {
		if _, err := parseKernelBootID([]byte(input)); err == nil {
			t.Fatalf("invalid boot ID accepted: %q", input)
		}
	}
}

func TestReadActualKernelBootID(t *testing.T) {
	id, err := readKernelBootID()
	if err != nil || !validWitnessBootID(id) {
		t.Fatalf("invalid actual kernel boot ID: %v", err)
	}
}

func TestEpochWitnessRegistersKernelBoot(t *testing.T) {
	layout := lockWitnessTestLayout(t)
	expected := testEpochWitness(1, witnessTestBootA)

	if err := registerHelperEpochLocked(layout, expected.RuntimeID, expected.HelperID, expected.PublicKeySHA256); err != nil {
		t.Fatal(err)
	}

	bootID, err := readKernelBootID()
	if err != nil {
		t.Fatal(err)
	}

	ledger, err := readEpochWitnessLedger(layout)
	if err != nil {
		t.Fatal(err)
	}

	expected.BootID = bootID

	if stored, exists := ledger.find(expected.HelperID); !exists || stored != expected || len(ledger.Entries) != 1 {
		t.Fatal("helper epoch not bound to the current kernel boot")
	}
}

func TestEpochWitnessPersistence(t *testing.T) {
	layout := lockWitnessTestLayout(t)
	first := testEpochWitness(1, witnessTestBootA)

	if err := appendEpochWitnessLocked(layout, first); err != nil {
		t.Fatal(err)
	}

	ledger, err := readEpochWitnessLedger(layout)
	if err != nil || len(ledger.Entries) != 1 {
		t.Fatalf("witness lost: %v", err)
	}

	if stored, exists := ledger.find(first.HelperID); !exists || stored != first {
		t.Fatal("incorrect persisted witness")
	}

	info, err := os.Stat(layout.epochWitnessPath())
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatal("incorrect witness file permissions")
	}
}

func TestEpochWitnessBootHistory(t *testing.T) {
	layout := lockWitnessTestLayout(t)

	witnesses := []epochWitness{
		testEpochWitness(1, witnessTestBootA),
		testEpochWitness(2, witnessTestBootA),
		testEpochWitness(3, witnessTestBootB),
	}

	for _, witness := range witnesses {
		if err := appendEpochWitnessLocked(layout, witness); err != nil {
			t.Fatal(err)
		}
	}

	ledger, err := readEpochWitnessLedger(layout)
	if err != nil || len(ledger.Entries) != 3 {
		t.Fatal("incorrect witness history")
	}

	for _, expected := range witnesses {
		if actual, exists := ledger.find(expected.HelperID); !exists || actual != expected {
			t.Fatal("historical witness changed")
		}
	}

	if ledger.Entries[0].BootID != ledger.Entries[1].BootID {
		t.Fatal("same-boot history was lost")
	}

	if ledger.Entries[1].BootID == ledger.Entries[2].BootID {
		t.Fatal("different boot was not retained")
	}
}

func TestEpochWitnessRejectsDuplicate(t *testing.T) {
	layout := lockWitnessTestLayout(t)
	first := testEpochWitness(1, witnessTestBootA)

	if err := appendEpochWitnessLocked(layout, first); err != nil {
		t.Fatal(err)
	}

	before, err := os.ReadFile(layout.epochWitnessPath())
	if err != nil {
		t.Fatal(err)
	}

	changed := first
	changed.BootID = witnessTestBootB

	if err := appendEpochWitnessLocked(layout, changed); err == nil {
		t.Fatal("duplicate helper epoch accepted")
	}

	after, err := os.ReadFile(layout.epochWitnessPath())
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("duplicate epoch modified history")
	}
}

func TestEpochWitnessCorruption(t *testing.T) {
	layout := lockWitnessTestLayout(t)
	corrupted := []byte(`{"version":1,"entries":[`)

	if err := os.WriteFile(layout.epochWitnessPath(), corrupted, 0o600); err != nil {
		t.Fatal(err)
	}

	if err := appendEpochWitnessLocked(layout, testEpochWitness(1, witnessTestBootA)); err == nil {
		t.Fatal("corrupted ledger was accepted")
	}

	current, err := os.ReadFile(layout.epochWitnessPath())
	if err != nil || !bytes.Equal(current, corrupted) {
		t.Fatal("corrupted ledger was silently replaced")
	}
}

func TestEpochWitnessRejectsUnsafePermissions(t *testing.T) {
	layout := lockWitnessTestLayout(t)

	if err := appendEpochWitnessLocked(layout, testEpochWitness(1, witnessTestBootA)); err != nil {
		t.Fatal(err)
	}

	if err := os.Chmod(layout.epochWitnessPath(), 0o644); err != nil {
		t.Fatal(err)
	}

	if _, err := readEpochWitnessLedger(layout); err == nil {
		t.Fatal("unsafe witness permissions accepted")
	}
}

func TestEpochWitnessRejectsSymlink(t *testing.T) {
	layout := lockWitnessTestLayout(t)
	other := filepath.Join(layout.dataDir, "other.json")

	if err := os.WriteFile(other, []byte("unrelated"), 0o600); err != nil {
		t.Fatal(err)
	}

	if err := os.Symlink(other, layout.epochWitnessPath()); err != nil {
		t.Fatal(err)
	}

	if err := appendEpochWitnessLocked(layout, testEpochWitness(1, witnessTestBootA)); err == nil {
		t.Fatal("symbolic link accepted")
	}

	data, err := os.ReadFile(other)
	if err != nil || string(data) != "unrelated" {
		t.Fatal("symlink target was modified")
	}
}

func TestEpochWitnessHistoryLimit(t *testing.T) {
	layout := lockWitnessTestLayout(t)

	ledger := epochWitnessLedger{Version: epochWitnessVersion, Entries: make([]epochWitness, 0, maxEpochWitnesses)}

	for i := 1; i <= maxEpochWitnesses; i++ {
		ledger.Entries = append(ledger.Entries, testEpochWitness(i, witnessTestBootA))
	}

	if err := writeEpochWitnessLedgerLocked(layout, ledger); err != nil {
		t.Fatal(err)
	}

	if err := appendEpochWitnessLocked(layout, testEpochWitness(maxEpochWitnesses+1, witnessTestBootB)); err == nil {
		t.Fatal("history capacity exceeded")
	}

	recovered, err := readEpochWitnessLedger(layout)
	if err != nil || len(recovered.Entries) != maxEpochWitnesses || recovered.Entries[0] != ledger.Entries[0] {
		t.Fatal("history was evicted or modified")
	}
}

func rawWitnessRecord(t *testing.T, ledger epochWitnessLedger) string {
	t.Helper()

	body, err := json.Marshal(ledger)
	if err != nil {
		t.Fatal(err)
	}

	sum := sha256.Sum256(body)

	data, err := json.Marshal(epochWitnessRecord{Version: ledger.Version, Entries: ledger.Entries, SHA256: hex.EncodeToString(sum[:])})
	if err != nil {
		t.Fatal(err)
	}

	return string(data) + "\n"
}

func TestEpochWitnessRejectsNoncanonical(t *testing.T) {
	first := testEpochWitness(1, witnessTestBootA)
	ledger := epochWitnessLedger{Version: epochWitnessVersion, Entries: []epochWitness{first}}

	valid, err := encodeEpochWitnessLedger(ledger)
	if err != nil {
		t.Fatal(err)
	}

	text := string(valid)
	if rawWitnessRecord(t, ledger) != text {
		t.Fatal("unexpected canonical encoding")
	}

	if decoded, err := decodeEpochWitnessLedger(valid); err != nil || len(decoded.Entries) != 1 || decoded.Entries[0] != first {
		t.Fatalf("canonical ledger refused: %v", err)
	}

	zeroBoot := first
	zeroBoot.BootID = "00000000-0000-0000-0000-000000000000"

	legacy, err := json.Marshal(ledger)
	if err != nil {
		t.Fatal(err)
	}

	cases := map[string]string{
		"unknown field":   strings.Replace(text, `{"version":1,`, `{"version":1,"extra":1,`, 1),
		"duplicate field": strings.Replace(text, `{"version":1,`, `{"version":1,"version":1,`, 1),
		"spacing":         strings.Replace(text, `{"version":1,`, `{"version": 1,`, 1),
		"no newline":      strings.TrimSuffix(text, "\n"),
		"no checksum":     string(legacy) + "\n",
		"wrong checksum":  text[:len(text)-4] + `0"}` + "\n",
		"other version":   rawWitnessRecord(t, epochWitnessLedger{Version: 2, Entries: ledger.Entries}),
		"duplicate epoch": rawWitnessRecord(t, epochWitnessLedger{Version: 1, Entries: []epochWitness{first, first}}),
		"no entries":      rawWitnessRecord(t, epochWitnessLedger{Version: 1, Entries: []epochWitness{}}),
		"zero boot ID":    rawWitnessRecord(t, epochWitnessLedger{Version: 1, Entries: []epochWitness{zeroBoot}}),
		"oversized":       text + strings.Repeat(" ", maxEpochWitnessBytes),
	}

	for name, input := range cases {
		if input == text {
			t.Fatalf("%s: unchanged input", name)
		}

		if _, err := decodeEpochWitnessLedger([]byte(input)); err == nil {
			t.Fatalf("%s accepted", name)
		}
	}
}

func TestEpochWitnessDetectsChangedValue(t *testing.T) {
	layout := lockWitnessTestLayout(t)

	if err := appendEpochWitnessLocked(layout, testEpochWitness(1, witnessTestBootA)); err != nil {
		t.Fatal(err)
	}

	data, err := os.ReadFile(layout.epochWitnessPath())
	if err != nil {
		t.Fatal(err)
	}

	changed := bytes.Replace(data, []byte(witnessTestBootA), []byte(witnessTestBootB), 1)
	if bytes.Equal(changed, data) {
		t.Fatal("boot ID not stored")
	}

	if err := os.WriteFile(layout.epochWitnessPath(), changed, 0o600); err != nil {
		t.Fatal(err)
	}

	if _, err := readEpochWitnessLedger(layout); err == nil {
		t.Fatal("changed boot ID accepted")
	}

	if err := appendEpochWitnessLocked(layout, testEpochWitness(2, witnessTestBootA)); err == nil {
		t.Fatal("ledger with a changed boot ID was extended")
	}

	current, err := os.ReadFile(layout.epochWitnessPath())
	if err != nil || !bytes.Equal(current, changed) {
		t.Fatal("changed ledger was replaced")
	}
}
