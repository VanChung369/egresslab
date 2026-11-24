//go:build linux

package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const testHelperID = "helper_0123456789abcdef0123456789abcdef"

// keyDir returns a directory owned by the current user and not writable by others.
func keyDir(t *testing.T) string {
	t.Helper()

	dir := t.TempDir()
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}

	return dir
}

func writeKey(t *testing.T, dir, content string, mode os.FileMode) string {
	t.Helper()

	path := filepath.Join(dir, "helper-auth.pub")
	if err := os.WriteFile(path, []byte(content), mode); err != nil {
		t.Fatal(err)
	}

	if err := os.Chmod(path, mode); err != nil { // WriteFile's mode is filtered by umask
		t.Fatal(err)
	}

	return path
}

func publicHex(t *testing.T) string {
	t.Helper()

	public, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	return hex.EncodeToString(public)
}

func TestLoadAuthVerifierFlags(t *testing.T) {
	if v, err := loadAuthVerifier("", ""); v != nil || err != nil {
		t.Fatalf("no flags: %v %v", v, err)
	}

	for _, args := range [][2]string{{"/etc/egresslab/helper-auth.pub", ""}, {"", testHelperID}} {
		if _, err := loadAuthVerifier(args[0], args[1]); err == nil || !strings.Contains(err.Error(), "together") {
			t.Fatalf("%q: %v", args, err)
		}
	}
}

func TestLoadAuthVerifierAcceptsOwnedKey(t *testing.T) {
	me := uint32(os.Getuid())
	path := writeKey(t, keyDir(t), publicHex(t)+"\n", 0o644)

	v, err := loadAuthVerifierOwnedBy(path, testHelperID, me)
	if err != nil || v == nil {
		t.Fatalf("valid key rejected: %v", err)
	}

	if _, err := loadAuthVerifierOwnedBy(path, "helper_1234", me); err == nil || !strings.Contains(err.Error(), "-helper-id") {
		t.Fatalf("bad helper ID: %v", err)
	}

	// The production entry point requires root ownership.
	if me != 0 {
		if _, err := loadAuthVerifier(path, testHelperID); err == nil {
			t.Fatal("key owned by a non-root user accepted")
		}
	}
}

func TestLoadAuthVerifierRejectsUnsafeKeys(t *testing.T) {
	me := uint32(os.Getuid())
	good := publicHex(t)

	tests := []struct {
		name    string
		setup   func(t *testing.T) string
		wantErr string
	}{
		{"group writable file", func(t *testing.T) string {
			return writeKey(t, keyDir(t), good, 0o664)
		}, "not writable"},
		{"world writable directory", func(t *testing.T) string {
			dir := keyDir(t)
			path := writeKey(t, dir, good, 0o644)
			if err := os.Chmod(dir, 0o777); err != nil {
				t.Fatal(err)
			}
			return path
		}, "directory"},
		{"symlink", func(t *testing.T) string {
			dir := keyDir(t)
			target := writeKey(t, dir, good, 0o644)
			link := filepath.Join(dir, "link.pub")
			if err := os.Symlink(target, link); err != nil {
				t.Fatal(err)
			}
			return link
		}, "regular file"},
		{"short key", func(t *testing.T) string {
			return writeKey(t, keyDir(t), good[:62], 0o644)
		}, "64 hex"},
		{"not hex", func(t *testing.T) string {
			return writeKey(t, keyDir(t), strings.Repeat("zz", 32), 0o644)
		}, "encoding"},
		{"oversized file", func(t *testing.T) string {
			return writeKey(t, keyDir(t), good+strings.Repeat(" ", 100), 0o644)
		}, "at most"},
		{"private key instead of public key", func(t *testing.T) string {
			_, private, _ := ed25519.GenerateKey(rand.Reader)
			return writeKey(t, keyDir(t), hex.EncodeToString(private), 0o644)
		}, "64 hex"},
		{"missing", func(t *testing.T) string {
			return filepath.Join(keyDir(t), "absent.pub")
		}, "inspect"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v, err := loadAuthVerifierOwnedBy(tt.setup(t), testHelperID, me)
			if err == nil || v != nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("got %v %v, want error containing %q", v, err, tt.wantErr)
			}
		})
	}

	t.Run("owned by another UID", func(t *testing.T) {
		path := writeKey(t, keyDir(t), good, 0o644)
		if _, err := loadAuthVerifierOwnedBy(path, testHelperID, me+1); err == nil {
			t.Fatal("key owned by another UID accepted")
		}
	})
}
