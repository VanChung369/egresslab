//go:build linux

package main

import (
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

func TestParseMultiProbePin(t *testing.T) {
	for _, raw := range []string{"9.9.9.9", "9.9.9.9\n"} {
		if pin, err := parseMultiProbePin([]byte(raw)); err != nil || pin != netip.MustParseAddr("9.9.9.9") {
			t.Fatalf("valid pin %q refused: %v %v", raw, pin, err)
		}
	}

	for _, raw := range []string{
		"",
		"\n",
		"1.1.1.1",
		"10.0.0.1",
		"127.0.0.1",
		"100.64.0.1",
		"169.254.169.254",
		"192.0.2.1",
		"198.51.100.1",
		"203.0.113.1",
		"224.0.0.1",
		"240.0.0.1",
		"2001:db8::1",
		"::ffff:9.9.9.9",
		"4.ident.me",
		"https://4.ident.me/",
		"9.9.9.9:443",
		" 9.9.9.9",
		"9.9.9.9 ",
		"9.9.9.9\r\n",
		"9.9.9.9\n\n",
		"9.9.9.9\n8.8.8.8",
		"IDENT_PIN=9.9.9.9",
		"009.9.9.9",
		strings.Repeat("x", maxMultiProbePinBytes+1),
	} {
		if pin, err := parseMultiProbePin([]byte(raw)); err == nil || pin.IsValid() {
			t.Fatalf("invalid pin %q accepted", raw)
		}
	}
}

func writePinFile(t *testing.T, path, content string, mode os.FileMode) {
	t.Helper()

	if err := os.WriteFile(path, []byte(content), mode); err != nil {
		t.Fatal(err)
	}

	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
}

func TestLoadMultiProbePinOwnedBy(t *testing.T) {
	dir := keyDir(t)
	root := filepath.Dir(dir)
	owner := uint32(os.Getuid())
	path := filepath.Join(dir, "multi-probe-pin")

	for _, mode := range []os.FileMode{0o600, 0o644} {
		writePinFile(t, path, "9.9.9.9\n", mode)

		pin, err := loadMultiProbePinOwnedBy(path, owner, root)
		if err != nil || pin.String() != "9.9.9.9" {
			t.Fatalf("trusted configuration (mode %o) refused: %v %v", mode, pin, err)
		}
	}

	// The loaded pin is a value: a later edit changes nothing until the next load (a restart).
	pin, _ := loadMultiProbePinOwnedBy(path, owner, root)
	writePinFile(t, path, "8.8.8.8\n", 0o600)

	if pin.String() != "9.9.9.9" {
		t.Fatal("loaded policy changed without a reload")
	}

	if reloaded, err := loadMultiProbePinOwnedBy(path, owner, root); err != nil || reloaded.String() != "8.8.8.8" {
		t.Fatalf("new configuration refused: %v %v", reloaded, err)
	}
}

func TestUnsafeMultiProbeConfiguration(t *testing.T) {
	for _, mode := range []string{
		"missing",
		"relative",
		"directory",
		"symlink",
		"symlink parent",
		"group writable",
		"world writable",
		"writable parent",
		"wrong owner",
		"FIFO",
		"empty",
		"oversized",
		"invalid pin",
		"dot-dot path",
		"dot-dot after a symlink",
		"double slash",
		"trailing slash",
	} {
		t.Run(mode, func(t *testing.T) {
			dir := keyDir(t)
			root := filepath.Dir(dir)
			owner := uint32(os.Getuid())
			path := filepath.Join(dir, "multi-probe-pin")

			switch mode {
			case "missing":
			case "relative":
				path = "multi-probe-pin"
			case "directory":
				if err := os.Mkdir(path, 0o700); err != nil {
					t.Fatal(err)
				}
			case "symlink":
				target := filepath.Join(dir, "target")
				writePinFile(t, target, "9.9.9.9\n", 0o600)

				if err := os.Symlink(target, path); err != nil {
					t.Fatal(err)
				}
			case "symlink parent":
				writePinFile(t, path, "9.9.9.9\n", 0o600)

				alias := filepath.Join(root, "alias")
				if err := os.Symlink(dir, alias); err != nil {
					t.Fatal(err)
				}

				path = filepath.Join(alias, "multi-probe-pin")
			case "group writable":
				writePinFile(t, path, "9.9.9.9\n", 0o660)
			case "world writable":
				writePinFile(t, path, "9.9.9.9\n", 0o666)
			case "writable parent":
				writePinFile(t, path, "9.9.9.9\n", 0o600)

				if err := os.Chmod(dir, 0o777); err != nil {
					t.Fatal(err)
				}
			case "wrong owner":
				writePinFile(t, path, "9.9.9.9\n", 0o600)
				owner ^= 1
			case "FIFO":
				if err := syscall.Mkfifo(path, 0o600); err != nil {
					t.Fatal(err)
				}
			case "empty":
				writePinFile(t, path, "", 0o600)
			case "oversized":
				writePinFile(t, path, strings.Repeat("x", maxMultiProbePinBytes+1), 0o600)
			case "invalid pin":
				writePinFile(t, path, "10.0.0.1\n", 0o600)
			case "dot-dot path":
				writePinFile(t, path, "9.9.9.9\n", 0o600)
				path = filepath.Join(dir, "sub") + "/../multi-probe-pin"
			case "dot-dot after a symlink":
				// For the kernel, dir/alias/.. is the symlink target's parent; cleaned, it is dir.
				writePinFile(t, path, "9.9.9.9\n", 0o600)

				if err := os.Symlink(t.TempDir(), filepath.Join(dir, "alias")); err != nil {
					t.Fatal(err)
				}

				path = dir + "/alias/../multi-probe-pin"
			case "double slash":
				writePinFile(t, path, "9.9.9.9\n", 0o600)
				path = dir + "//multi-probe-pin"
			case "trailing slash":
				writePinFile(t, path, "9.9.9.9\n", 0o600)
				path += "/"
			}

			if pin, err := loadMultiProbePinOwnedBy(path, owner, root); err == nil || pin.IsValid() {
				t.Fatalf("unsafe configuration accepted: %v", pin)
			}
		})
	}
}

func TestCheckMultiProbePinCommand(t *testing.T) {
	for _, args := range [][]string{nil, {"a", "b"}, {"relative/pin"}} {
		if pin, err := checkMultiProbePinCommand(args); err == nil || pin.IsValid() {
			t.Errorf("%q accepted", args)
		}
	}

	// The command checks root ownership, so a file the test user owns is refused.
	dir := keyDir(t)
	path := filepath.Join(dir, "multi-probe-pin")
	writePinFile(t, path, "9.9.9.9\n", 0o600)

	if os.Getuid() != 0 {
		if _, err := checkMultiProbePinCommand([]string{path}); err == nil {
			t.Fatal("a pin file owned by a normal user passed the root check")
		}
	}
}
