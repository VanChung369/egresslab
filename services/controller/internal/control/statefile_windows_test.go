//go:build windows

package control

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

// Readers that load the state files the way every serve-endpoint CONNECT does, while the API and
// the lab commands save them. On NTFS, os.ReadFile plus os.Rename made most saves fail with
// ERROR_ACCESS_DENIED and some reads with a sharing violation; under %APPDATA%, where the real
// files live, a filter also refuses some renames, and a read could find no file during a replace.
func TestStateFilesReplaceWhileRead(t *testing.T) {
	t.Run("temp", func(t *testing.T) { stressStateFiles(t, t.TempDir(), 0) })

	config, err := os.UserConfigDir()
	if err != nil {
		return
	}

	dir, err := os.MkdirTemp(config, "egresslab-statefile-test-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })

	// Unpaced saves (200 to 400 a second there) can make the filter refuse renames for longer than
	// the retry budget; about 100 a second is still far above what the API sees.
	t.Run("user config", func(t *testing.T) { stressStateFiles(t, dir, 20*time.Millisecond) })
}

// holdExclusive opens path with no sharing, as a scanner can, and closes it after hold.
func holdExclusive(t *testing.T, path string, hold time.Duration) {
	t.Helper()

	name, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		t.Fatal(err)
	}

	handle, err := syscall.CreateFile(name, syscall.GENERIC_READ, 0, nil, syscall.OPEN_EXISTING, syscall.FILE_ATTRIBUTE_NORMAL, 0)
	if err != nil {
		t.Fatal(err)
	}

	time.AfterFunc(hold, func() { syscall.CloseHandle(handle) })
}

// A reader keeps its handle for the whole save: neither side may wait for the other.
func TestStateFileReplacedWhileOpen(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.json")
	tmp := filepath.Join(dir, "state.tmp")

	if err := os.WriteFile(path, []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}

	if err := os.WriteFile(tmp, []byte("new"), 0o600); err != nil {
		t.Fatal(err)
	}

	reader, err := openStateFile(path)
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()

	start := time.Now()
	if err := replaceStateFile(tmp, path); err != nil || time.Since(start) > time.Second {
		t.Fatalf("replace under an open reader: %v after %v", err, time.Since(start))
	}

	if old, err := io.ReadAll(reader); err != nil || string(old) != "old" {
		t.Fatalf("open reader: %q, %v", old, err)
	}

	if data, err := readStateFile(path); err != nil || string(data) != "new" {
		t.Fatalf("after replace: %q, %v", data, err)
	}
}

// The name can be missing for a moment while a filter intervenes in a replace; that is not an
// empty state. The budget is raised so that the test does not depend on scheduling.
func TestStateFileMissingBriefly(t *testing.T) {
	saved := stateFileMissingRetry
	stateFileMissingRetry = 2 * time.Second
	t.Cleanup(func() { stateFileMissingRetry = saved })

	dir := t.TempDir()
	path := filepath.Join(dir, "state.json")
	tmp := filepath.Join(dir, "state.tmp")

	if err := os.WriteFile(tmp, []byte("new"), 0o600); err != nil {
		t.Fatal(err)
	}

	renamed := make(chan error, 1)
	time.AfterFunc(50*time.Millisecond, func() { renamed <- os.Rename(tmp, path) })

	data, err := readStateFile(path)
	if renameErr := <-renamed; renameErr != nil {
		t.Fatal(renameErr)
	}

	if err != nil || string(data) != "new" {
		t.Fatalf("read while the name was missing: %q, %v", data, err)
	}
}

func TestStateFileRetriesWhileHeld(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.json")

	if err := os.WriteFile(path, []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}

	holdExclusive(t, path, 100*time.Millisecond)

	if data, err := readStateFile(path); err != nil || string(data) != "old" {
		t.Fatalf("read while held: %q, %v", data, err)
	}

	tmp := filepath.Join(dir, "state.tmp")
	if err := os.WriteFile(tmp, []byte("new"), 0o600); err != nil {
		t.Fatal(err)
	}

	holdExclusive(t, tmp, 300*time.Millisecond)

	if err := replaceStateFile(tmp, path); err != nil {
		t.Fatalf("replace while held: %v", err)
	}

	if data, err := readStateFile(path); err != nil || string(data) != "new" {
		t.Fatalf("after replace: %q, %v", data, err)
	}

	start := time.Now()
	if _, err := readStateFile(filepath.Join(dir, "missing.json")); !errors.Is(err, os.ErrNotExist) || time.Since(start) > time.Second {
		t.Fatalf("missing file: %v after %v", err, time.Since(start))
	}
}

func stressStateFiles(t *testing.T, dir string, pause time.Duration) {
	path := filepath.Join(dir, "state.json")

	store, err := NewStore(path)
	if err != nil {
		t.Fatal(err)
	}

	profile, err := store.CreateProfile("Concurrent profile")
	if err != nil {
		t.Fatal(err)
	}

	runtimes, err := LoadRuntimeState(dir)
	if err != nil {
		t.Fatal(err)
	}

	if err := runtimes.Save(); err != nil {
		t.Fatal(err)
	}

	var reads, readErrs, emptyReads atomic.Int64
	var firstReadErr atomic.Value

	stop := make(chan struct{})

	var wg sync.WaitGroup
	for range 4 {
		wg.Add(1)

		go func() {
			defer wg.Done()

			for {
				select {
				case <-stop:
					return
				default:
				}

				// A missing file would load as an empty state; it must never be seen here.
				if s, err := NewStore(path); err != nil {
					readErrs.Add(1)
					firstReadErr.CompareAndSwap(nil, err.Error())
				} else if len(s.Profiles()) != 1 {
					emptyReads.Add(1)
				}

				if _, err := LoadRuntimeState(dir); err != nil {
					readErrs.Add(1)
					firstReadErr.CompareAndSwap(nil, err.Error())
				}

				reads.Add(2)
			}
		}()
	}

	saves, saveErrs := 0, 0
	var firstSaveErr error

	for deadline := time.Now().Add(3 * time.Second); time.Now().Before(deadline); {
		endpoint, err := store.CreateEndpoint(fmt.Sprintf("Endpoint %d", saves), "socks5", profile.ID, 1090)
		if err == nil {
			err = store.DeleteEndpoint(endpoint.ID)
		}

		if err == nil {
			err = runtimes.Save()
		}

		saves += 3

		if err != nil {
			saveErrs++
			if firstSaveErr == nil {
				firstSaveErr = err
			}

			// Leave no endpoint behind for the next round's port check.
			for _, left := range store.Endpoints() {
				_ = store.DeleteEndpoint(left.ID)
			}
		}

		time.Sleep(pause)
	}

	close(stop)
	wg.Wait()

	if saveErrs != 0 || readErrs.Load() != 0 || emptyReads.Load() != 0 || saves < 30 || reads.Load() < 100 {
		t.Fatalf("saves %d (%d failed, first %v), reads %d (%d failed, %d empty, first %v)", saves, saveErrs,
			firstSaveErr, reads.Load(), readErrs.Load(), emptyReads.Load(), firstReadErr.Load())
	}

	final, err := NewStore(path)
	if err != nil || len(final.Endpoints()) != 0 || len(final.Profiles()) != 1 {
		t.Fatalf("final state: %v", err)
	}
}
