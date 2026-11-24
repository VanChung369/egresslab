//go:build !windows

package labruntime

import (
	"runtime"
	"testing"
)

func TestPlatformLaunchers(t *testing.T) {
	if _, err := New("wsl", Options{}); err == nil {
		t.Fatal("WSL runtime accepted outside Windows")
	}

	_, err := New("native", Options{})
	if (runtime.GOOS == "linux") != (err == nil) {
		t.Fatalf("native runtime on %s: %v", runtime.GOOS, err)
	}
}
