//go:build windows

package labruntime

import (
	"strings"
	"testing"
)

func TestWSLLauncher(t *testing.T) {
	if _, err := newWSL("Ubuntu 22.04"); err == nil {
		t.Fatal("unsafe distro name accepted")
	}

	if _, err := New("native", Options{}); err == nil {
		t.Fatal("native runtime accepted on Windows")
	}

	l, err := newWSL("Ubuntu-22.04")
	if err != nil {
		t.Fatal(err)
	}

	wsl := l.(wslLauncher)
	if !strings.HasSuffix(strings.ToLower(wsl.wsl), `\system32\wsl.exe`) {
		t.Fatalf("wsl path: %s", wsl.wsl)
	}

	got := strings.Join(wsl.args("delete-lab", testProfile, testNamespace), " ")
	if got != "--distribution Ubuntu-22.04 --exec "+HelperctlPath+" delete-lab "+testProfile+" "+testNamespace {
		t.Fatalf("wsl args: %s", got)
	}

	if got := strings.Join(wslLauncher{}.args("ping"), " "); got != "--exec "+HelperctlPath+" ping" {
		t.Fatalf("default distro args: %s", got)
	}
}
