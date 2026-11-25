//go:build linux

package main

import (
	"strings"
	"testing"
)

// Every combination here is refused before the key, the socket or the kernel is touched.
func TestProbeFlagsRefused(t *testing.T) {
	for name, tt := range map[string]struct {
		tunnel, probe bool
		probeUID      int
		probeGID      int
		want          string
	}{
		"probe without tunnel":   {false, true, 2000, 2000, "requires managed tunnel"},
		"probe as root":          {true, true, 0, 2000, "separate non-root"},
		"probe as the agent UID": {true, true, 1000, 2000, "separate non-root"},
		"probe in the agent GID": {true, true, 2000, 1000, "separate non-root"},
		"probe IDs missing":      {true, true, -1, -1, "separate non-root"},
		"IDs without the probe":  {true, false, 2000, 2000, "require -enable-probe"},
	} {
		err := run(1000, 1000, "/nonexistent/key", true, true, tt.tunnel, tt.probe, tt.probeUID, tt.probeGID)
		if err == nil || !strings.Contains(err.Error(), tt.want) {
			t.Errorf("%s: %v", name, err)
		}
	}
}
