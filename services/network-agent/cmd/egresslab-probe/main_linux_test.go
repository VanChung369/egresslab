//go:build linux

package main

import (
	"os"
	"strings"
	"testing"
)

const droppedStatus = `Name:	egresslab-probe
CapInh:	0000000000000000
CapPrm:	0000000000000000
CapEff:	0000000000000000
CapBnd:	0000000000000000
CapAmb:	0000000000000000
NoNewPrivs:	1
`

func TestRequireProbePrivileges(t *testing.T) {
	// The test process itself is never fully dropped: it keeps a bounding set or runs as root.
	status, err := os.ReadFile("/proc/self/status")
	if err != nil {
		t.Fatal(err)
	}

	if err := requireProbePrivileges(string(status)); err == nil {
		t.Fatal("an undropped process passed the privilege check")
	}

	if err := checkProbeStatus(droppedStatus); err != nil {
		t.Fatalf("fully dropped status refused: %v", err)
	}

	for name, status := range map[string]string{
		"bounding set":    strings.Replace(droppedStatus, "CapBnd:\t0000000000000000", "CapBnd:\t000001ffffffffff", 1),
		"effective cap":   strings.Replace(droppedStatus, "CapEff:\t0000000000000000", "CapEff:\t0000000000001000", 1),
		"new privileges":  strings.Replace(droppedStatus, "NoNewPrivs:\t1", "NoNewPrivs:\t0", 1),
		"missing ambient": strings.Replace(droppedStatus, "CapAmb:\t0000000000000000\n", "", 1),
	} {
		if err := checkProbeStatus(status); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}
