//go:build linux

package main

import (
	"strconv"
	"strings"
	"testing"
)

// Every combination here is refused before the pin file, the key, the socket or the kernel is touched.
func TestProbeFlagsRefused(t *testing.T) {
	for name, tt := range map[string]struct {
		tunnel, probe, multi bool
		probeUID             int
		probeGID             int
		want                 string
	}{
		"probe without tunnel":              {false, true, false, 2000, 2000, "requires managed tunnel"},
		"probe as root":                     {true, true, false, 0, 2000, "separate non-root"},
		"probe as the agent UID":            {true, true, false, 1000, 2000, "separate non-root"},
		"probe in the agent GID":            {true, true, false, 2000, 1000, "separate non-root"},
		"probe IDs missing":                 {true, true, false, -1, -1, "separate non-root"},
		"IDs without the probe":             {true, false, false, 2000, 2000, "require -enable-probe"},
		"both probe modes":                  {true, true, true, 2000, 2000, "mutually exclusive"},
		"multi-source probe without tunnel": {false, false, true, 2000, 2000, "requires managed tunnel"},
		"multi-source probe as the agent":   {true, false, true, 1000, 1000, "separate non-root"},
	} {
		err := run(1000, 1000, "/nonexistent/key", true, true, tt.tunnel, tt.probe, tt.probeUID, tt.probeGID, tt.multi,
			proxyFlags{uid: -1, gid: -1})
		if err == nil || !strings.Contains(err.Error(), tt.want) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestMultiProbeFlags(t *testing.T) {
	tests := map[string]struct {
		tunnel, single, multi bool
		uid, gid              int
		want                  string
	}{
		"no probe":                    {false, false, false, -1, -1, ""},
		"single-source mode":          {true, true, false, 2000, 2000, ""},
		"multi-source mode":           {true, false, true, 2000, 2000, ""},
		"both modes":                  {true, true, true, 2000, 2000, "mutually exclusive"},
		"multi-source without tunnel": {false, false, true, 2000, 2000, "requires managed tunnel"},
		"worker UID is root":          {true, false, true, 0, 2000, "separate non-root"},
		"worker GID is root":          {true, false, true, 2000, 0, "separate non-root"},
		"worker shares the agent UID": {true, false, true, 1000, 2000, "separate non-root"},
		"worker shares the agent GID": {true, false, true, 2000, 1000, "separate non-root"},
		"worker IDs missing":          {true, false, true, -1, -1, "separate non-root"},
		"worker IDs without a probe":  {true, false, false, 2000, 2000, "require -enable-probe"},
	}

	// An ID beyond 32 bits only exists where int is 64-bit; the value is built at run time so the
	// package still compiles on 32-bit Linux.
	if strconv.IntSize == 64 {
		wide := uint64(1) << 32
		tests["worker UID out of range"] = struct {
			tunnel, single, multi bool
			uid, gid              int
			want                  string
		}{true, false, true, int(wide), 2000, "separate non-root"}
	}

	tests["worker UID 2^31-1 accepted"] = struct {
		tunnel, single, multi bool
		uid, gid              int
		want                  string
	}{true, false, true, int(^uint32(0) >> 1), 2000, ""}

	for name, tt := range tests {
		err := validateProbeFlags(1000, 1000, tt.tunnel, tt.single, tt.multi, tt.uid, tt.gid)

		if tt.want == "" && err != nil {
			t.Errorf("%s: %v", name, err)
		}

		if tt.want != "" && (err == nil || !strings.Contains(err.Error(), tt.want)) {
			t.Errorf("%s: expected %q, got %v", name, tt.want, err)
		}
	}
}

// An agent ID beyond 32 bits would name the worker once truncated for the socket.
func TestAgentIDsBounded(t *testing.T) {
	refused := [][2]int{{0, 1000}, {1000, 0}, {-1, 1000}}

	if strconv.IntSize == 64 {
		wide := uint64(1) << 32
		refused = append(refused, [2]int{int(wide) + 2000, 1000}, [2]int{1000, int(wide) + 2000},
			[2]int{int(wide - 1), 1000})
	}

	for _, ids := range refused {
		err := validateProbeFlags(ids[0], ids[1], true, false, true, 2000, 2000)
		if err == nil || !strings.Contains(err.Error(), "agent UID and GID") {
			t.Errorf("agent IDs %v accepted: %v", ids, err)
		}
	}
}

// The proxy user is checked before the worker binary, the key, the socket or the kernel.
func TestProxyFlagsRefused(t *testing.T) {
	for name, tt := range map[string]struct {
		multi bool
		proxy proxyFlags
		want  string
	}{
		"IDs without the proxy":  {true, proxyFlags{false, 3000, 3000}, "require -enable-proxy"},
		"proxy without V2 probe": {false, proxyFlags{true, 3000, 3000}, "require -enable-multi-probe"},
		"proxy as root":          {true, proxyFlags{true, 0, 3000}, "separate non-root"},
		"proxy as the agent":     {true, proxyFlags{true, 1000, 3000}, "separate non-root"},
		"proxy in the agent GID": {true, proxyFlags{true, 3000, 1000}, "separate non-root"},
		"proxy as the prober":    {true, proxyFlags{true, 2000, 3000}, "separate non-root"},
		"proxy in the probe GID": {true, proxyFlags{true, 3000, 2000}, "separate non-root"},
		"proxy IDs missing":      {true, proxyFlags{true, -1, -1}, "separate non-root"},
	} {
		err := validateProxyFlags(tt.proxy, 1000, 1000, tt.multi, 2000, 2000)
		if err == nil || !strings.Contains(err.Error(), tt.want) {
			t.Errorf("%s: %v", name, err)
		}
	}

	if err := validateProxyFlags(proxyFlags{true, 3000, 3000}, 1000, 1000, true, 2000, 2000); err != nil {
		t.Fatal(err)
	}
}
