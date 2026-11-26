package main

import (
	"strings"
	"testing"
)

func TestServeSocksArguments(t *testing.T) {
	h := newHarness(t)
	id := "reservation_0123456789abcdef0123456789abcdef"

	if err := h.run("serve-socks", id, "1080"); err == nil || !strings.Contains(err.Error(), "requires -approve") {
		t.Fatal("an unapproved proxy accepted")
	}

	for _, args := range [][]string{
		{"-approve", "serve-socks"},
		{"-approve", "serve-socks", id},
		{"-approve", "serve-socks", "reservation_1", "1080"},
		{"-approve", "serve-socks", id, "80"},
		{"-approve", "serve-socks", id, "0"},
		{"-approve", "serve-socks", id, "65536"},
		{"-approve", "serve-socks", id, "01080"},
		{"-approve", "serve-socks", id, "1080", "extra"},
	} {
		if err := h.run(args...); err == nil || !strings.Contains(err.Error(), "usage") {
			t.Fatalf("invalid arguments accepted: %v: %v", args, err)
		}
	}

	if h.reached != 0 {
		t.Fatal("invalid arguments reached a runtime")
	}
}
