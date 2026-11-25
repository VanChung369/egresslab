package agent

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"testing"
)

// The dialer below is a fake: no connection is made. 192.0.2.0/24 is a documentation range.
func TestPinnedProbeDial(t *testing.T) {
	ctx := context.Background()
	dialErr := errors.New("fake dial result")
	calls := 0

	fake := func(_ context.Context, network, address string) (net.Conn, error) {
		calls++

		if network != "tcp4" || address != "192.0.2.42:443" {
			t.Fatal("unexpected dial destination")
		}

		return nil, dialErr
	}

	dial := pinnedProbeDial(netip.MustParseAddr("192.0.2.42"), fake)

	for _, tt := range []struct{ network, address string }{
		{"tcp", "example.com:443"},
		{"tcp", "192.0.2.43:443"},
		{"tcp", "192.0.2.42:80"},
		{"tcp", "192.0.2.42:853"},
		{"tcp", "[2001:db8::1]:443"},
		{"tcp", "[::ffff:192.0.2.42]:443"},
		{"tcp", "192.0.2.42"},
		{"tcp6", "192.0.2.42:443"},
		{"udp", "192.0.2.42:443"},
		{"unix", "/run/resolver.sock"},
	} {
		if _, err := dial(ctx, tt.network, tt.address); !errors.Is(err, ErrProbeDestination) {
			t.Fatalf("unauthorized destination accepted: %s %s", tt.network, tt.address)
		}
	}

	if calls != 0 {
		t.Fatal("unauthorized request reached the dialer")
	}

	if _, err := dial(ctx, "tcp", "192.0.2.42:443"); !errors.Is(err, dialErr) || calls != 1 {
		t.Fatal("authorized destination not passed")
	}

	for name, unusable := range map[string]probeDialFunc{
		"IPv6 target": pinnedProbeDial(netip.MustParseAddr("2001:db8::1"), fake),
		"no dialer":   pinnedProbeDial(netip.MustParseAddr("192.0.2.42"), nil),
	} {
		if _, err := unusable(ctx, "tcp", "[2001:db8::1]:443"); !errors.Is(err, ErrProbeDestination) {
			t.Errorf("%s accepted", name)
		}
	}

	if calls != 1 {
		t.Fatal("an unusable dialer reached the network")
	}
}
