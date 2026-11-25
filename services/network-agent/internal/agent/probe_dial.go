package agent

import (
	"context"
	"errors"
	"net"
	"net/netip"
)

var ErrProbeDestination = errors.New("probe destination is not authorized")

type probeDialFunc func(ctx context.Context, network, address string) (net.Conn, error)

// pinnedProbeDial permits only the exact numeric IPv4 address on TCP port 443, whatever the HTTP
// client above it asks for. It never passes a hostname to the underlying dialer, so no resolver
// is ever consulted.
func pinnedProbeDial(target netip.Addr, dial probeDialFunc) probeDialFunc {
	return func(ctx context.Context, network, address string) (net.Conn, error) {
		if !target.Is4() || dial == nil {
			return nil, ErrProbeDestination
		}

		if network != "tcp" && network != "tcp4" {
			return nil, ErrProbeDestination
		}

		expected := netip.AddrPortFrom(target, 443).String()
		if address != expected {
			return nil, ErrProbeDestination
		}

		return dial(ctx, "tcp4", expected)
	}
}
