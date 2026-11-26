package socks5

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"
)

func domainRequest(name string, port uint16) []byte {
	msg := append([]byte{5, 1, 0, 3, byte(len(name))}, name...)

	return binary.BigEndian.AppendUint16(msg, port)
}

func TestConnectByDomainName(t *testing.T) {
	var asked atomic.Value

	h := &harness{echo: echoServer(t), resolve: func(_ context.Context, name string) (netip.Addr, error) {
		asked.Store(name)
		return netip.MustParseAddr("93.184.216.34"), nil
	}}
	c := serve(t, h)

	login(t, c, testUser, testPass)
	expect(t, c, []byte{1, 0})

	if _, err := c.Write(domainRequest("example.com", 443)); err != nil {
		t.Fatal(err)
	}

	expect(t, c, []byte{5, 0, 0, 1, 10, 0, 0, 2, 0x9c, 0x40})

	if name, _ := asked.Load().(string); name != "example.com" {
		t.Fatalf("resolved %q", name)
	}

	// The resolved address is dialed like any IPv4 destination.
	if target, _ := h.target.Load().(netip.AddrPort); target.String() != "93.184.216.34:443" || h.dialed.Load() != 1 {
		t.Fatalf("dialed %v", target)
	}

	if _, err := c.Write([]byte("hello")); err != nil {
		t.Fatal(err)
	}

	expect(t, c, []byte("hello"))

	// The relay ends before the test does.
	if err := c.CloseWrite(); err != nil {
		t.Fatal(err)
	}

	if rest, err := io.ReadAll(c); err != nil || len(rest) != 0 {
		t.Fatalf("unexpected tail: %q %v", rest, err)
	}

	if err := <-h.done; err != nil {
		t.Fatal(err)
	}
}

// A lookup that fails after the original handshake deadline still gets its reply out.
func TestDomainFailureReplyAfterHandshakeDeadline(t *testing.T) {
	saved := handshakeTimeout
	handshakeTimeout = 600 * time.Millisecond
	t.Cleanup(func() { handshakeTimeout = saved })

	h := &harness{echo: echoServer(t), resolve: func(context.Context, string) (netip.Addr, error) {
		time.Sleep(400 * time.Millisecond)
		return netip.Addr{}, errors.New("DoH failed")
	}}
	c := serve(t, h)

	login(t, c, testUser, testPass)
	expect(t, c, []byte{1, 0})

	// Most of the original deadline is gone before the request arrives.
	time.Sleep(350 * time.Millisecond)

	if _, err := c.Write(domainRequest("example.com", 443)); err != nil {
		t.Fatal(err)
	}

	expect(t, c, []byte{5, 1})

	if err := <-h.done; err == nil {
		t.Fatal("failure reported success")
	}
}

func TestDomainRefusals(t *testing.T) {
	for name, tt := range map[string]struct {
		request    []byte
		resolved   netip.Addr
		resolveErr error
		dialErr    error
		want       []byte
		resolves   bool
	}{
		"resolution failed": {domainRequest("example.com", 443), netip.Addr{}, errors.New("DoH failed"), nil,
			[]byte{5, 1}, true},
		"name refused": {domainRequest("printer.local", 443), netip.Addr{}, ErrNotAllowed, nil, []byte{5, 2}, true},
		"not IPv4": {domainRequest("example.com", 443), netip.MustParseAddr("2001:db8::1"), nil, nil,
			[]byte{5, 1}, true},
		"answer refused by the dial": {domainRequest("example.com", 443), netip.MustParseAddr("1.1.1.1"), nil,
			ErrNotAllowed, []byte{5, 2}, true},
		"DNS port":          {domainRequest("example.com", 53), netip.Addr{}, nil, nil, []byte{5, 2}, false},
		"DNS over TLS port": {domainRequest("example.com", 853), netip.Addr{}, nil, nil, []byte{5, 2}, false},
		"port zero":         {domainRequest("example.com", 0), netip.Addr{}, nil, nil, []byte{5, 2}, false},
		"empty domain":      {domainRequest("", 443), netip.Addr{}, nil, nil, []byte{5, 1}, false},
		"IPv4 DNS port":     {connectRequest(netip.MustParseAddrPort("93.184.216.34:53")), netip.Addr{}, nil, nil, []byte{5, 2}, false},
	} {
		t.Run(name, func(t *testing.T) {
			var resolved atomic.Int32

			h := &harness{echo: echoServer(t), dialErr: tt.dialErr,
				resolve: func(context.Context, string) (netip.Addr, error) {
					resolved.Add(1)
					return tt.resolved, tt.resolveErr
				}}
			c := serve(t, h)

			login(t, c, testUser, testPass)
			expect(t, c, []byte{1, 0})

			if _, err := c.Write(tt.request); err != nil {
				t.Fatal(err)
			}

			expect(t, c, tt.want)

			if err := <-h.done; err == nil {
				t.Fatal("refusal reported success")
			}

			if (resolved.Load() == 1) != tt.resolves {
				t.Fatalf("resolver called %d times", resolved.Load())
			}

			if tt.dialErr == nil && h.dialed.Load() != 0 {
				t.Fatal("a refused request was dialed")
			}
		})
	}
}
