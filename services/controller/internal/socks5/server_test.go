package socks5

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"
)

const (
	testUser = "user0123"
	testPass = "pass0123456789"
)

type tcpStream struct{ *net.TCPConn }

func (s tcpStream) BoundAddr() netip.AddrPort { return netip.MustParseAddrPort("10.0.0.2:40000") }

// echoServer echoes until the client half-closes, then closes.
func echoServer(t *testing.T) string {
	t.Helper()

	l, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })

	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}

			go func() {
				defer c.Close()
				_, _ = io.Copy(c, c)
			}()
		}
	}()

	return l.Addr().String()
}

type harness struct {
	dialed  atomic.Int32
	target  atomic.Value
	dialErr error
	echo    string
	done    chan error
	cancel  context.CancelFunc
}

func serve(t *testing.T, h *harness) *net.TCPConn {
	t.Helper()

	l, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })

	ctx, cancel := context.WithCancel(context.Background())
	h.cancel = cancel
	h.done = make(chan error, 1)
	t.Cleanup(cancel)

	dial := func(ctx context.Context, destination netip.AddrPort) (Stream, error) {
		h.dialed.Add(1)
		h.target.Store(destination)

		if h.dialErr != nil {
			return nil, h.dialErr
		}

		c, err := net.Dial("tcp4", h.echo)
		if err != nil {
			return nil, err
		}

		return tcpStream{c.(*net.TCPConn)}, nil
	}

	go func() {
		c, err := l.AcceptTCP()
		if err != nil {
			h.done <- err
			return
		}

		h.done <- ServeConn(ctx, c, testUser, testPass, dial)
	}()

	client, err := net.DialTCP("tcp4", nil, l.Addr().(*net.TCPAddr))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })

	_ = client.SetDeadline(time.Now().Add(10 * time.Second))

	return client
}

func expect(t *testing.T, c net.Conn, want []byte) {
	t.Helper()

	got := make([]byte, len(want))
	if _, err := io.ReadFull(c, got); err != nil || !bytes.Equal(got, want) {
		t.Fatalf("got %v (%v), want %v", got, err, want)
	}
}

func login(t *testing.T, c net.Conn, user, pass string) {
	t.Helper()

	if _, err := c.Write([]byte{5, 1, 2}); err != nil {
		t.Fatal(err)
	}

	expect(t, c, []byte{5, 2})

	msg := append([]byte{1, byte(len(user))}, user...)
	msg = append(msg, byte(len(pass)))
	msg = append(msg, pass...)

	if _, err := c.Write(msg); err != nil {
		t.Fatal(err)
	}
}

func connectRequest(destination netip.AddrPort) []byte {
	ip := destination.Addr().As4()
	msg := []byte{5, 1, 0, 1, ip[0], ip[1], ip[2], ip[3], 0, 0}
	binary.BigEndian.PutUint16(msg[8:], destination.Port())

	return msg
}

func TestConnectRelaysThroughDialFunc(t *testing.T) {
	h := &harness{echo: echoServer(t)}
	c := serve(t, h)

	login(t, c, testUser, testPass)
	expect(t, c, []byte{1, 0})

	if _, err := c.Write(connectRequest(netip.MustParseAddrPort("93.184.216.34:443"))); err != nil {
		t.Fatal(err)
	}

	expect(t, c, []byte{5, 0, 0, 1, 10, 0, 0, 2, 0x9c, 0x40})

	if target, _ := h.target.Load().(netip.AddrPort); target.String() != "93.184.216.34:443" {
		t.Fatalf("dialed %v", target)
	}

	if _, err := c.Write([]byte("hello")); err != nil {
		t.Fatal(err)
	}

	expect(t, c, []byte("hello"))

	// A half-close reaches the destination, whose close comes back.
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

func TestFragmentedGreeting(t *testing.T) {
	h := &harness{echo: echoServer(t)}
	c := serve(t, h)

	request := []byte{5, 1, 2, 1, byte(len(testUser))}
	request = append(request, testUser...)
	request = append(request, byte(len(testPass)))
	request = append(request, testPass...)

	go func() {
		for _, b := range request {
			_, _ = c.Write([]byte{b})
			time.Sleep(2 * time.Millisecond)
		}
	}()

	expect(t, c, []byte{5, 2})
	expect(t, c, []byte{1, 0})
}

func TestRefusals(t *testing.T) {
	for name, tt := range map[string]struct {
		user, pass string
		methods    []byte
		request    []byte
		dialErr    error
		want       []byte
	}{
		"wrong password":     {testUser, "wrong", nil, nil, nil, []byte{1, 1}},
		"wrong user":         {"other", testPass, nil, nil, nil, []byte{1, 1}},
		"no authentication":  {"", "", []byte{5, 1, 0}, nil, nil, []byte{5, 255}},
		"BIND":               {testUser, testPass, nil, []byte{5, 2, 0, 1, 93, 184, 216, 34, 1, 187}, nil, []byte{5, 7}},
		"UDP ASSOCIATE":      {testUser, testPass, nil, []byte{5, 3, 0, 1, 93, 184, 216, 34, 1, 187}, nil, []byte{5, 7}},
		"domain name":        {testUser, testPass, nil, []byte{5, 1, 0, 3, 11}, nil, []byte{5, 8}},
		"IPv6":               {testUser, testPass, nil, []byte{5, 1, 0, 4}, nil, []byte{5, 8}},
		"port zero":          {testUser, testPass, nil, []byte{5, 1, 0, 1, 93, 184, 216, 34, 0, 0}, nil, []byte{5, 2}},
		"destination denied": {testUser, testPass, nil, connectRequest(netip.MustParseAddrPort("1.1.1.1:443")), ErrNotAllowed, []byte{5, 2}},
		"dial failed":        {testUser, testPass, nil, connectRequest(netip.MustParseAddrPort("93.184.216.34:443")), errors.New("worker failed"), []byte{5, 1}},
	} {
		t.Run(name, func(t *testing.T) {
			h := &harness{echo: echoServer(t), dialErr: tt.dialErr}
			c := serve(t, h)

			if tt.methods != nil {
				if _, err := c.Write(tt.methods); err != nil {
					t.Fatal(err)
				}

				expect(t, c, tt.want)
			} else {
				login(t, c, tt.user, tt.pass)

				if tt.request == nil {
					expect(t, c, tt.want)
				} else {
					expect(t, c, []byte{1, 0})

					if _, err := c.Write(tt.request); err != nil {
						t.Fatal(err)
					}

					expect(t, c, tt.want)
				}
			}

			if err := <-h.done; err == nil {
				t.Fatal("refusal reported success")
			}

			if tt.dialErr == nil && h.dialed.Load() != 0 {
				t.Fatal("a refused request was dialed")
			}
		})
	}
}

func TestShutdownClosesStream(t *testing.T) {
	h := &harness{echo: echoServer(t)}
	c := serve(t, h)

	login(t, c, testUser, testPass)
	expect(t, c, []byte{1, 0})

	if _, err := c.Write(connectRequest(netip.MustParseAddrPort("93.184.216.34:443"))); err != nil {
		t.Fatal(err)
	}

	expect(t, c, []byte{5, 0, 0, 1, 10, 0, 0, 2, 0x9c, 0x40})

	h.cancel()

	select {
	case <-h.done:
	case <-time.After(5 * time.Second):
		t.Fatal("stream outlived its context")
	}

	if _, err := io.ReadAll(c); err != nil && !errors.Is(err, net.ErrClosed) {
		var opErr *net.OpError
		if !errors.As(err, &opErr) {
			t.Fatal(err)
		}
	}
}

type endingStream struct {
	tcpStream
	done chan struct{}
}

func (s endingStream) Done() <-chan struct{} { return s.done }

func connectThrough(t *testing.T, dial DialFunc) (*net.TCPConn, chan error) {
	t.Helper()

	l, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })

	done := make(chan error, 1)

	go func() {
		c, err := l.AcceptTCP()
		if err != nil {
			done <- err
			return
		}

		done <- ServeConn(context.Background(), c, testUser, testPass, dial)
	}()

	c, err := net.DialTCP("tcp4", nil, l.Addr().(*net.TCPAddr))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })

	_ = c.SetDeadline(time.Now().Add(10 * time.Second))

	login(t, c, testUser, testPass)
	expect(t, c, []byte{1, 0})

	if _, err := c.Write(connectRequest(netip.MustParseAddrPort("93.184.216.34:443"))); err != nil {
		t.Fatal(err)
	}

	expect(t, c, []byte{5, 0, 0, 1, 10, 0, 0, 2, 0x9c, 0x40})

	return c, done
}

// A stream that ended in the runtime closes an idle client at once.
func TestStreamEndClosesClient(t *testing.T) {
	echo := echoServer(t)
	ended := make(chan struct{})

	_, done := connectThrough(t, func(context.Context, netip.AddrPort) (Stream, error) {
		c, err := net.Dial("tcp4", echo)
		if err != nil {
			return nil, err
		}

		return endingStream{tcpStream{c.(*net.TCPConn)}, ended}, nil
	})

	close(ended)

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("an ended stream kept the client")
	}
}

// After the destination finished, an idle client no longer holds the connection.
func TestIdleClientAfterDestinationFin(t *testing.T) {
	saved := uploadIdleAfterFin
	uploadIdleAfterFin = 300 * time.Millisecond
	t.Cleanup(func() { uploadIdleAfterFin = saved })

	l, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })

	go func() {
		c, err := l.Accept()
		if err != nil {
			return
		}
		defer c.Close()

		_, _ = c.Write([]byte("bye"))
		_ = c.(*net.TCPConn).CloseWrite()
		_, _ = io.Copy(io.Discard, c)
	}()

	c, done := connectThrough(t, func(context.Context, netip.AddrPort) (Stream, error) {
		conn, err := net.Dial("tcp4", l.Addr().String())
		if err != nil {
			return nil, err
		}

		return tcpStream{conn.(*net.TCPConn)}, nil
	})

	if data, err := io.ReadAll(c); err != nil || string(data) != "bye" {
		t.Fatalf("download: %q %v", data, err)
	}

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("an idle client held the connection after the destination finished")
	}
}
