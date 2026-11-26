// Package socks5 serves one SOCKS5 CONNECT (RFC 1928) with username/password authentication
// (RFC 1929), to an IPv4 address or a domain name. It never dials and never asks the host's
// resolver: every connection, DNS queries included, goes through DialFunc, which the trusted runtime
// transport provides.
package socks5

import (
	"context"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"
)

// handshakeTimeout bounds the handshake, and since Step 35 again a name's resolution and the dial.
var handshakeTimeout = time.Minute

// uploadIdleAfterFin bounds a client that keeps its side open after the destination finished.
var uploadIdleAfterFin = 30 * time.Second

// Reply codes (RFC 1928, section 6).
const (
	replySucceeded           = 0
	replyGeneralFailure      = 1
	replyNotAllowed          = 2
	replyCommandNotSupported = 7
	replyAddressNotSupported = 8
)

// ErrNotAllowed: DialFunc refuses the destination by policy.
var ErrNotAllowed = errors.New("destination not allowed")

type Stream interface {
	io.ReadWriteCloser
	CloseWrite() error
	BoundAddr() netip.AddrPort
}

type DialFunc func(context.Context, netip.AddrPort) (Stream, error)

// ServeConn serves one client and closes it. Domain names, IPv6, BIND and UDP ASSOCIATE are refused.
func ServeConn(ctx context.Context, client *net.TCPConn, username, password string, dial DialFunc) error {
	return ServeConnWithResolver(ctx, client, username, password, dial, nil)
}

// ServeConnWithResolver is ServeConn that also accepts domain names, resolved by resolve; the
// resolved address then goes through dial like any IPv4 destination. Without resolve, domain names
// are refused.
func ServeConnWithResolver(ctx context.Context, client *net.TCPConn, username, password string, dial DialFunc,
	resolve ResolveFunc) error {
	defer client.Close()

	stop := context.AfterFunc(ctx, func() { _ = client.Close() })
	defer stop()

	_ = client.SetDeadline(time.Now().Add(handshakeTimeout))

	if err := authenticate(client, username, password); err != nil {
		return err
	}

	var header [4]byte
	if _, err := io.ReadFull(client, header[:]); err != nil {
		return err
	}

	if header[0] != 5 || header[2] != 0 {
		return errors.New("invalid SOCKS5 request")
	}

	if header[1] != 1 {
		_ = reply(client, replyCommandNotSupported, netip.AddrPort{})
		return errors.New("unsupported SOCKS5 command")
	}

	var ip netip.Addr
	var domain string

	switch header[3] {
	case 1: // IPv4
		var raw [4]byte
		if _, err := io.ReadFull(client, raw[:]); err != nil {
			return err
		}

		ip = netip.AddrFrom4(raw)

	case 3: // domain name
		if resolve == nil {
			_ = reply(client, replyAddressNotSupported, netip.AddrPort{})
			return errors.New("domain resolution unavailable")
		}

		var length [1]byte
		if _, err := io.ReadFull(client, length[:]); err != nil {
			return err
		}

		if length[0] == 0 {
			_ = reply(client, replyGeneralFailure, netip.AddrPort{})
			return errors.New("empty domain")
		}

		raw := make([]byte, int(length[0]))
		if _, err := io.ReadFull(client, raw); err != nil {
			return err
		}

		domain = string(raw)

	default:
		_ = reply(client, replyAddressNotSupported, netip.AddrPort{})
		return errors.New("only IPv4 destinations and domain names are supported")
	}

	var portBytes [2]byte
	if _, err := io.ReadFull(client, portBytes[:]); err != nil {
		return err
	}

	port := binary.BigEndian.Uint16(portBytes[:])

	// Refused before anything is resolved.
	if port == 0 || port == 53 || port == 853 {
		_ = reply(client, replyNotAllowed, netip.AddrPort{})
		return ErrNotAllowed
	}

	if domain != "" {
		// Resolution starts the budget over, so that even a failure still gets its reply out.
		_ = client.SetDeadline(time.Now().Add(handshakeTimeout))

		resolved, err := resolve(ctx, domain)
		if err == nil && !resolved.Is4() {
			err = errDNSNoAnswer
		}

		if err != nil {
			code := byte(replyGeneralFailure)
			if errors.Is(err, ErrNotAllowed) {
				code = replyNotAllowed
			}

			_ = reply(client, code, netip.AddrPort{})

			return fmt.Errorf("isolated DNS resolution failed: %w", err)
		}

		ip = resolved

		// The dial keeps the budget it had without a name to resolve.
		_ = client.SetDeadline(time.Now().Add(handshakeTimeout))
	}

	destination := netip.AddrPortFrom(ip, port)

	target, err := dial(ctx, destination)
	if err != nil {
		code := byte(replyGeneralFailure)
		if errors.Is(err, ErrNotAllowed) {
			code = replyNotAllowed
		}

		_ = reply(client, code, netip.AddrPort{})

		return err
	}
	defer target.Close()

	if err := reply(client, replySucceeded, target.BoundAddr()); err != nil {
		return err
	}

	_ = client.SetDeadline(time.Time{})

	finished := make(chan struct{})
	defer close(finished)

	// A stream that ended in the runtime ends the client at once.
	if ender, ok := target.(interface{ Done() <-chan struct{} }); ok {
		go func() {
			select {
			case <-ender.Done():
				_ = client.Close()
				_ = target.Close()
			case <-finished:
			}
		}()
	}

	var downloaded atomic.Bool

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()

		buf := make([]byte, 32*1024)

		for {
			if downloaded.Load() {
				_ = client.SetReadDeadline(time.Now().Add(uploadIdleAfterFin))
			}

			n, err := client.Read(buf)
			if n > 0 {
				if _, werr := target.Write(buf[:n]); werr != nil {
					_ = target.Close()
					_ = client.Close()

					return
				}
			}

			if errors.Is(err, io.EOF) {
				_ = target.CloseWrite()
				return
			}

			if err != nil {
				_ = target.Close()
				_ = client.Close()

				return
			}
		}
	}()

	go func() {
		defer wg.Done()

		if _, err := io.Copy(client, target); err != nil {
			_ = target.Close()
			_ = client.Close()

			return
		}

		_ = client.CloseWrite()

		// The upload may go on, but no longer idle forever.
		downloaded.Store(true)
		_ = client.SetReadDeadline(time.Now().Add(uploadIdleAfterFin))
	}()

	wg.Wait()

	return nil
}

// authenticate offers only username/password and compares both in constant time.
func authenticate(conn net.Conn, username, password string) error {
	var greeting [2]byte
	if _, err := io.ReadFull(conn, greeting[:]); err != nil {
		return err
	}

	if greeting[0] != 5 || greeting[1] == 0 {
		return errors.New("invalid SOCKS5 greeting")
	}

	methods := make([]byte, int(greeting[1]))
	if _, err := io.ReadFull(conn, methods); err != nil {
		return err
	}

	supported := false

	for _, method := range methods {
		if method == 2 {
			supported = true
		}
	}

	if !supported {
		_, _ = conn.Write([]byte{5, 255})
		return errors.New("username/password authentication required")
	}

	if _, err := conn.Write([]byte{5, 2}); err != nil {
		return err
	}

	var authHeader [2]byte
	if _, err := io.ReadFull(conn, authHeader[:]); err != nil {
		return err
	}

	if authHeader[0] != 1 || authHeader[1] == 0 {
		return errors.New("invalid SOCKS5 authentication")
	}

	user := make([]byte, int(authHeader[1]))
	if _, err := io.ReadFull(conn, user); err != nil {
		return err
	}

	var length [1]byte
	if _, err := io.ReadFull(conn, length[:]); err != nil {
		return err
	}

	pass := make([]byte, int(length[0]))
	defer clear(pass)

	if _, err := io.ReadFull(conn, pass); err != nil {
		return err
	}

	validUser := subtle.ConstantTimeCompare(user, []byte(username))
	validPass := subtle.ConstantTimeCompare(pass, []byte(password))

	if validUser&validPass != 1 || username == "" || password == "" {
		_, _ = conn.Write([]byte{1, 1})
		return errors.New("SOCKS5 authentication denied")
	}

	_, err := conn.Write([]byte{1, 0})

	return err
}

func reply(conn net.Conn, code byte, bound netip.AddrPort) error {
	response := []byte{5, code, 0, 1, 0, 0, 0, 0, 0, 0}

	if code == replySucceeded && bound.Addr().Is4() {
		ip := bound.Addr().As4()
		copy(response[4:8], ip[:])
		binary.BigEndian.PutUint16(response[8:], bound.Port())
	}

	_, err := conn.Write(response)

	return err
}
