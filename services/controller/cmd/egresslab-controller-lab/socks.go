package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/signal"
	"strconv"
	"sync"
	"syscall"
	"time"

	"github.com/VanChung369/egresslab/services/controller/internal/control"
	"github.com/VanChung369/egresslab/services/controller/internal/labruntime"
	"github.com/VanChung369/egresslab/services/controller/internal/socks5"
)

const (
	proxySetupTimeout = 30 * time.Second

	// Up to socksMaxClients clients are served at once, as many as the helper admits streams per
	// runtime; a few more wait briefly for a slot, and the rest are refused.
	socksMaxClients = 32
	socksSlotWait   = 10 * time.Second
	socksMaxWaiting = 32
)

func validSocksPort(raw string) bool {
	port, err := strconv.ParseUint(raw, 10, 16)

	return err == nil && port >= 1024 && strconv.FormatUint(port, 10) == raw
}

func randomToken(n int) (string, error) {
	raw := make([]byte, n)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}

	return hex.EncodeToString(raw), nil
}

// serveSocks serves SOCKS5 on 127.0.0.1 only, up to socksMaxClients clients at once, in the
// foreground until interrupted. Every CONNECT is authorized on its own: the runtime's current helper epoch, a fresh
// signed capability for that one destination, and the helper's prepared lease and monitoring health.
// It changes no global readiness and opens nothing on the LAN.
func (s *session) serveSocks(reservationID, portArg string) error {
	authority, keys, err := s.openReservationAuthority()
	if err != nil {
		return err
	}

	hold, err := authority.Lookup(reservationID)
	if err != nil {
		return reservationCommandError(err)
	}

	route := &socksRoute{reservationID: reservationID, identIPv4: hold.IdentIPv4}

	return s.serveSocksWithAuthority(portArg, authority, keys, func() *socksRoute { return route })
}

// socksRoute is what one CONNECT is minted for: the hold, its ident pin for the resolver's answers,
// and the guard that must hold after the mint and before the capability is sent.
type socksRoute struct {
	reservationID string
	identIPv4     string
	guard         func() error
}

// errRouteRecovering refuses a CONNECT while an automatic recovery replaces the route.
var errRouteRecovering = errors.New("the route is being recovered")

// serveSocksWithAuthority reads route once per CONNECT; nil refuses it. The first route is the one
// printed at start.
func (s *session) serveSocksWithAuthority(portArg string, authority *control.ReservationAuthority,
	keys control.LabSigner, route func() *socksRoute) error {
	port, _ := strconv.ParseUint(portArg, 10, 16)

	first := route()
	if first == nil {
		return errRouteRecovering
	}

	trusted := func() (control.TrustedRuntime, error) {
		state, err := control.LoadRuntimeState(s.dataDir)
		if err != nil {
			return control.TrustedRuntime{}, err
		}

		rt, exists := state.RuntimeFor(s.provider.Kind(), s.provider.Target())
		if !exists {
			return control.TrustedRuntime{}, labruntime.Errorf(labruntime.CodeRuntimeUntrusted, "selected runtime is not trusted")
		}

		return rt, nil
	}

	if _, err := trusted(); err != nil {
		return err
	}

	transport := s.provider.Transport()

	streams, ok := transport.(labruntime.ProxyStreamTransport)
	if !ok {
		return labruntime.Errorf(labruntime.CodeOperationDisabled, "runtime has no proxy stream transport")
	}

	listener, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: int(port)})
	if err != nil {
		return err
	}
	defer listener.Close()

	username, err := randomToken(8)
	if err != nil {
		return err
	}

	password, err := randomToken(16)
	if err != nil {
		return err
	}

	parent := s.ctx
	if parent == nil {
		parent = context.Background()
	}

	ctx, stop := signal.NotifyContext(parent, os.Interrupt, syscall.SIGTERM)
	defer stop()

	go func() {
		<-ctx.Done()
		_ = listener.Close()
	}()

	if err := s.print(struct {
		Listen        string `json:"listen"`
		Username      string `json:"username"`
		Password      string `json:"password"`
		ReservationID string `json:"reservation_id"`
		NetworkReady  bool   `json:"network_ready"`
	}{listener.Addr().String(), username, password, first.reservationID, false}); err != nil {
		return err
	}

	// A client is served on the route it found when it connected, for its DNS and its CONNECT: a
	// recovery meanwhile never mixes the old route with the new one. Without a route, both refuse.
	handlers := func(current *socksRoute) (socks5.DialFunc, socks5.ResolveFunc) {
		dial := func(ctx context.Context, destination netip.AddrPort) (socks5.Stream, error) {
			if current == nil {
				return nil, errors.Join(socks5.ErrNotAllowed, errRouteRecovering)
			}

			// The trust record is read again for every CONNECT: untrust-runtime stops new streams.
			rt, err := trusted()
			if err != nil {
				return nil, err
			}

			// Bounded setup; the stream itself lives on ctx.
			setup, cancel := context.WithTimeout(ctx, proxySetupTimeout)
			defer cancel()

			helper, err := transport.HelperInfo(setup)
			if err != nil {
				return nil, err
			}

			capability, err := authority.MintProxyStream(current.reservationID, destination, keys, rt, helper, s.d.now())
			if err != nil {
				if errors.Is(err, control.ErrProxyDestinationNotAllowed) {
					return nil, socks5.ErrNotAllowed
				}

				if errors.Is(err, control.ErrReservationReleaseInvalid) || errors.Is(err, control.ErrReservationNotFound) {
					return nil, errors.Join(socks5.ErrNotAllowed, err)
				}

				return nil, err
			}

			// The last check before the capability leaves the controller; a refused one is discarded.
			if current.guard != nil {
				if err := current.guard(); err != nil {
					return nil, errors.Join(socks5.ErrNotAllowed, err)
				}
			}

			return streams.OpenProxyStream(ctx, capability)
		}

		// DNS goes through dial too: the same trust, reservation, binding and signed capability checks.
		// Answers the mint would refuse (the probe sources, say) are skipped; the port is checked before
		// resolution and again by the mint.
		resolve := socks5.NewIsolatedResolver(dial, func(ip netip.Addr) bool {
			return current != nil && control.ValidLabProxyDestination(netip.AddrPortFrom(ip, 443), current.identIPv4)
		})

		return dial, resolve
	}

	slot := make(chan struct{}, socksMaxClients)
	waiting := make(chan struct{}, socksMaxWaiting)

	var clients sync.WaitGroup

	// A listener failure cancels the clients before waiting for them.
	defer func() {
		stop()
		clients.Wait()
	}()

	for {
		conn, err := listener.AcceptTCP()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}

			return err
		}

		select {
		case waiting <- struct{}{}:
		default:
			_ = conn.Close()
			continue
		}

		clients.Add(1)

		go func() {
			defer clients.Done()

			timer := time.NewTimer(socksSlotWait)
			defer timer.Stop()

			select {
			case slot <- struct{}{}:
				<-waiting
			case <-timer.C:
				<-waiting
				_ = conn.Close()

				return
			case <-ctx.Done():
				<-waiting
				_ = conn.Close()

				return
			}

			defer func() { <-slot }()

			dial, resolve := handlers(route())

			if err := socks5.ServeConnWithResolver(ctx, conn, username, password, dial, resolve); err != nil {
				fmt.Fprintln(os.Stderr, "serve-socks:", err)
			}
		}()
	}
}
