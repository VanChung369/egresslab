//go:build windows || linux || darwin

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/VanChung369/egresslab/services/controller/internal/control"
)

func TestServeEndpointArguments(t *testing.T) {
	h := newHarness(t)
	id := "proxy_0123456789abcdef"

	if err := h.run("serve-endpoint", id); err == nil || !strings.Contains(err.Error(), "requires -approve") {
		t.Fatal("unapproved endpoint accepted")
	}

	for _, args := range [][]string{
		{"-approve", "serve-endpoint"},
		{"-approve", "serve-endpoint", "invalid"},
		{"-approve", "serve-endpoint", id, "1080"},
		{"-approve", "-wsl-distro", "Ubuntu-B", "serve-endpoint", id},
		{"-approve", "-runtime", "lima", "serve-endpoint", id},
	} {
		if err := h.run(args...); err == nil {
			t.Fatalf("invalid arguments accepted: %v", args)
		}
	}

	if h.reached != 0 {
		t.Fatal("invalid request reached a runtime")
	}
}

func TestEndpointPlanLifecycle(t *testing.T) {
	h := newHarness(t)
	h.now = time.Now

	h.mustRun("-approve", "init-reservations")

	store, err := control.NewStore(filepath.Join(h.dir, "state.json"))
	if err != nil {
		t.Fatal(err)
	}

	endpoint, err := store.CreateEndpoint("Test SOCKS", "socks5", h.profile.ID, 1080)
	if err != nil {
		t.Fatal(err)
	}

	authority, err := control.OpenReservationAuthority(h.dir, h.keys)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := readEndpointPlan(h.dir, endpoint.ID, authority); err == nil {
		t.Fatal("unverified endpoint accepted")
	}

	setupReservationLab(t, h, "Ubuntu-A", h.profile.ID)
	h.mustRun("-approve", "-wsl-distro", "Ubuntu-A", "reserve-egress", h.profile.ID, labNS)

	holds := reservationList(t, h).Reservations
	if len(holds) != 1 {
		t.Fatal("expected one reservation")
	}

	plan, err := readEndpointPlan(h.dir, endpoint.ID, authority)
	if err != nil {
		t.Fatal(err)
	}

	if plan.EndpointID != endpoint.ID || plan.Port != 1080 || plan.ReservationID != holds[0].ID ||
		plan.Owner != holds[0].Owner || plan.IPv4 != holds[0].IPv4.String() || plan.Provider != "wsl" ||
		plan.Target != "Ubuntu-A" {
		t.Fatal("incorrect endpoint resolution")
	}

	if route, err := readEndpointRoute(h.dir, endpoint.ID); err != nil || route != plan.endpointRoute {
		t.Fatalf("route disagrees with the plan: %v", err)
	}

	if _, err := readEndpointPlan(h.dir, "proxy_ffffffffffffffff", authority); !errors.Is(err, control.ErrNotFound) {
		t.Fatalf("unknown endpoint accepted: %v", err)
	}

	// A released reservation can no longer open streams.
	h.mustRun("-approve", "-wsl-distro", "Ubuntu-A", "release-egress", holds[0].ID)

	if _, err := readEndpointPlan(h.dir, endpoint.ID, authority); !errors.Is(err, control.ErrReservationNotFound) {
		t.Fatalf("released endpoint accepted: %v", err)
	}

	// A later hold on the same helper keeps the route; only the pinned reservation tells them apart.
	h.mustRun("-approve", "-wsl-distro", "Ubuntu-A", "connect-tunnel", h.profile.ID, labNS, cliTestStage)
	h.mustRun("-approve", "-wsl-distro", "Ubuntu-A", "reserve-egress", h.profile.ID, labNS)

	next, err := readEndpointPlan(h.dir, endpoint.ID, authority)
	if err != nil || next.ReservationID == plan.ReservationID || next.endpointRoute != plan.endpointRoute {
		t.Fatalf("unexpected plan for the later hold: %v", err)
	}

	if _, err := authority.Lookup(plan.ReservationID); !errors.Is(err, control.ErrReservationNotFound) {
		t.Fatalf("the earlier reservation is still held: %v", err)
	}
}

func socksConnectCode(addr, user, pass string, destination netip.AddrPort) (byte, error) {
	c, err := net.DialTimeout("tcp4", addr, 5*time.Second)
	if err != nil {
		return 0, err
	}
	defer c.Close()

	_ = c.SetDeadline(time.Now().Add(10 * time.Second))

	ip := destination.Addr().As4()
	auth := append([]byte{1, byte(len(user))}, user...)
	auth = append(append(auth, byte(len(pass))), pass...)
	request := []byte{5, 1, 0, 1, ip[0], ip[1], ip[2], ip[3], byte(destination.Port() >> 8), byte(destination.Port())}

	reply := make([]byte, 2)

	for _, step := range []struct{ send, want []byte }{{[]byte{5, 1, 2}, []byte{5, 2}}, {auth, []byte{1, 0}}} {
		if _, err := c.Write(step.send); err != nil {
			return 0, err
		}

		if _, err := io.ReadFull(c, reply); err != nil || !bytes.Equal(reply, step.want) {
			return 0, fmt.Errorf("handshake: %v %v", reply, err)
		}
	}

	if _, err := c.Write(request); err != nil {
		return 0, err
	}

	if _, err := io.ReadFull(c, reply); err != nil || reply[0] != 5 {
		return 0, fmt.Errorf("no CONNECT reply: %v %v", reply, err)
	}

	return reply[1], nil
}

func freeLoopbackPort(t *testing.T) int {
	t.Helper()

	l, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()

	return l.Addr().(*net.TCPAddr).Port
}

var testSocksDestination = netip.MustParseAddrPort("93.184.216.34:443")

type endpointHarness struct {
	*harness
	rt       *fakeRuntime
	store    *control.Store
	endpoint control.ProxyEndpoint
	policy   recoveryPolicy
}

func newEndpointHarness(t *testing.T) *endpointHarness {
	t.Helper()

	h := newHarness(t)
	h.now = time.Now

	h.mustRun("-approve", "init-reservations")

	rt := setupReservationLab(t, h, "Ubuntu-A", h.profile.ID)
	h.mustRun("-approve", "-wsl-distro", "Ubuntu-A", "reserve-egress", h.profile.ID, labNS)

	store, err := control.NewStore(filepath.Join(h.dir, "state.json"))
	if err != nil {
		t.Fatal(err)
	}

	// Chosen last: the port stays free only for the moment until the listener binds it.
	endpoint, err := store.CreateEndpoint("Test SOCKS", "socks5", h.profile.ID, freeLoopbackPort(t))
	if err != nil {
		t.Fatal(err)
	}

	return &endpointHarness{harness: h, rt: rt, store: store, endpoint: endpoint}
}

type runningEndpoint struct {
	Listen, Username, Password string
	ReservationID              string `json:"reservation_id"`

	done <-chan error // the endpoint ended by itself
	stop func() error
}

func (e *runningEndpoint) connect(t *testing.T) byte {
	t.Helper()

	code, err := socksConnectCode(e.Listen, e.Username, e.Password, testSocksDestination)
	if err != nil {
		t.Fatal(err)
	}

	return code
}

// serve starts serve-endpoint in the background and reads its listener.
func (e *endpointHarness) serve(t *testing.T) *runningEndpoint {
	t.Helper()

	output, stdout := io.Pipe()
	d := e.deps()
	d.stdout = stdout

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	done := make(chan error, 1)

	go func() {
		done <- (&session{d: d, dataDir: e.dir, ctx: ctx}).serveEndpoint(e.endpoint.ID, e.policy)
		_ = stdout.Close()
	}()

	running := &runningEndpoint{done: done, stop: func() error {
		cancel()
		return <-done
	}}

	if err := json.NewDecoder(output).Decode(running); err != nil {
		t.Fatal(err)
	}

	go func() { _, _ = io.Copy(io.Discard, output) }()

	return running
}

// A running listener re-reads the endpoint after the helper call and the mint: a change during the
// helper call stops the stream before its capability is sent.
func TestServeEndpointRevalidatesEachConnect(t *testing.T) {
	e := newEndpointHarness(t)

	start := e.rt.helperInfoCalls
	e.rt.onHelperInfo = func(call int) {
		// The third call since start: the listener's own, the first CONNECT's, then this one.
		if call == start+3 {
			if err := e.store.DeleteEndpoint(e.endpoint.ID); err != nil {
				t.Error(err)
			}
		}
	}

	running := e.serve(t)

	// Allowed: minted and handed to the transport, whose fake refuses to open it.
	if code := running.connect(t); code != 1 {
		t.Fatalf("first CONNECT answered %d", code)
	}

	// The endpoint is deleted while the helper call runs.
	if code := running.connect(t); code != 2 {
		t.Fatalf("CONNECT after the change answered %d", code)
	}

	if err := running.stop(); err != nil {
		t.Fatal(err)
	}

	if len(e.rt.streamCalls) != 1 || e.rt.streamCalls[0].Claims.Intent.ReservationID != running.ReservationID ||
		e.rt.streamCalls[0].Claims.Intent.DestinationIPv4 != "93.184.216.34" {
		t.Fatalf("unexpected streams: %d", len(e.rt.streamCalls))
	}
}

// Several clients are authorized and opened at once, each with its own capability.
func TestServeEndpointConcurrentClients(t *testing.T) {
	e := newEndpointHarness(t)

	const clients = 3

	arrived := make(chan struct{}, clients)
	release := make(chan struct{})

	e.rt.onStream = func() {
		arrived <- struct{}{}
		<-release
	}

	running := e.serve(t)
	codes := make(chan byte, clients)

	for range clients {
		go func() {
			code, err := socksConnectCode(running.Listen, running.Username, running.Password, testSocksDestination)
			if err != nil {
				t.Error(err)
			}

			codes <- code
		}()
	}

	timeout := time.After(10 * time.Second)

	for range clients {
		select {
		case <-arrived:
		case <-timeout:
			close(release)
			t.Fatal("clients were not served at once")
		}
	}

	close(release)

	for range clients {
		if code := <-codes; code != 1 {
			t.Fatalf("CONNECT answered %d", code)
		}
	}

	if err := running.stop(); err != nil {
		t.Fatal(err)
	}

	nonces := map[string]bool{}
	for _, c := range e.rt.streamCalls {
		nonces[c.Claims.Nonce] = true
	}

	if len(e.rt.streamCalls) != clients || len(nonces) != clients {
		t.Fatalf("unexpected streams: %d, %d nonces", len(e.rt.streamCalls), len(nonces))
	}
}

// Only SOCKS5 on loopback is served.
func TestEndpointPlanRefusesOtherEndpoints(t *testing.T) {
	h := newHarness(t)
	h.mustRun("-approve", "init-reservations")

	store, err := control.NewStore(filepath.Join(h.dir, "state.json"))
	if err != nil {
		t.Fatal(err)
	}

	endpoint, err := store.CreateEndpoint("HTTP", "http-connect", h.profile.ID, 1082)
	if err != nil {
		t.Fatal(err)
	}

	authority, err := control.OpenReservationAuthority(h.dir, h.keys)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := readEndpointPlan(h.dir, endpoint.ID, authority); err == nil ||
		!strings.Contains(err.Error(), "only SOCKS5") {
		t.Fatalf("HTTP CONNECT endpoint accepted: %v", err)
	}
}
