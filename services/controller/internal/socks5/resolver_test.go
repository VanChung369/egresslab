package socks5

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/netip"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// testCertificate is a self-signed certificate for name, and a pool trusting only it.
func testCertificate(t *testing.T, name string) (tls.Certificate, *x509.CertPool) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: name},
		DNSNames:              []string{name},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}

	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}

	pool := x509.NewCertPool()
	pool.AddCert(leaf)

	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}, pool
}

// dohServer serves handler over TLS with cert on a loopback port; tls false accepts TCP and never
// answers.
func dohServer(t *testing.T, cert tls.Certificate, handler http.HandlerFunc, useTLS bool) string {
	t.Helper()

	l, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })

	if !useTLS {
		go func() {
			var held []net.Conn

			for {
				c, err := l.Accept()
				if err != nil {
					for _, c := range held {
						_ = c.Close()
					}

					return
				}

				held = append(held, c)
			}
		}()

		return l.Addr().String()
	}

	server := &http.Server{Handler: handler, ReadHeaderTimeout: 5 * time.Second}
	t.Cleanup(func() { _ = server.Close() })

	go func() {
		_ = server.Serve(tls.NewListener(l, &tls.Config{Certificates: []tls.Certificate{cert}}))
	}()

	return l.Addr().String()
}

// routeStream is a stream of one route: it lives on the context it was dialed with, as the runtime's
// proxy stream does.
type routeStream struct {
	*net.TCPConn
	closed atomic.Bool
}

func (s *routeStream) Close() error {
	s.closed.Store(true)
	return s.TCPConn.Close()
}

func (s *routeStream) BoundAddr() netip.AddrPort { return netip.MustParseAddrPort("10.0.0.2:40000") }

type route struct {
	server  string
	dialErr error

	mu      sync.Mutex
	dialed  []netip.AddrPort
	streams []*routeStream
}

func (r *route) dial(ctx context.Context, destination netip.AddrPort) (Stream, error) {
	r.mu.Lock()
	r.dialed = append(r.dialed, destination)
	r.mu.Unlock()

	if r.dialErr != nil {
		return nil, r.dialErr
	}

	c, err := net.Dial("tcp4", r.server)
	if err != nil {
		return nil, err
	}

	s := &routeStream{TCPConn: c.(*net.TCPConn)}
	context.AfterFunc(ctx, func() { _ = s.Close() })

	r.mu.Lock()
	r.streams = append(r.streams, s)
	r.mu.Unlock()

	return s, nil
}

func (r *route) allClosed() bool {
	r.mu.Lock()
	defer r.mu.Unlock()

	for _, s := range r.streams {
		if !s.closed.Load() {
			return false
		}
	}

	return true
}

func answer(name string, records ...string) string {
	return fmt.Sprintf(`{"Status":0,"TC":false,"RD":true,"RA":true,"AD":false,"CD":false,`+
		`"Question":[{"name":"%s.","type":1}],"Answer":[%s]}`, name, strings.Join(records, ","))
}

func record(name string, kind int, data string) string {
	return fmt.Sprintf(`{"name":"%s.","type":%d,"TTL":60,"data":"%s"}`, name, kind, data)
}

// aliasChain answers n0.example.com through n CNAMEs, n0 to nN, nN with an address.
func aliasChain(n int) string {
	records := make([]string, 0, n+1)
	for i := range n {
		records = append(records, record(fmt.Sprintf("n%d.example.com", i), 5, fmt.Sprintf("n%d.example.com.", i+1)))
	}

	records = append(records, record(fmt.Sprintf("n%d.example.com", n), 1, "93.184.216.37"))

	return answer("n0.example.com", records...)
}

func TestIsolatedResolver(t *testing.T) {
	cert, roots := testCertificate(t, dohName)
	otherCert, otherRoots := testCertificate(t, "example.net")

	tests := []struct {
		name     string
		query    string
		body     string
		status   int
		redirect bool
		cert     *tls.Certificate
		roots    *x509.CertPool
		dialErr  error
		want     string
		noDial   bool

		hostnameErr bool // trusted certificate, refused for its name alone
	}{
		{name: "A record", query: "example.com", body: answer("example.com", record("example.com", 1, "93.184.216.34")),
			want: "93.184.216.34"},
		{name: "upper case and trailing dot", query: "Example.COM.",
			body: answer("example.com", record("example.com", 1, "93.184.216.34")), want: "93.184.216.34"},
		{name: "CNAME chain", query: "www.example.com", body: answer("www.example.com",
			record("www.example.com", 5, "edge.example.net."), record("edge.example.net", 1, "93.184.216.35")),
			want: "93.184.216.35"},
		{name: "private address", query: "example.com",
			body: answer("example.com", record("example.com", 1, "10.0.0.7"))},
		{name: "loopback address", query: "example.com",
			body: answer("example.com", record("example.com", 1, "127.0.0.1"))},
		{name: "IPv6 only", query: "example.com",
			body: answer("example.com", record("example.com", 28, "2001:db8::1"))},
		{name: "CNAME loop", query: "a.example.com", body: answer("a.example.com",
			record("a.example.com", 5, "b.example.com."), record("b.example.com", 5, "a.example.com."))},
		{name: "two aliases", query: "a.example.com", body: answer("a.example.com",
			record("a.example.com", 5, "b.example.com."), record("a.example.com", 5, "c.example.com."))},
		{name: "answer for another name", query: "example.com",
			body: answer("example.com", record("example.org", 1, "93.184.216.34"))},
		{name: "question for another name", query: "example.com",
			body: answer("example.org", record("example.com", 1, "93.184.216.34"))},
		{name: "NXDOMAIN", query: "example.com", body: `{"Status":3,"TC":false,"Question":[{"name":"example.com.","type":1}]}`},
		{name: "truncated", query: "example.com", body: strings.Replace(answer("example.com",
			record("example.com", 1, "93.184.216.34")), `"TC":false`, `"TC":true`, 1)},
		{name: "no status", query: "example.com", body: `{"Question":[{"name":"example.com.","type":1}]}`},
		{name: "not JSON", query: "example.com", body: "<html></html>"},
		{name: "oversized", query: "example.com", body: strings.Repeat(" ", maxDNSResponse+1)},
		{name: "server error", query: "example.com", status: http.StatusInternalServerError},
		{name: "redirect", query: "example.com", redirect: true},
		{name: "untrusted certificate", query: "example.com", roots: otherRoots,
			body: answer("example.com", record("example.com", 1, "93.184.216.34"))},
		{name: "certificate for another name", query: "example.com", cert: &otherCert, roots: otherRoots,
			hostnameErr: true, body: answer("example.com", record("example.com", 1, "93.184.216.34"))},
		{name: "CGNAT before a public address", query: "example.com", body: answer("example.com",
			record("example.com", 1, "100.64.0.1"), record("example.com", 1, "93.184.216.36")), want: "93.184.216.36"},
		{name: "documentation address", query: "example.com",
			body: answer("example.com", record("example.com", 1, "192.0.2.1"))},
		{name: "eight aliases", query: "n0.example.com", body: aliasChain(8), want: "93.184.216.37"},
		{name: "nine aliases", query: "n0.example.com", body: aliasChain(9)},
		{name: "address beside an alias", query: "a.example.com", body: answer("a.example.com",
			record("a.example.com", 1, "93.184.216.34"), record("a.example.com", 5, "b.example.com."),
			record("b.example.com", 1, "93.184.216.35"))},
		{name: "invalid alias after an address", query: "a.example.com", body: answer("a.example.com",
			record("a.example.com", 1, "93.184.216.34"), record("a.example.com", 5, "bad_name.example.com."))},
		{name: "empty domain", query: "", noDial: true},
		{name: "alias beside a malformed address", query: "a.example.com", body: answer("a.example.com",
			record("a.example.com", 5, "b.example.com."), record("a.example.com", 1, "not-an-address"),
			record("b.example.com", 1, "93.184.216.35"))},
		{name: "alias beside an IPv6 address", query: "a.example.com", body: answer("a.example.com",
			record("a.example.com", 5, "b.example.com."), record("a.example.com", 28, "2001:db8::1"),
			record("b.example.com", 1, "93.184.216.35"))},
		{name: "the same alias twice", query: "a.example.com", body: answer("a.example.com",
			record("a.example.com", 5, "b.example.com."), record("a.example.com", 5, "b.example.com."),
			record("b.example.com", 1, "93.184.216.35"))},
		{name: "dial refused", query: "example.com", dialErr: ErrNotAllowed},
		{name: "localhost", query: "localhost", noDial: true},
		{name: "mDNS", query: "printer.local", noDial: true},
		{name: "onion", query: "abc.onion", noDial: true},
		{name: "underscore", query: "a_b.example.com", noDial: true},
		{name: "empty label", query: "a..example.com", noDial: true},
		{name: "too long", query: strings.Repeat("a", 64) + ".example.com", noDial: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			serverCert := cert
			if tt.cert != nil {
				serverCert = *tt.cert
			}

			trusted := roots
			if tt.roots != nil {
				trusted = tt.roots
			}

			var requests atomic.Int32

			server := dohServer(t, serverCert, func(w http.ResponseWriter, r *http.Request) {
				requests.Add(1)

				q := r.URL.Query()
				if r.Host != dohName || r.URL.Path != "/resolve" || q.Get("type") != "A" ||
					q.Get("edns_client_subnet") != "0.0.0.0/0" || q.Get("name") != canonicalDNSName(tt.query) ||
					r.Header.Get("Accept") != "application/dns-json" {
					t.Errorf("unexpected DNS request: %s %s %v", r.Host, r.URL.Path, q)
				}

				switch {
				case tt.redirect:
					http.Redirect(w, r, "https://dns.google/elsewhere", http.StatusFound)
				case tt.status != 0:
					w.WriteHeader(tt.status)
				default:
					_, _ = w.Write([]byte(tt.body))
				}
			}, true)

			via := &route{server: server, dialErr: tt.dialErr}

			ip, err := newIsolatedResolver(via.dial, trusted, nil)(context.Background(), tt.query)

			if tt.want != "" {
				if err != nil || ip.String() != tt.want {
					t.Fatalf("resolved %v, %v; want %s", ip, err, tt.want)
				}
			} else if err == nil {
				t.Fatalf("unsafe answer accepted: %v", ip)
			}

			if tt.noDial {
				if !errors.Is(err, ErrNotAllowed) || len(via.dialed) != 0 {
					t.Fatalf("invalid name reached the network: %v", err)
				}

				return
			}

			// One stream, to the fixed resolver address, closed by the time the query returns.
			if len(via.dialed) != 1 || via.dialed[0] != dohAddress || !via.allClosed() {
				t.Fatalf("unexpected streams: %v closed=%v", via.dialed, via.allClosed())
			}

			var hostname x509.HostnameError
			if tt.hostnameErr && !errors.As(err, &hostname) {
				t.Fatalf("not refused for its name: %v", err)
			}

			// Refused as a redirect, not only by the one-stream limit behind it.
			if tt.redirect && (requests.Load() != 1 || !errors.Is(err, errDNSRedirect)) {
				t.Fatalf("redirect followed: %v", err)
			}
		})
	}
}

// The built-in roots are the only trust: a certificate the test trusts elsewhere is refused.
func TestIsolatedResolverBuiltInRoots(t *testing.T) {
	files, _ := dohRootFiles.ReadDir("dohroots")
	if roots, err := dohRoots(); err != nil || roots == nil || len(files) != 3 {
		t.Fatalf("built-in roots: %v", err)
	}

	cert, _ := testCertificate(t, dohName)
	via := &route{server: dohServer(t, cert, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(answer("example.com", record("example.com", 1, "93.184.216.34"))))
	}, true)}

	var unknown x509.UnknownAuthorityError
	if _, err := NewIsolatedResolver(via.dial, nil)(context.Background(), "example.com"); !errors.As(err, &unknown) {
		t.Fatalf("certificate outside the built-in roots accepted: %v", err)
	}
}

// The built-in roots verify the chain dns.google served on 2026-11-26 (testdata, recorded through a
// direct connection), at that time.
func TestDoHRootsVerifyServedChain(t *testing.T) {
	data, err := os.ReadFile("testdata/dns-google-chain.pem")
	if err != nil {
		t.Fatal(err)
	}

	var chain []*x509.Certificate

	for block, rest := pem.Decode(data); block != nil; block, rest = pem.Decode(rest) {
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			t.Fatal(err)
		}

		chain = append(chain, cert)
	}

	intermediates := x509.NewCertPool()
	for _, cert := range chain[1:] {
		intermediates.AddCert(cert)
	}

	roots, err := dohRoots()
	if err != nil {
		t.Fatal(err)
	}

	opts := x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates,
		DNSName:       dohName,
		CurrentTime:   time.Date(2026, 11, 26, 15, 17, 42, 0, time.UTC),
	}

	if _, err := chain[0].Verify(opts); err != nil {
		t.Fatalf("built-in roots refused dns.google's chain: %v", err)
	}

	opts.Roots = x509.NewCertPool()
	if _, err := chain[0].Verify(opts); err == nil {
		t.Fatal("chain verified without a root")
	}
}

// accept skips answers the destination policy would refuse, and a later allowed one is taken.
func TestIsolatedResolverSkipsRefusedAnswers(t *testing.T) {
	cert, roots := testCertificate(t, dohName)
	via := &route{server: dohServer(t, cert, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(answer("one.example.com", record("one.example.com", 1, "1.1.1.1"),
			record("one.example.com", 1, "1.0.0.1"))))
	}, true)}

	refuse := func(ip netip.Addr) bool { return ip.String() != "1.1.1.1" }

	if ip, err := newIsolatedResolver(via.dial, roots, refuse)(context.Background(), "one.example.com"); err != nil ||
		ip.String() != "1.0.0.1" {
		t.Fatalf("resolved %v, %v", ip, err)
	}

	none := func(netip.Addr) bool { return false }

	if _, err := newIsolatedResolver(via.dial, roots, none)(context.Background(), "one.example.com"); !errors.Is(err, errDNSNoAnswer) {
		t.Fatalf("refused answers taken: %v", err)
	}
}

// exitingStream ends in the runtime some time after Close, as helperctl does.
type exitingStream struct {
	*routeStream
	exited chan struct{}
	once   sync.Once
	delay  time.Duration
	onWait func() // called when the resolver starts waiting for the exit
}

func (s *exitingStream) Close() error {
	delay := s.delay
	if delay == 0 {
		delay = 200 * time.Millisecond
	}

	s.once.Do(func() { time.AfterFunc(delay, func() { close(s.exited) }) })

	return s.routeStream.Close()
}

func (s *exitingStream) Exited() <-chan struct{} {
	if s.onWait != nil {
		s.onWait()
	}

	return s.exited
}

// The query returns only once its stream has ended in the runtime, so its slot is free for the CONNECT.
func TestIsolatedResolverWaitsForStreamExit(t *testing.T) {
	cert, roots := testCertificate(t, dohName)
	via := &route{server: dohServer(t, cert, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(answer("example.com", record("example.com", 1, "93.184.216.34"))))
	}, true)}

	var stream *exitingStream

	dial := func(ctx context.Context, destination netip.AddrPort) (Stream, error) {
		s, err := via.dial(ctx, destination)
		if err != nil {
			return nil, err
		}

		stream = &exitingStream{routeStream: s.(*routeStream), exited: make(chan struct{})}

		return stream, nil
	}

	if _, err := newIsolatedResolver(dial, roots, nil)(context.Background(), "example.com"); err != nil {
		t.Fatal(err)
	}

	select {
	case <-stream.exited:
	default:
		t.Fatal("query returned before its stream ended")
	}
}

// A failed query is followed by no CONNECT and does not wait for its stream; a waiting query stops
// when its client leaves.
func TestIsolatedResolverWaitsOnlyForAnswers(t *testing.T) {
	cert, roots := testCertificate(t, dohName)

	for _, mode := range []string{"failure", "client left"} {
		t.Run(mode, func(t *testing.T) {
			via := &route{server: dohServer(t, cert, func(w http.ResponseWriter, _ *http.Request) {
				if mode == "failure" {
					w.WriteHeader(http.StatusServiceUnavailable)
					return
				}

				_, _ = w.Write([]byte(answer("example.com", record("example.com", 1, "93.184.216.34"))))
			}, true)}

			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			dial := func(dialCtx context.Context, destination netip.AddrPort) (Stream, error) {
				s, err := via.dial(dialCtx, destination)
				if err != nil {
					return nil, err
				}

				stream := &exitingStream{routeStream: s.(*routeStream), exited: make(chan struct{}), delay: time.Minute}
				if mode == "client left" {
					// The caller leaves exactly while the resolver waits for the stream.
					stream.onWait = cancel
				}

				return stream, nil
			}

			start := time.Now()
			ip, err := newIsolatedResolver(dial, roots, nil)(ctx, "example.com")

			if elapsed := time.Since(start); elapsed > 2*time.Second {
				t.Fatalf("query waited %v for a stream nobody needs", elapsed)
			}

			if mode == "failure" && err == nil {
				t.Fatal("failure answered")
			}

			if mode == "client left" && (err != nil || ip.String() != "93.184.216.34") {
				t.Fatalf("answer lost while waiting: %v %v", ip, err)
			}
		})
	}
}

// A dial that completes only once the query was cancelled leaves no stream behind.
func TestIsolatedResolverDialAfterCancel(t *testing.T) {
	cert, roots := testCertificate(t, dohName)
	via := &route{server: dohServer(t, cert, nil, false)}

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	dial := func(dialCtx context.Context, destination netip.AddrPort) (Stream, error) {
		<-dialCtx.Done()
		return via.dial(context.Background(), destination)
	}

	if _, err := newIsolatedResolver(dial, roots, nil)(ctx, "example.com"); err == nil {
		t.Fatal("cancelled query answered")
	}

	if len(via.dialed) != 1 || !via.allClosed() {
		t.Fatalf("stream left open: %v closed=%v", via.dialed, via.allClosed())
	}
}

// A resolver that never completes its TLS handshake gives up with its query, and its stream is closed.
func TestIsolatedResolverStalledHandshake(t *testing.T) {
	cert, roots := testCertificate(t, dohName)
	via := &route{server: dohServer(t, cert, nil, false)}

	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()

	start := time.Now()

	if _, err := newIsolatedResolver(via.dial, roots, nil)(ctx, "example.com"); err == nil {
		t.Fatal("stalled resolver answered")
	}

	if time.Since(start) > 5*time.Second || len(via.dialed) != 1 || !via.allClosed() {
		t.Fatalf("stalled query not ended with its stream: %v closed=%v", time.Since(start), via.allClosed())
	}
}

// The stream ends during the query, as a release ends it: the query fails, nothing falls back.
func TestIsolatedResolverStreamEndsDuringQuery(t *testing.T) {
	cert, roots := testCertificate(t, dohName)

	arrived := make(chan struct{})
	release := make(chan struct{})

	server := dohServer(t, cert, func(w http.ResponseWriter, _ *http.Request) {
		close(arrived)
		<-release
	}, true)
	defer close(release)

	via := &route{server: server}

	go func() {
		<-arrived

		via.mu.Lock()
		defer via.mu.Unlock()

		for _, s := range via.streams {
			_ = s.Close()
		}
	}()

	if _, err := newIsolatedResolver(via.dial, roots, nil)(context.Background(), "example.com"); err == nil {
		t.Fatal("query answered after its stream ended")
	}

	if len(via.dialed) != 1 {
		t.Fatalf("query retried or fell back: %v", via.dialed)
	}
}

// Two routes resolve at once, each through its own streams only, and get their own answers.
func TestIsolatedResolversKeepTheirRoutes(t *testing.T) {
	cert, roots := testCertificate(t, dohName)

	routes := map[string]*route{}
	for name, ip := range map[string]string{"A": "93.184.216.34", "B": "93.184.216.35"} {
		body := answer("example.com", record("example.com", 1, ip))
		routes[name] = &route{server: dohServer(t, cert, func(w http.ResponseWriter, _ *http.Request) {
			time.Sleep(50 * time.Millisecond)
			_, _ = w.Write([]byte(body))
		}, true)}
	}

	results := map[string]string{}

	var mu sync.Mutex
	var wg sync.WaitGroup

	for name, via := range routes {
		resolve := newIsolatedResolver(via.dial, roots, nil)

		for range 4 {
			wg.Add(1)

			go func() {
				defer wg.Done()

				ip, err := resolve(context.Background(), "example.com")

				mu.Lock()
				defer mu.Unlock()

				if err != nil {
					t.Errorf("route %s: %v", name, err)
					return
				}

				if previous, seen := results[name]; seen && previous != ip.String() {
					t.Errorf("route %s answered %s and %s", name, previous, ip)
				}

				results[name] = ip.String()
			}()
		}
	}

	wg.Wait()

	if results["A"] != "93.184.216.34" || results["B"] != "93.184.216.35" || len(routes["A"].dialed) != 4 ||
		len(routes["B"].dialed) != 4 {
		t.Fatalf("routes mixed: %v, %d and %d streams", results, len(routes["A"].dialed), len(routes["B"].dialed))
	}
}
