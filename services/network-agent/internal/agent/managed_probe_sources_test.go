package agent

import (
	"context"
	"crypto/x509"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
)

func testManagedHTTPSources(t *testing.T) []managedProbeHTTPSource {
	t.Helper()

	// A synthetic public pin: no request is ever made to it.
	sources, err := managedProbeHTTPSources(netip.MustParseAddr("9.9.9.9"))
	if err != nil {
		t.Fatal(err)
	}

	return sources
}

func TestManagedProbeHTTPSourcePolicy(t *testing.T) {
	sources := testManagedHTTPSources(t)

	if len(sources) != 2 || sources[0].url() != "https://1.1.1.1/cdn-cgi/trace" ||
		sources[1].url() != "https://4.ident.me/" {
		t.Fatalf("unexpected sources: %+v", sources)
	}

	for _, pin := range []netip.Addr{
		{},
		netip.MustParseAddr("1.1.1.1"),
		netip.MustParseAddr("10.0.0.1"),
		netip.MustParseAddr("127.0.0.1"),
		netip.MustParseAddr("100.64.0.1"),
		netip.MustParseAddr("192.0.2.1"),
		netip.MustParseAddr("::ffff:9.9.9.9"),
		netip.MustParseAddr("2001:db8::1"),
	} {
		if result, err := managedProbeHTTPSources(pin); !errors.Is(err, ErrManagedProbeSourcePolicy) || result != nil {
			t.Fatalf("invalid pin accepted: %v", pin)
		}
	}

	for name, mutate := range map[string]func(*managedProbeHTTPSource){
		"host":     func(s *managedProbeHTTPSource) { s.host = "example.com" },
		"path":     func(s *managedProbeHTTPSource) { s.path = "/other" },
		"id":       func(s *managedProbeHTTPSource) { s.id = "unknown" },
		"operator": func(s *managedProbeHTTPSource) { s.operator = "cloudflare" },
	} {
		bad := sources[1]
		mutate(&bad)

		if err := bad.validate(); !errors.Is(err, ErrManagedProbeSourcePolicy) {
			t.Fatalf("modified ident.me %s accepted", name)
		}
	}

	bad := sources[0]
	bad.destination = netip.MustParseAddr("8.8.8.8")

	if err := bad.validate(); !errors.Is(err, ErrManagedProbeSourcePolicy) {
		t.Fatal("modified Cloudflare destination accepted")
	}

	// Refused before any connection is attempted.
	body, err := fetchManagedProbeBody(context.Background(), bad)
	if !errors.Is(err, ErrManagedProbeSourcePolicy) || body != nil {
		t.Fatalf("invalid source fetched: %v", err)
	}
}

func TestManagedProbeBodyParsing(t *testing.T) {
	sources := testManagedHTTPSources(t)
	cloudflare, ident := sources[0], sources[1]
	expected := netip.MustParseAddr("8.8.4.4")

	tests := []struct {
		name   string
		source managedProbeHTTPSource
		body   string
		valid  bool
	}{
		{"valid trace", cloudflare, "fl=1\nip=8.8.4.4\nts=1\n", true},
		{"duplicate trace IP", cloudflare, "ip=8.8.4.4\nip=8.8.4.4\n", false},
		{"missing trace IP", cloudflare, "fl=1\nts=1\n", false},
		{"private trace IP", cloudflare, "ip=10.0.0.1\n", false},
		{"plain text", ident, "8.8.4.4", true},
		{"LF", ident, "8.8.4.4\n", true},
		{"CRLF", ident, "8.8.4.4\r\n", true},
		{"multiple lines", ident, "8.8.4.4\n8.8.4.4", false},
		{"extra line ending", ident, "8.8.4.4\n\n", false},
		{"bare CR", ident, "8.8.4.4\r", false},
		{"leading whitespace", ident, " 8.8.4.4", false},
		{"trailing whitespace", ident, "8.8.4.4 ", false},
		{"HTML", ident, "<html>8.8.4.4</html>", false},
		{"JSON", ident, `{"ip":"8.8.4.4"}`, false},
		{"IPv6", ident, "2001:4860::1", false},
		{"IPv4-mapped IPv6", ident, "::ffff:8.8.4.4", false},
		{"CGNAT", ident, "100.64.0.1", false},
		{"empty body", ident, "", false},
		{"oversized body", ident, strings.Repeat("x", maxEgressProbeBytes+1), false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ip, err := parseManagedProbeBody(tt.source, []byte(tt.body))

			if tt.valid {
				if err != nil || ip != expected {
					t.Fatalf("valid IP rejected: %v %v", ip, err)
				}

				return
			}

			if err == nil || ip.IsValid() {
				t.Fatalf("invalid body accepted: %v", ip)
			}
		})
	}
}

// A local TLS server stands in for the source: nothing reaches Cloudflare, ident.me or 9.9.9.9.
func TestManagedProbePinnedHTTPS(t *testing.T) {
	ctx := context.Background()

	var requests atomic.Int32

	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)

		if r.Host != "example.com" || r.TLS == nil || r.TLS.ServerName != "example.com" {
			t.Error("HTTPS identity was changed")
		}

		switch r.URL.Path {
		case "/ok":
			_, _ = w.Write([]byte("8.8.4.4\n"))
		case "/redirect":
			// Same host: a client that followed it would land on /ok and succeed.
			http.Redirect(w, r, "https://example.com/ok", http.StatusFound)
		case "/oversized":
			_, _ = w.Write([]byte(strings.Repeat("x", maxEgressProbeBytes+1)))
		case "/encoded":
			w.Header().Set("Content-Encoding", "gzip")
			_, _ = w.Write([]byte("not permitted"))
		case "/encoded-second-field":
			// Only the second field declares an encoding; the body itself would parse.
			w.Header()["Content-Encoding"] = []string{"identity", "gzip"}
			_, _ = w.Write([]byte("8.8.4.4\n"))
		case "/encoded-list":
			w.Header().Set("Content-Encoding", "identity, gzip")
			_, _ = w.Write([]byte("8.8.4.4\n"))
		case "/identity":
			w.Header().Set("Content-Encoding", "identity")
			_, _ = w.Write([]byte("8.8.4.4\n"))
		case "/empty":
			w.WriteHeader(http.StatusOK)
		default:
			w.WriteHeader(http.StatusServiceUnavailable)
		}
	}))
	defer server.Close()

	target := netip.MustParseAddr("9.9.9.9")

	// The fake dialer checks the pin, then connects to the local test server only.
	fakeDial := func(ctx context.Context, network, address string) (net.Conn, error) {
		if network != "tcp4" || address != "9.9.9.9:443" {
			t.Error("unexpected dial destination")
			return nil, ErrProbeDestination
		}

		return (&net.Dialer{}).DialContext(ctx, "tcp4", server.Listener.Addr().String())
	}

	roots := x509.NewCertPool()
	roots.AddCert(server.Certificate())

	client := newManagedProbeHTTPClient("example.com", target, fakeDial)
	defer client.CloseIdleConnections()

	transport := client.Transport.(*http.Transport)
	if transport.Proxy != nil || transport.TLSClientConfig.InsecureSkipVerify || !transport.DisableKeepAlives {
		t.Fatal("insecure HTTPS transport")
	}

	// Test-only trust of the httptest certificate; production uses the system trust store.
	transport.TLSClientConfig.RootCAs = roots

	body, err := readManagedProbeHTTPS(ctx, client, "https://example.com/ok")
	if err != nil || string(body) != "8.8.4.4\n" {
		t.Fatalf("valid HTTPS request failed: %q %v", body, err)
	}

	before := requests.Load()

	if _, err := readManagedProbeHTTPS(ctx, client, "https://example.com/redirect"); err == nil {
		t.Fatal("redirect accepted")
	}

	if requests.Load() != before+1 {
		t.Fatal("redirect was followed")
	}

	if body, err := readManagedProbeHTTPS(ctx, client, "https://example.com/identity"); err != nil || len(body) == 0 {
		t.Fatalf("explicit identity encoding refused: %v", err)
	}

	for _, path := range []string{
		"/oversized", "/encoded", "/encoded-second-field", "/encoded-list", "/empty", "/unavailable",
	} {
		if body, err := readManagedProbeHTTPS(ctx, client, "https://example.com"+path); err == nil || body != nil {
			t.Fatalf("invalid response accepted: %s", path)
		}
	}

	// A URL whose authority differs from the pinned host is refused by the dialer.
	if _, err := readManagedProbeHTTPS(ctx, client, "https://other.example/ok"); !errors.Is(err, ErrProbeDestination) {
		t.Fatalf("foreign authority dialed: %v", err)
	}

	before = requests.Load()

	wrongHost := newManagedProbeHTTPClient("wrong.example", target, fakeDial)
	defer wrongHost.CloseIdleConnections()
	wrongHost.Transport.(*http.Transport).TLSClientConfig.RootCAs = roots

	if _, err := readManagedProbeHTTPS(ctx, wrongHost, "https://wrong.example/ok"); err == nil {
		t.Fatal("TLS hostname mismatch accepted")
	}

	untrusted := newManagedProbeHTTPClient("example.com", target, fakeDial)
	defer untrusted.CloseIdleConnections()
	untrusted.Transport.(*http.Transport).TLSClientConfig.RootCAs = x509.NewCertPool()

	if _, err := readManagedProbeHTTPS(ctx, untrusted, "https://example.com/ok"); err == nil {
		t.Fatal("untrusted certificate accepted")
	}

	if requests.Load() != before {
		t.Fatal("an invalid TLS connection reached the HTTP handler")
	}
}

func TestIdentityEncodingOnly(t *testing.T) {
	for _, tt := range []struct {
		values []string
		ok     bool
	}{
		{nil, true},
		{[]string{"identity"}, true},
		{[]string{"Identity", " identity "}, true},
		{[]string{"gzip"}, false},
		{[]string{"identity", "gzip"}, false},
		{[]string{"identity, br"}, false},
		{[]string{""}, false},
		{[]string{"identity,"}, false},
	} {
		if identityEncodingOnly(tt.values) != tt.ok {
			t.Errorf("%q: want %t", tt.values, tt.ok)
		}
	}
}
