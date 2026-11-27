package agent

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"syscall"
	"testing"
	"time"
)

// Only a source from which nothing came back counts as giving no answer; any reply that arrived and
// was refused does not.
func TestManagedProbeNoAnswer(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/ok":
			_, _ = w.Write([]byte("8.8.4.4\n"))
			return
		case "/silent-after-tls":
			time.Sleep(time.Second)
			return
		case "/interrupted":
			// A status line, then the connection ends before the headers do.
			conn, buf, err := w.(http.Hijacker).Hijack()
			if err == nil {
				_, _ = buf.WriteString("HTTP/1.1 503 Service Unavailable\r\n")
				_ = buf.Flush()
				_ = conn.Close()
			}

			return
		}

		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer server.Close()

	roots := x509.NewCertPool()
	roots.AddCert(server.Certificate())

	silent, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer silent.Close()

	go func() {
		for {
			c, err := silent.Accept()
			if err != nil {
				return
			}
			defer c.Close()
		}
	}()

	closing, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer closing.Close()

	go func() {
		for {
			c, err := closing.Accept()
			if err != nil {
				return
			}
			_ = c.Close()
		}
	}()

	plain := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer plain.Close()

	// A short reply that is not TLS, then the connection ends.
	short, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer short.Close()

	go func() {
		for {
			c, err := short.Accept()
			if err != nil {
				return
			}
			_, _ = c.Write([]byte("HT"))
			_ = c.Close()
		}
	}()

	refused, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	refusedAddr := refused.Addr().String()
	_ = refused.Close()

	fetch := func(addr, host, path string, trusted bool) error {
		dial := func(ctx context.Context, network, address string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "tcp4", addr)
		}

		client := newManagedProbeHTTPClient(host, netip.MustParseAddr("9.9.9.9"), dial)
		defer client.CloseIdleConnections()

		if trusted {
			client.Transport.(*http.Transport).TLSClientConfig.RootCAs = roots
		} else {
			client.Transport.(*http.Transport).TLSClientConfig.RootCAs = x509.NewCertPool()
		}

		ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
		defer cancel()

		_, err := readManagedProbeHTTPS(ctx, client, "https://"+host+path)

		return err
	}

	tlsAddr := server.Listener.Addr().String()

	if err := fetch(tlsAddr, "example.com", "/ok", true); err != nil {
		t.Fatalf("valid request: %v", err)
	}

	for name, err := range map[string]error{
		"no response in time": fetch(silent.Addr().String(), "example.com", "/ok", true),
		"connection refused":  fetch(refusedAddr, "example.com", "/ok", true),
		"closed before TLS":   fetch(closing.Addr().String(), "example.com", "/ok", true),
	} {
		if !errors.Is(err, ErrManagedProbeNoAnswer) {
			t.Errorf("%s: %v", name, err)
		}
	}

	for name, err := range map[string]error{
		"untrusted certificate": fetch(tlsAddr, "example.com", "/ok", false),
		"other host name":       fetch(tlsAddr, "wrong.example", "/ok", true),
		"not TLS":               fetch(plain.Listener.Addr().String(), "example.com", "/ok", true),
		"HTTP status":           fetch(tlsAddr, "example.com", "/unavailable", true),
		"interrupted reply":     fetch(tlsAddr, "example.com", "/interrupted", true),
		"short reply, not TLS":  fetch(short.Addr().String(), "example.com", "/ok", true),
		"silent after TLS":      fetch(tlsAddr, "example.com", "/silent-after-tls", true),
	} {
		if err == nil || errors.Is(err, ErrManagedProbeNoAnswer) {
			t.Errorf("%s counted as no answer: %v", name, err)
		}
	}

	for _, err := range []error{
		tls.AlertError(40),
		x509.UnknownAuthorityError{},
		fmt.Errorf("dial: %w", syscall.EACCES),
		errors.New("probe returned HTTP 503"),
	} {
		if probeNoAnswer(err) {
			t.Errorf("%v counted as no answer", err)
		}
	}

	if !probeNoAnswer(fmt.Errorf("read: %w", syscall.ECONNRESET)) {
		t.Error("a reset is no answer")
	}
}

// A source without an answer, whose window closed as opened, leaves the tunnel as it was; anything
// more on top of it removes the tunnel as before.
func TestManagedMultiProbeNoAnswer(t *testing.T) {
	noAnswer := fmt.Errorf("%w: %s: %w", ErrManagedProbeFailed, "HTTPS_NO_ANSWER", ErrManagedProbeNoAnswer)

	tests := []struct {
		mode   string
		source int // the source without an answer
		soft   bool
		want   error
		text   string
	}{
		{mode: "first source", source: 0, soft: true},
		{mode: "second source", source: 1, soft: true},
		{mode: "cleanup failure", source: 1, want: ErrProbeCleanup},
		{mode: "drift", source: 0, text: "fwmark"},
		{mode: "worker left running", source: 0, want: ErrNetNSBusy},
		{mode: "cancelled", source: 0, want: context.Canceled},
		{mode: "expired window", source: 1, want: ErrProbePolicyDrift},
		{mode: "clock stepped", source: 0, want: ErrInvalidObservation, text: "clock"},
		{mode: "cancelled at the clock check", source: 0, want: context.Canceled},
	}

	for _, tt := range tests {
		t.Run(tt.mode, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			b, kernel, window, pids := multiProbeFixture(t)
			sources := testManagedHTTPSources(t)
			tracked := b.active

			if tt.mode == "worker left running" {
				*pids = []string{"", "4242\n"}
			}

			var clock managedProbeClock

			switch tt.mode {
			case "clock stepped":
				// The wall clock steps back 1.5 s between the start and the source without an answer.
				clock = offsetClock(time.Now().UTC(), time.Second, 0, -1500*time.Millisecond)
			case "cancelled at the clock check":
				// The attempt is cancelled at its second reading, after the source's window closed.
				steady := offsetClock(time.Now().UTC(), time.Second)
				readings := 0
				clock = func() (time.Time, time.Duration) {
					readings++
					if readings == 2 {
						cancel()
					}

					return steady()
				}
			}

			calls := 0

			b.multiProbe = &managedMultiProbeConfig{
				identPin: sources[1].destination,
				clock:    clock,
				run: func(_ context.Context, _ string, source managedProbeHTTPSource) ([]byte, error) {
					index := calls
					calls++

					if index != tt.source {
						return syntheticSourceBody(source, "8.8.4.4"), nil
					}

					switch tt.mode {
					case "cleanup failure":
						window.failDel = true
					case "drift":
						kernel.wrongMark = true
					case "cancelled":
						cancel()
					case "expired window":
						window.window = probeCapture(t, "nft-lab-probe-expired.json")
					}

					return nil, noAnswer
				},
			}

			result, err := b.ProbeConfiguredMultiForGeneration(ctx, vpnTestNS, tracked.generation)

			if result.IPv4.IsValid() || result.Sources != nil || calls != tt.source+1 || tracked.expectedIPv4.IsValid() {
				t.Fatalf("an attempt without an answer returned evidence or went on: %+v", result)
			}

			if tt.soft {
				if !errors.Is(err, ErrManagedProbeSourceUnavailable) || errors.Is(err, ErrManagedProbeFailed) {
					t.Fatalf("expected a source without an answer, got %v", err)
				}

				if b.active != tracked || tracked.faulted || kernel.tableRemovals != 0 || window.open ||
					len(window.closed) != window.opened || b.sealed.firewall.drifted[vpnTestNS] {
					t.Fatal("a source without an answer changed the tunnel or its firewall")
				}

				if err := b.VerifyConfigured(ctx, vpnTestNS); err != nil {
					t.Fatal(err)
				}

				// The next attempt runs as usual.
				b.multiProbe.run = func(_ context.Context, _ string, source managedProbeHTTPSource) ([]byte, error) {
					return syntheticSourceBody(source, "8.8.4.4"), nil
				}

				if result, err := b.ProbeConfiguredMultiForGeneration(ctx, vpnTestNS, tracked.generation); err != nil ||
					result.IPv4.String() != "8.8.4.4" {
					t.Fatalf("the probe after a source without an answer: %v", err)
				}

				return
			}

			if errors.Is(err, ErrManagedProbeSourceUnavailable) || !errors.Is(err, ErrManagedProbeFailed) ||
				(tt.want != nil && !errors.Is(err, tt.want)) || (tt.text != "" && !strings.Contains(err.Error(), tt.text)) {
				t.Fatalf("expected a failure %v %q, got %v", tt.want, tt.text, err)
			}

			if b.active != nil || kernel.tableRemovals != 1 {
				t.Fatal("a failure on top of no answer kept the tunnel")
			}
		})
	}
}

// A source that does not accept a connection gives no answer within the connect timeout, well
// inside the attempt's own limit, so that more rechecks fit into the monitor's health.
func TestManagedProbeConnectTimeout(t *testing.T) {
	if d := newManagedProbeDialer(); d.Timeout != managedProbeConnectTimeout ||
		managedProbeConnectTimeout > egressProbeTimeout/2 {
		t.Fatalf("connect timeout %v", d.Timeout)
	}
}
