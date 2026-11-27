package agent

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync/atomic"
	"syscall"
)

const (
	managedCloudflareSourceID = "cloudflare_trace"
	managedIdentSourceID      = "ident_me"

	managedProbeMaxHeaderBytes = 16 * 1024
)

// managedProbeHTTPSource is one mandatory HTTPS source: its HTTPS identity (host and path) and the
// numeric IPv4 destination that TCP is pinned to.
type managedProbeHTTPSource struct {
	managedProbeSourceSpec

	host string
	path string
}

// managedProbeHTTPSources builds the mandatory source policy. identPin comes from trusted
// provisioning only: never from an IPC request, an environment variable or an automatic DNS lookup.
// Cloudflare's destination is its literal address.
func managedProbeHTTPSources(identPin netip.Addr) ([]managedProbeHTTPSource, error) {
	cloudflare, err := managedProbeHTTPSourceFor(managedCloudflareSourceID, netip.MustParseAddr("1.1.1.1"))
	if err != nil {
		return nil, err
	}

	ident, err := managedProbeHTTPSourceFor(managedIdentSourceID, identPin)
	if err != nil {
		return nil, err
	}

	specs := []managedProbeSourceSpec{cloudflare.managedProbeSourceSpec, ident.managedProbeSourceSpec}
	if err := validateManagedProbeSources(specs); err != nil {
		return nil, err
	}

	return []managedProbeHTTPSource{cloudflare, ident}, nil
}

// managedProbeHTTPSourceFor rebuilds a known source from its ID and numeric destination. The
// caller stays responsible for where that destination came from and for authorizing it.
func managedProbeHTTPSourceFor(id string, destination netip.Addr) (managedProbeHTTPSource, error) {
	var source managedProbeHTTPSource

	switch id {
	case managedCloudflareSourceID:
		source = managedProbeHTTPSource{
			managedProbeSourceSpec: managedProbeSourceSpec{
				id:          managedCloudflareSourceID,
				operator:    "cloudflare",
				destination: destination,
			},
			host: "1.1.1.1",
			path: "/cdn-cgi/trace",
		}

	case managedIdentSourceID:
		source = managedProbeHTTPSource{
			managedProbeSourceSpec: managedProbeSourceSpec{
				id:          managedIdentSourceID,
				operator:    "ident_me",
				destination: destination,
			},
			host: "4.ident.me",
			path: "/",
		}

	default:
		return managedProbeHTTPSource{}, ErrManagedProbeSourcePolicy
	}

	if err := source.validate(); err != nil {
		return managedProbeHTTPSource{}, err
	}

	return source, nil
}

// FetchManagedProbeSource makes one HTTPS request to a built-in source; it is the worker's entry
// point. It opens no firewall window and its result is not managed tunnel evidence: the privileged
// parent chooses the destination from trusted policy and parses the body itself.
func FetchManagedProbeSource(ctx context.Context, sourceID string, destination netip.Addr) ([]byte, error) {
	source, err := managedProbeHTTPSourceFor(sourceID, destination)
	if err != nil {
		return nil, err
	}

	return fetchManagedProbeBody(ctx, source)
}

// validate accepts only the two known sources, exactly as built in.
func (s managedProbeHTTPSource) validate() error {
	if _, err := parseCandidateIPv4(s.destination.String()); err != nil {
		return ErrManagedProbeSourcePolicy
	}

	switch s.id {
	case managedCloudflareSourceID:
		if s.operator != "cloudflare" || s.host != "1.1.1.1" || s.path != "/cdn-cgi/trace" ||
			s.destination.String() != "1.1.1.1" {
			return ErrManagedProbeSourcePolicy
		}

	case managedIdentSourceID:
		if s.operator != "ident_me" || s.host != "4.ident.me" || s.path != "/" || s.destination.String() == "1.1.1.1" {
			return ErrManagedProbeSourcePolicy
		}

	default:
		return ErrManagedProbeSourcePolicy
	}

	return nil
}

func (s managedProbeHTTPSource) url() string {
	return "https://" + s.host + s.path
}

// newManagedProbeHTTPClient keeps the HTTPS identity (SNI, certificate name, Host header) while TCP
// goes to the pinned IPv4 address. It uses the system trust store, takes no proxy, follows no
// redirect and reuses no connection.
func newManagedProbeHTTPClient(host string, destination netip.Addr, dial probeDialFunc) *http.Client {
	transport := &http.Transport{
		Proxy:                  nil,
		DialContext:            recordingProbeDial(pinnedProbeHostDial(host, destination, dial)),
		TLSClientConfig:        &tls.Config{MinVersion: tls.VersionTLS12, ServerName: host},
		DisableKeepAlives:      true,
		DisableCompression:     true,
		MaxResponseHeaderBytes: managedProbeMaxHeaderBytes,
		TLSHandshakeTimeout:    egressProbeTimeout,
		ResponseHeaderTimeout:  egressProbeTimeout,
	}

	return &http.Client{
		Transport: transport,
		Timeout:   egressProbeTimeout,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

// fetchManagedProbeBody makes one request to a validated source. The worker runs it inside the
// source's own firewall window.
func fetchManagedProbeBody(ctx context.Context, source managedProbeHTTPSource) ([]byte, error) {
	if err := source.validate(); err != nil {
		return nil, err
	}

	dialer := &net.Dialer{Timeout: egressProbeTimeout}

	client := newManagedProbeHTTPClient(source.host, source.destination, dialer.DialContext)
	defer client.CloseIdleConnections()

	return readManagedProbeHTTPS(ctx, client, source.url())
}

// readManagedProbeHTTPS requires HTTP 200, no content encoding and a body of 1 to 4096 bytes.
func readManagedProbeHTTPS(ctx context.Context, client *http.Client, rawURL string) ([]byte, error) {
	// Once the source sent a byte, at any layer, an interrupted reply is an answer, not silence.
	var received atomic.Bool

	ctx = context.WithValue(ctx, probeReceivedKey{}, &received)

	request, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, err
	}

	request.Header.Set("User-Agent", "egresslab-probe/1")
	request.Header.Set("Accept-Encoding", "identity")
	request.Header.Set("Cache-Control", "no-cache, no-store")

	response, err := client.Do(request)
	if err != nil {
		if !received.Load() && probeNoAnswer(err) {
			return nil, fmt.Errorf("%w: %w", ErrManagedProbeNoAnswer, err)
		}

		return nil, err
	}
	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("probe returned HTTP %d", response.StatusCode)
	}

	if !identityEncodingOnly(response.Header.Values("Content-Encoding")) {
		return nil, errors.New("unexpected probe response encoding")
	}

	body, err := io.ReadAll(io.LimitReader(response.Body, maxEgressProbeBytes+1))
	if err != nil {
		return nil, err
	}

	if len(body) == 0 || len(body) > maxEgressProbeBytes {
		return nil, ErrInvalidObservation
	}

	return body, nil
}

// identityEncodingOnly checks every Content-Encoding field and every comma-separated coding in it,
// not only the first: each must be "identity". No field at all is identity too.
func identityEncodingOnly(values []string) bool {
	for _, value := range values {
		for _, coding := range strings.Split(value, ",") {
			if !strings.EqualFold(strings.TrimSpace(coding), "identity") {
				return false
			}
		}
	}

	return true
}

// parseManagedProbeBody reads the address in the source's own response format and applies the
// public IPv4 policy.
func parseManagedProbeBody(source managedProbeHTTPSource, body []byte) (netip.Addr, error) {
	if err := source.validate(); err != nil {
		return netip.Addr{}, err
	}

	if len(body) == 0 || len(body) > maxEgressProbeBytes {
		return netip.Addr{}, ErrInvalidObservation
	}

	switch source.id {
	case managedCloudflareSourceID:
		ip, err := parseTraceIP(body)
		if err != nil {
			return netip.Addr{}, fmt.Errorf("%w: invalid trace response", ErrInvalidObservation)
		}

		return parseCandidateIPv4(ip.String())

	case managedIdentSourceID:
		// One conventional line ending at most; any other whitespace or line is invalid.
		value := string(body)
		if trimmed, ok := strings.CutSuffix(value, "\r\n"); ok {
			value = trimmed
		} else {
			value = strings.TrimSuffix(value, "\n")
		}

		return parseCandidateIPv4(value)

	default:
		return netip.Addr{}, ErrManagedProbeSourcePolicy
	}
}

// probeNoAnswer: nothing came back in time, or the connection was refused, reset or closed. The
// caller asks only when the source sent no byte at all.
func probeNoAnswer(err error) bool {
	var timeout interface{ Timeout() bool }
	if errors.As(err, &timeout) && timeout.Timeout() {
		return true
	}

	return errors.Is(err, syscall.ECONNREFUSED) || errors.Is(err, syscall.ECONNRESET) ||
		errors.Is(err, syscall.EHOSTUNREACH) || errors.Is(err, syscall.ENETUNREACH) ||
		errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF)
}

type probeReceivedKey struct{}

// recordingProbeDial marks, in the request's context, that the source sent at least one byte.
func recordingProbeDial(dial probeDialFunc) probeDialFunc {
	return func(ctx context.Context, network, address string) (net.Conn, error) {
		conn, err := dial(ctx, network, address)
		if err != nil {
			return nil, err
		}

		if received, ok := ctx.Value(probeReceivedKey{}).(*atomic.Bool); ok {
			return receivingConn{Conn: conn, received: received}, nil
		}

		return conn, nil
	}
}

type receivingConn struct {
	net.Conn
	received *atomic.Bool
}

func (c receivingConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if n > 0 {
		c.received.Store(true)
	}

	return n, err
}
