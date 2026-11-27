package agent

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/netip"
	"strings"
	"sync/atomic"
	"time"
)

const (
	managedCloudflareSourceID = "cloudflare_trace"
	managedIdentSourceID      = "ident_me"

	managedProbeMaxHeaderBytes = 16 * 1024

	// managedProbeConnectTimeout bounds the TCP connection to a source, which leaves more rechecks
	// within the monitor's health when a source does not answer: the failures seen so far all came
	// before TCP connected. TLS and the response keep egressProbeTimeout.
	managedProbeConnectTimeout = 4 * time.Second
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

func newManagedProbeDialer() *net.Dialer {
	return &net.Dialer{Timeout: managedProbeConnectTimeout}
}

// fetchManagedProbeBody makes one request to a validated source. The worker runs it inside the
// source's own firewall window.
func fetchManagedProbeBody(ctx context.Context, source managedProbeHTTPSource) ([]byte, error) {
	if err := source.validate(); err != nil {
		return nil, err
	}

	client := newManagedProbeHTTPClient(source.host, source.destination, newManagedProbeDialer().DialContext)
	defer client.CloseIdleConnections()

	return readManagedProbeHTTPS(ctx, client, source.url())
}

// managedProbeReason is how the worker reports one class of source failure: its fixed line, and
// whether the failure says nothing about the egress (it then renews nothing and faults nothing).
type managedProbeReason struct {
	line     string
	noAnswer bool
}

// managedProbeReasons are the worker's failure classes; the helper maps the lines back. Only a source
// that sent nothing, or the verified host answering a service error or cutting its reply short, has
// no answer; anything unverified or refused faults.
var managedProbeReasons = map[string]managedProbeReason{
	"HTTPS_NO_ANSWER":          {line: "HTTPS probe got no answer", noAnswer: true},
	"HTTPS_SOURCE_UNAVAILABLE": {line: "HTTPS probe source unavailable", noAnswer: true},
	"HTTPS_REPLY_INCOMPLETE":   {line: "HTTPS probe reply incomplete", noAnswer: true},
	"HTTPS_TLS_FAILED":         {line: "HTTPS probe TLS failed"},
	"HTTPS_UNEXPECTED_STATUS":  {line: "HTTPS probe unexpected status"},
	"HTTPS_INVALID_RESPONSE":   {line: "HTTPS probe invalid response"},
	"HTTPS_REQUEST_FAILED":     {line: "HTTPS probe failed"},
}

// managedProbeSourceFailure is one source failure with its reason.
type managedProbeSourceFailure struct {
	reason string
	err    error
}

func (f *managedProbeSourceFailure) Error() string { return f.err.Error() + ": " + f.reason }

func (f *managedProbeSourceFailure) Unwrap() []error {
	if managedProbeReasons[f.reason].noAnswer {
		return []error{ErrManagedProbeNoAnswer, f.err}
	}

	return []error{f.err}
}

func probeSourceFailure(reason string, err error) error {
	return &managedProbeSourceFailure{reason: reason, err: err}
}

// managedProbeReasonOf names a source failure's reason; an untyped one has no answer or failed.
func managedProbeReasonOf(err error) string {
	var failure *managedProbeSourceFailure
	if errors.As(err, &failure) {
		if _, ok := managedProbeReasons[failure.reason]; ok {
			return failure.reason
		}
	}

	if errors.Is(err, ErrManagedProbeNoAnswer) {
		return "HTTPS_NO_ANSWER"
	}

	return "HTTPS_REQUEST_FAILED"
}

// ManagedProbeFailureLine is the worker's fixed line for a source failure; no source text reaches it.
func ManagedProbeFailureLine(err error) string {
	return managedProbeReasons[managedProbeReasonOf(err)].line
}

// readManagedProbeHTTPS requires HTTP 200, no content encoding and a body of 1 to 4096 bytes.
func readManagedProbeHTTPS(ctx context.Context, client *http.Client, rawURL string) ([]byte, error) {
	// Once the source sent a byte, at any layer, its reply counts; only one from the verified host may
	// fail without saying anything about the egress.
	var trace probeConnTrace
	var verified atomic.Bool

	ctx = context.WithValue(ctx, probeReceivedKey{}, &trace)
	ctx = httptrace.WithClientTrace(ctx, &httptrace.ClientTrace{
		TLSHandshakeDone: func(_ tls.ConnectionState, err error) {
			if err == nil {
				verified.Store(true)
			}
		},
	})

	request, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, err
	}

	request.Header.Set("User-Agent", "egresslab-probe/1")
	request.Header.Set("Accept-Encoding", "identity")
	request.Header.Set("Cache-Control", "no-cache, no-store")

	// A verified reply is cut short when it ends in silence, a reset, or the source closing while more
	// was still due; a complete line that does not parse is no interruption.
	cut := func(err error) bool { return probeNoAnswer(err) || trace.closed.Load() }

	response, err := client.Do(request)
	if err != nil {
		switch {
		case !trace.received.Load() && probeNoAnswer(err):
			return nil, probeSourceFailure("HTTPS_NO_ANSWER", err)
		case tlsAlertReceived(err):
			return nil, probeSourceFailure("HTTPS_TLS_FAILED", err)
		case verified.Load() && cut(err):
			return nil, probeSourceFailure("HTTPS_REPLY_INCOMPLETE", err)
		case verified.Load():
			return nil, probeSourceFailure("HTTPS_INVALID_RESPONSE", err)
		case trace.received.Load():
			return nil, probeSourceFailure("HTTPS_TLS_FAILED", err)
		}

		return nil, probeSourceFailure("HTTPS_REQUEST_FAILED", err)
	}
	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		err := fmt.Errorf("probe returned HTTP %d", response.StatusCode)

		// A busy or failing service is no claim about the address.
		if verified.Load() && (response.StatusCode == http.StatusTooManyRequests ||
			response.StatusCode >= 500 && response.StatusCode <= 599) {
			return nil, probeSourceFailure("HTTPS_SOURCE_UNAVAILABLE", err)
		}

		return nil, probeSourceFailure("HTTPS_UNEXPECTED_STATUS", err)
	}

	if !identityEncodingOnly(response.Header.Values("Content-Encoding")) {
		return nil, probeSourceFailure("HTTPS_INVALID_RESPONSE", errors.New("unexpected probe response encoding"))
	}

	body, err := io.ReadAll(io.LimitReader(response.Body, maxEgressProbeBytes+1))
	if err != nil {
		switch {
		case tlsAlertReceived(err):
			return nil, probeSourceFailure("HTTPS_TLS_FAILED", err)
		case verified.Load() && cut(err):
			return nil, probeSourceFailure("HTTPS_REPLY_INCOMPLETE", err)
		}

		return nil, probeSourceFailure("HTTPS_INVALID_RESPONSE", err)
	}

	if len(body) == 0 || len(body) > maxEgressProbeBytes {
		return nil, probeSourceFailure("HTTPS_INVALID_RESPONSE", ErrInvalidObservation)
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

	return probeErrnoIn(err, probeLostErrnos) || errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF)
}

func probeErrnoIn(err error, errnos []error) bool {
	for _, errno := range errnos {
		if errors.Is(err, errno) {
			return true
		}
	}

	return false
}

// tlsAlertReceived reports an alert the source sent, which TLS 1.3 may deliver after the handshake.
func tlsAlertReceived(err error) bool {
	var opErr *net.OpError

	return errors.As(err, &opErr) && opErr.Op == "remote error"
}

type probeReceivedKey struct{}

// probeConnTrace records, below TLS, whether the source sent a byte and whether it closed or reset
// the connection.
type probeConnTrace struct {
	received atomic.Bool
	closed   atomic.Bool
}

// recordingProbeDial traces the connection in the request's context.
func recordingProbeDial(dial probeDialFunc) probeDialFunc {
	return func(ctx context.Context, network, address string) (net.Conn, error) {
		conn, err := dial(ctx, network, address)
		if err != nil {
			return nil, err
		}

		if trace, ok := ctx.Value(probeReceivedKey{}).(*probeConnTrace); ok {
			return receivingConn{Conn: conn, trace: trace}, nil
		}

		return conn, nil
	}
}

type receivingConn struct {
	net.Conn
	trace *probeConnTrace
}

func (c receivingConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if n > 0 {
		c.trace.received.Store(true)
	}

	if errors.Is(err, io.EOF) || probeErrnoIn(err, probeResetErrnos) {
		c.trace.closed.Store(true)
	}

	return n, err
}
