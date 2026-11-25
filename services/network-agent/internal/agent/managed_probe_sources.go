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
	sources := []managedProbeHTTPSource{
		{
			managedProbeSourceSpec: managedProbeSourceSpec{
				id:          managedCloudflareSourceID,
				operator:    "cloudflare",
				destination: netip.MustParseAddr("1.1.1.1"),
			},
			host: "1.1.1.1",
			path: "/cdn-cgi/trace",
		},
		{
			managedProbeSourceSpec: managedProbeSourceSpec{
				id:          managedIdentSourceID,
				operator:    "ident_me",
				destination: identPin,
			},
			host: "4.ident.me",
			path: "/",
		},
	}

	specs := make([]managedProbeSourceSpec, 0, len(sources))

	for _, source := range sources {
		if err := source.validate(); err != nil {
			return nil, err
		}

		specs = append(specs, source.managedProbeSourceSpec)
	}

	if err := validateManagedProbeSources(specs); err != nil {
		return nil, err
	}

	return sources, nil
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
		DialContext:            pinnedProbeHostDial(host, destination, dial),
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

// fetchManagedProbeBody makes one request to a validated source. Step 29C.3 runs it inside the
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
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, err
	}

	request.Header.Set("User-Agent", "egresslab-probe/1")
	request.Header.Set("Accept-Encoding", "identity")
	request.Header.Set("Cache-Control", "no-cache, no-store")

	response, err := client.Do(request)
	if err != nil {
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
