package socks5

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"embed"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// ResolveFunc resolves a host name to one IPv4 address for a CONNECT. The address authorizes
// nothing: the dial that follows checks it like any other destination.
type ResolveFunc func(context.Context, string) (netip.Addr, error)

const (
	maxDNSResponse = 64 * 1024
	maxDNSAliases  = 8
	dnsTimeout     = 40 * time.Second

	// dnsStreamRelease bounds the wait for the runtime to end a query's stream, so that its slot is
	// free again, as far as the controller can tell, for the CONNECT that follows.
	dnsStreamRelease = 3 * time.Second

	// Google Public DNS's JSON API, reached at a fixed address, so that nothing resolves dns.google
	// itself.
	dohName  = "dns.google"
	dohDial  = "dns.google:443"
	dohQuery = "https://dns.google/resolve?"
)

var dohAddress = netip.MustParseAddrPort("8.8.8.8:443")

var (
	errDNSResponse = errors.New("invalid DNS response")
	errDNSNoAnswer = errors.New("no acceptable IPv4 answer")
	errDNSRedirect = errors.New("DNS resolver redirected the query")
)

// Google Trust Services' roots R1, R3 and R4, from Ubuntu's ca-certificates 20260816 (SHA-256
// fingerprints D947432A…, 34D8A73E…, 349DFA40…; dns.google chains to R4 through WE2). The platform
// verifier is not used: on Windows and macOS it may fetch missing certificates over the host's own
// network, resolving their names outside the tunnel.
//
//go:embed dohroots/*.pem
var dohRootFiles embed.FS

func dohRoots() (*x509.CertPool, error) {
	files, err := dohRootFiles.ReadDir("dohroots")
	if err != nil {
		return nil, err
	}

	pool := x509.NewCertPool()

	for _, file := range files {
		data, err := dohRootFiles.ReadFile("dohroots/" + file.Name())
		if err != nil || !pool.AppendCertsFromPEM(data) {
			return nil, errors.New("invalid built-in DNS resolver root")
		}
	}

	if len(files) == 0 {
		return nil, errors.New("no built-in DNS resolver root")
	}

	return pool, nil
}

// reservedIPv4 mirrors the controller's destination policy (control.validLabPublicIPv4), so that
// an answer it would refuse is skipped for a later one.
var reservedIPv4 = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("192.0.0.0/24"),
	netip.MustParsePrefix("192.0.2.0/24"),
	netip.MustParsePrefix("192.88.99.0/24"),
	netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("198.51.100.0/24"),
	netip.MustParsePrefix("203.0.113.0/24"),
	netip.MustParsePrefix("240.0.0.0/4"),
}

func publicIPv4(ip netip.Addr) bool {
	if !ip.Is4() || !ip.IsGlobalUnicast() || ip.IsPrivate() {
		return false
	}

	for _, prefix := range reservedIPv4 {
		if prefix.Contains(ip) {
			return false
		}
	}

	return true
}

func validHostname(name string) bool {
	if len(name) == 0 || len(name) > 253 || !strings.Contains(name, ".") {
		return false
	}

	for _, suffix := range []string{".local", ".localhost", ".internal", ".home.arpa", ".onion", ".invalid", ".test"} {
		if strings.HasSuffix(name, suffix) {
			return false
		}
	}

	for _, label := range strings.Split(name, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}

		for _, c := range label {
			if !(c >= 'a' && c <= 'z') && !(c >= '0' && c <= '9') && c != '-' {
				return false
			}
		}
	}

	return true
}

// NewIsolatedResolver resolves names with DNS over HTTPS through dial, the same signed stream
// transport as the CONNECTs, so a query leaves through the reservation's own tunnel and nothing
// asks the host's resolver. Each query opens one stream, to 8.8.8.8:443, and verifies dns.google's
// certificate against the built-in roots. There is no cache and no fallback. accept, when set,
// skips answers the dial's destination policy would refuse, so that a later allowed one is taken.
func NewIsolatedResolver(dial DialFunc, accept func(netip.Addr) bool) ResolveFunc {
	roots, err := dohRoots()
	if err != nil {
		return func(context.Context, string) (netip.Addr, error) { return netip.Addr{}, err }
	}

	return newIsolatedResolver(dial, roots, accept)
}

func newIsolatedResolver(dial DialFunc, roots *x509.CertPool, accept func(netip.Addr) bool) ResolveFunc {
	return func(parent context.Context, name string) (resolved netip.Addr, resultErr error) {
		name = canonicalDNSName(name)

		if dial == nil || roots == nil || !validHostname(name) {
			return netip.Addr{}, ErrNotAllowed
		}

		ctx, cancel := context.WithTimeout(parent, dnsTimeout)
		defer cancel()

		// Opened before the HTTP client starts, so it is never left to a dial still in progress.
		stream, err := dial(ctx, dohAddress)
		if err != nil {
			return netip.Addr{}, err
		}

		conn, closeStream := bridgeDNSStream(ctx, stream)

		// Only an answer is followed by a CONNECT that needs the stream's slot.
		defer func() { releaseDNSStream(parent, stream, closeStream, resultErr == nil) }()

		var handed atomic.Bool

		transport := &http.Transport{
			Proxy:               nil,
			DisableKeepAlives:   true,
			TLSHandshakeTimeout: 15 * time.Second,
			TLSClientConfig:     &tls.Config{ServerName: dohName, MinVersion: tls.VersionTLS12, RootCAs: roots},
			DialContext: func(_ context.Context, _, address string) (net.Conn, error) {
				if address != dohDial || !handed.CompareAndSwap(false, true) {
					return nil, ErrNotAllowed
				}

				return conn, nil
			},
		}
		defer transport.CloseIdleConnections()

		client := &http.Client{
			Transport:     transport,
			Timeout:       dnsTimeout,
			CheckRedirect: func(*http.Request, []*http.Request) error { return errDNSRedirect },
		}

		query := url.Values{
			"name":               {name},
			"type":               {"A"},
			"cd":                 {"0"},
			"edns_client_subnet": {"0.0.0.0/0"},
		}

		req, err := http.NewRequestWithContext(ctx, http.MethodGet, dohQuery+query.Encode(), nil)
		if err != nil {
			return netip.Addr{}, err
		}

		req.Header.Set("Accept", "application/dns-json")

		resp, err := client.Do(req)
		if err != nil {
			// Without the URL, which names the host.
			var urlErr *url.Error
			if errors.As(err, &urlErr) {
				err = urlErr.Err
			}

			return netip.Addr{}, err
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			return netip.Addr{}, errors.New("DNS resolver refused the request")
		}

		raw, err := io.ReadAll(io.LimitReader(resp.Body, maxDNSResponse+1))
		if err != nil || len(raw) > maxDNSResponse {
			return netip.Addr{}, errors.New("invalid DNS response size")
		}

		return parseDNSAnswer(raw, name, accept)
	}
}

// releaseDNSStream closes the stream and, when wait is set, waits briefly until the runtime has
// ended it, or until ctx ends.
func releaseDNSStream(ctx context.Context, stream Stream, closeStream func(), wait bool) {
	closeStream()

	exiter, ok := stream.(interface{ Exited() <-chan struct{} })
	if !wait || !ok {
		return
	}

	timer := time.NewTimer(dnsStreamRelease)
	defer timer.Stop()

	select {
	case <-exiter.Exited():
	case <-timer.C:
	case <-ctx.Done():
	}
}

// bridgeDNSStream gives the HTTP client a net.Conn over stream: an in-memory pipe, no connection of
// its own. Everything closes together, through the returned function or at the latest when ctx
// ends.
func bridgeDNSStream(ctx context.Context, stream Stream) (net.Conn, func()) {
	client, relay := net.Pipe()

	var once sync.Once

	closeAll := func() {
		once.Do(func() {
			_ = client.Close()
			_ = relay.Close()
			_ = stream.Close()
		})
	}

	context.AfterFunc(ctx, closeAll)

	go func() {
		defer closeAll()
		_, _ = io.Copy(stream, relay)
	}()

	go func() {
		defer closeAll()
		_, _ = io.Copy(relay, stream)
	}()

	return client, closeAll
}

type dnsRecord struct {
	Name string `json:"name"`
	Type int    `json:"type"`
	Data string `json:"data"`
}

type dnsResponse struct {
	Status   *int        `json:"Status"`
	TC       bool        `json:"TC"`
	Question []dnsRecord `json:"Question"`
	Answer   []dnsRecord `json:"Answer"`
}

func canonicalDNSName(name string) string {
	return strings.ToLower(strings.TrimSuffix(name, "."))
}

// parseDNSAnswer takes the first public IPv4 address that accept allows (any, when nil) the answer
// gives for name, directly or through at most maxDNSAliases CNAMEs. Every record of each name on the
// way is checked first: a name with an alias has exactly one CNAME and no address record of either
// family, well formed or not.
func parseDNSAnswer(data []byte, name string, accept func(netip.Addr) bool) (netip.Addr, error) {
	var response dnsResponse

	if err := json.Unmarshal(data, &response); err != nil {
		return netip.Addr{}, errDNSResponse
	}

	if response.Status == nil || *response.Status != 0 || response.TC || len(response.Question) != 1 ||
		response.Question[0].Type != 1 || canonicalDNSName(response.Question[0].Name) != name ||
		len(response.Answer) > 128 {
		return netip.Addr{}, errDNSResponse
	}

	current := name
	seen := map[string]bool{}

	for aliases := 0; ; aliases++ {
		if seen[current] {
			return netip.Addr{}, errors.New("DNS alias loop")
		}

		seen[current] = true
		alias := ""
		addressRecords := 0
		var addresses []netip.Addr

		for _, record := range response.Answer {
			if canonicalDNSName(record.Name) != current {
				continue
			}

			switch record.Type {
			case 1: // A
				addressRecords++

				if ip, err := netip.ParseAddr(record.Data); err == nil {
					addresses = append(addresses, ip)
				}

			case 28: // AAAA
				addressRecords++

			case 5: // CNAME
				next := canonicalDNSName(record.Data)
				if alias != "" || !validHostname(next) {
					return netip.Addr{}, errors.New("invalid DNS alias")
				}

				alias = next
			}
		}

		if alias == "" {
			for _, ip := range addresses {
				if publicIPv4(ip) && (accept == nil || accept(ip)) {
					return ip, nil
				}
			}

			return netip.Addr{}, errDNSNoAnswer
		}

		if addressRecords != 0 || aliases == maxDNSAliases {
			return netip.Addr{}, errors.New("invalid DNS alias")
		}

		current = alias
	}
}
