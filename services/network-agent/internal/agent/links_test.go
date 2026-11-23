package agent

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

const linkFixture = `[
    {
        "ifindex": 1,
        "ifname": "lo",
        "flags": ["LOOPBACK", "UP"],
        "link_type": "loopback",
        "operstate": "UNKNOWN"
    },
    {
        "ifindex": 2,
        "ifname": "eth0",
        "link_type": "ether",
        "operstate": "UP"
    },
    {
        "ifindex": 7,
        "ifname": "wg0",
        "linkinfo": {
            "info_kind": "wireguard"
        },
        "operstate": "UNKNOWN"
    },
    {
        "ifindex": 9,
        "ifname": "veth123",
        "linkinfo": {
            "info_kind": "veth"
        },
        "operstate": "DOWN"
    }
]`

func TestParseIPLinkJSON(t *testing.T) {

	links, err := parseIPLinkJSON(
		[]byte(linkFixture),
	)

	if err != nil {
		t.Fatal(err)
	}

	expectedCategories := []string{
		"loopback",
		"unknown",
		"vpn-interface",
		"virtual",
	}

	if len(links) != len(expectedCategories) {
		t.Fatalf("unexpected link count: %d", len(links))
	}

	for i, expected := range expectedCategories {
		if links[i].Category != expected {
			t.Errorf(
				"%s: got %s, want %s",
				links[i].Name,
				links[i].Category,
				expected,
			)
		}
	}

	if links[1].Kind != "unknown" {
		t.Errorf("unexpected kind: %s", links[1].Kind)
	}
}

func TestInvalidIPLinkJSON(t *testing.T) {

	cases := []string{
		"invalid json",
		"null",
		"[{}]",
	}

	for _, input := range cases {
		_, err := parseIPLinkJSON([]byte(input))

		if err == nil {
			t.Errorf("expected error for %q", input)
		}
	}
}

func TestInterfaceAdminState(t *testing.T) {

	flags := net.FlagBroadcast | net.FlagMulticast

	if got := interfaceAdminState(flags); got != "down" {
		t.Errorf("expected down, got %s", got)
	}

	if got := interfaceAdminState(net.FlagUp); got != "up" {
		t.Errorf("expected up, got %s", got)
	}

	result := interfaceFlags(flags)

	for _, value := range result {
		if value == "down" {
			t.Error("down must not be a capability flag")
		}
	}
}

func TestClassifiedLinksHandler(t *testing.T) {

	provider := func(
		ctx context.Context,
	) ([]ClassifiedLink, error) {

		return []ClassifiedLink{
			{
				Index:            1,
				Name:             "lo",
				Kind:             "loopback",
				Category:         "loopback",
				OperationalState: "unknown",
			},
		}, nil
	}

	handler := handleLinks(provider)

	request := httptest.NewRequest(
		http.MethodGet,
		"/network/links",
		nil,
	)

	recorder := httptest.NewRecorder()

	handler.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf("unexpected status: %d", recorder.Code)
	}

	var response ClassifiedLinksResponse

	if err := json.Unmarshal(
		recorder.Body.Bytes(),
		&response,
	); err != nil {
		t.Fatal(err)
	}

	if len(response.Links) != 1 {
		t.Fatalf("expected one link")
	}

	if response.Links[0].Category != "loopback" {
		t.Errorf("unexpected category")
	}
}

func TestClassifiedLinksUnsupported(t *testing.T) {

	handler := handleLinks(
		func(
			context.Context,
		) ([]ClassifiedLink, error) {
			return nil, ErrLinuxRequired
		},
	)

	request := httptest.NewRequest(
		http.MethodGet,
		"/network/links",
		nil,
	)

	recorder := httptest.NewRecorder()

	handler.ServeHTTP(recorder, request)

	assertErrorResponse(
		t,
		recorder,
		http.StatusNotImplemented,
		"LINUX_REQUIRED",
	)
}

func TestClassifiedLinksFailure(t *testing.T) {

	handler := handleLinks(
		func(
			context.Context,
		) ([]ClassifiedLink, error) {
			return nil, errors.New("private internal error")
		},
	)

	request := httptest.NewRequest(
		http.MethodGet,
		"/network/links",
		nil,
	)

	recorder := httptest.NewRecorder()

	handler.ServeHTTP(recorder, request)

	assertErrorResponse(
		t,
		recorder,
		http.StatusServiceUnavailable,
		"LINKS_UNAVAILABLE",
	)

	if strings.Contains(
		recorder.Body.String(),
		"private internal error",
	) {
		t.Error("internal error was exposed")
	}
}

func TestNetworkLinksRoute(t *testing.T) {

	handler := newHTTPHandler(
		nil,
		nil,
		func(context.Context) ([]ClassifiedLink, error) {
			return []ClassifiedLink{
				{
					Index:            7,
					Name:             "wg0",
					Kind:             "wireguard",
					Category:         "vpn-interface",
					OperationalState: "unknown",
				},
			}, nil
		},
		nil,
	)

	request := newTestRequest(http.MethodGet, "/network/links")

	recorder := httptest.NewRecorder()

	handler.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf(
			"expected status %d, got %d",
			http.StatusOK,
			recorder.Code,
		)
	}

	var response ClassifiedLinksResponse

	if err := json.Unmarshal(
		recorder.Body.Bytes(),
		&response,
	); err != nil {
		t.Fatalf("invalid JSON response: %v", err)
	}

	if len(response.Links) != 1 || response.Links[0].Name != "wg0" {
		t.Errorf("unexpected links: %+v", response.Links)
	}
}

func TestNetworkLinksRouteRejectsNonLoopbackHost(t *testing.T) {

	called := false

	handler := newHTTPHandler(
		nil,
		nil,
		func(context.Context) ([]ClassifiedLink, error) {
			called = true
			return nil, nil
		},
		nil,
	)

	request := newTestRequest(http.MethodGet, "/network/links")
	request.Host = "attacker.example:8788"

	recorder := httptest.NewRecorder()

	handler.ServeHTTP(recorder, request)

	assertErrorResponse(
		t,
		recorder,
		http.StatusForbidden,
		"HOST_BLOCKED",
	)

	if called {
		t.Error("link provider ran for a blocked request")
	}
}

func TestParseIPLinkJSONRealOutput(t *testing.T) {

	data, err := os.ReadFile("testdata/ip-link-details.json")
	if err != nil {
		t.Fatal(err)
	}

	links, err := parseIPLinkJSON(data)
	if err != nil {
		t.Fatal(err)
	}

	if len(links) != 23 {
		t.Fatalf("expected 23 links, got %d", len(links))
	}

	byName := make(map[string]ClassifiedLink, len(links))

	for _, link := range links {
		byName[link.Name] = link
	}

	expected := map[string]struct {
		kind      string
		category  string
		operState string
	}{
		"lo":       {"loopback", "loopback", "unknown"},
		"eth0":     {"veth", "virtual", "up"},
		"veth0":    {"veth", "virtual", "lowerlayerdown"},
		"br0":      {"bridge", "virtual", "down"},
		"eth0.10":  {"vlan", "virtual", "down"},
		"macvlan0": {"macvlan", "virtual", "down"},
		"ipvlan0":  {"ipvlan", "virtual", "down"},
		"tun0":     {"tun", "tunnel", "down"},
		"tap0":     {"tap", "tunnel", "down"},
		"gre1":     {"gre", "tunnel", "down"},
		"ip6tnl0":  {"ip6tnl", "tunnel", "down"},
		"ip6gre0":  {"ip6gre", "tunnel", "down"},
		"wg0":      {"wireguard", "vpn-interface", "down"},
	}

	for name, want := range expected {

		link, ok := byName[name]
		if !ok {
			t.Errorf("%s: missing from parsed links", name)
			continue
		}

		if link.Kind != want.kind ||
			link.Category != want.category ||
			link.OperationalState != want.operState {
			t.Errorf(
				"%s: got %s/%s/%s, want %s/%s/%s",
				name,
				link.Kind,
				link.Category,
				link.OperationalState,
				want.kind,
				want.category,
				want.operState,
			)
		}
	}
}
