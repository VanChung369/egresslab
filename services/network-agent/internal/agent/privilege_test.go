package agent

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

func TestCheckAgentPrivileges(t *testing.T) {
	const unprivileged = "Name:\tegresslab-agent\nUid:\t1000\t1000\t1000\t1000\nCapEff:\t0000000000000000\n"

	if err := checkAgentPrivileges(1000, unprivileged); err != nil {
		t.Fatalf("unprivileged agent refused: %v", err)
	}

	refused := map[string]struct {
		euid   int
		status string
	}{
		"root":          {0, unprivileged},
		"CAP_NET_ADMIN": {1000, strings.Replace(unprivileged, "0000000000000000", "0000000000001000", 1)},
		"CAP_NET_RAW":   {1000, strings.Replace(unprivileged, "0000000000000000", "0000000000002000", 1)},
		"CAP_SYS_ADMIN": {1000, strings.Replace(unprivileged, "0000000000000000", "0000000000200000", 1)},
		"full set":      {1000, strings.Replace(unprivileged, "0000000000000000", "000001ffffffffff", 1)},
		"missing":       {1000, "Name:\tegresslab-agent\n"},
		"garbage":       {1000, "CapEff:\tzz\n"},
	}

	for name, c := range refused {
		if err := checkAgentPrivileges(c.euid, c.status); !errors.Is(err, ErrPrivilegedAgent) {
			t.Errorf("%s: accepted (%v)", name, err)
		}
	}
}

// The agent's HTTP API is read-only by design: every route is GET and every other method is
// refused. This guards the review finding that ip/wg/nft must not reach an HTTP handler before a
// privileged helper and an authorization protocol exist.
func TestAgentHTTPRoutesAreReadOnly(t *testing.T) {
	handler := newHTTPHandler(
		func() ([]NetworkInterface, error) { return nil, nil },
		nil, nil,
		func() ([]NamedNamespace, error) { return nil, nil },
	)

	paths := []string{"/health", "/system/info", "/network/interfaces", "/network/links", "/capabilities", "/network/namespaces"}

	for _, path := range paths {
		for _, method := range []string{http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete} {
			request := httptest.NewRequest(method, path, strings.NewReader("{}"))
			request.Host = "127.0.0.1:8788"

			recorder := httptest.NewRecorder()
			handler.ServeHTTP(recorder, request)

			if recorder.Code != http.StatusMethodNotAllowed {
				t.Errorf("%s %s returned %d", method, path, recorder.Code)
			}
		}
	}
}

var (
	routePattern      = regexp.MustCompile(`HandleFunc\("([A-Z]+) `)
	anyRoutePattern   = regexp.MustCompile(`\.Handle(Func)?\(`)
	privilegedPattern = regexp.MustCompile(
		`NetNSLabManager|LabFirewall|SealedLabBackend|VPNEgressLab|WireGuardLab|WireGuardConfigVault|SealedWireGuardStore|` +
			`EgressCandidateRegistry|LabRecovery|newSystemWGRunner|newSystemUnderlayNFT|` +
			`findSystemBinary\("(wg|nft)"\)`)
)

// Source-level gate: files that serve HTTP must not reference privileged lab machinery, and
// every registered route must be a GET.
func TestHTTPCodeDoesNotReachPrivilegedLabCode(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}

	served := 0

	for _, file := range files {
		if strings.HasSuffix(file, "_test.go") {
			continue
		}

		data, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}

		source := string(data)
		if !strings.Contains(source, "http.ResponseWriter") && !anyRoutePattern.MatchString(source) {
			continue
		}

		served++

		if match := privilegedPattern.FindString(source); match != "" {
			t.Errorf("%s serves HTTP and references privileged code (%s)", file, match)
		}

		for _, route := range routePattern.FindAllStringSubmatch(source, -1) {
			if route[1] != http.MethodGet {
				t.Errorf("%s registers a %s route", file, route[1])
			}
		}
	}

	if served == 0 {
		t.Fatal("found no HTTP-serving files; the guard is not checking anything")
	}
}
