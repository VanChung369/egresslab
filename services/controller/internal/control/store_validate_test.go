package control

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const validStateJSON = `{
  "version": 1,
  "profiles": [
    {
      "id": "profile_0123456789abcdef",
      "name": "Office",
      "status": "unconfigured",
      "unique_ip_required": true,
      "kill_switch_required": true,
      "created_at": "2026-11-20T10:00:00Z"
    }
  ],
  "endpoints": [
    {
      "id": "proxy_0123456789abcdef",
      "name": "Browser",
      "protocol": "socks5",
      "listen_host": "127.0.0.1",
      "port": 1080,
      "profile_id": "profile_0123456789abcdef",
      "status": "draft",
      "created_at": "2026-11-20T10:01:00Z"
    }
  ]
}`

func writeState(t *testing.T, contents string) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), "state.json")
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatal(err)
	}

	return path
}

func TestNewStoreAcceptsValidState(t *testing.T) {
	store, err := NewStore(writeState(t, validStateJSON))
	if err != nil {
		t.Fatal(err)
	}

	if len(store.Profiles()) != 1 || len(store.Endpoints()) != 1 {
		t.Fatalf("unexpected contents: %+v %+v", store.Profiles(), store.Endpoints())
	}
}

func TestNewStoreRejectsBrokenInvariants(t *testing.T) {
	cases := map[string][2]string{
		"malformed profile id":    {`"id": "profile_0123456789abcdef"`, `"id": "profile_XYZ"`},
		"surrounding whitespace":  {`"name": "Office"`, `"name": " Office"`},
		"short name":              {`"name": "Office"`, `"name": "O"`},
		"profile status":          {`"status": "unconfigured"`, `"status": "active"`},
		"tunnel attached":         {`"status": "unconfigured",`, `"status": "unconfigured", "tunnel_id": "tunnel_1",`},
		"unique IP disabled":      {`"unique_ip_required": true`, `"unique_ip_required": false`},
		"kill-switch disabled":    {`"kill_switch_required": true`, `"kill_switch_required": false`},
		"missing profile time":    {`"created_at": "2026-11-20T10:00:00Z"`, `"created_at": "0001-01-01T00:00:00Z"`},
		"malformed endpoint id":   {`"id": "proxy_0123456789abcdef"`, `"id": "proxy_1"`},
		"protocol":                {`"protocol": "socks5"`, `"protocol": "socks4"`},
		"non-loopback listener":   {`"listen_host": "127.0.0.1"`, `"listen_host": "0.0.0.0"`},
		"privileged port":         {`"port": 1080`, `"port": 80`},
		"dangling profile":        {`"profile_id": "profile_0123456789abcdef"`, `"profile_id": "profile_ffffffffffffffff"`},
		"endpoint status":         {`"status": "draft"`, `"status": "running"`},
		"unknown field":           {`"version": 1,`, `"version": 1, "network_ready": true,`},
		"trailing data":           {`  ]` + "\n}", `  ]` + "\n}{}"},
		"endpoint id reused":      {`"id": "proxy_0123456789abcdef"`, `"id": "profile_0123456789abcdef"`},
		"missing endpoint time":   {`"created_at": "2026-11-20T10:01:00Z"`, `"created_at": "0001-01-01T00:00:00Z"`},
		"endpoint name too long":  {`"name": "Browser"`, `"name": "` + strings.Repeat("x", 65) + `"`},
		"endpoint name has space": {`"name": "Browser"`, `"name": "Browser "`},
	}

	for name, edit := range cases {
		t.Run(name, func(t *testing.T) {
			if !strings.Contains(validStateJSON, edit[0]) {
				t.Fatalf("test edit %q does not apply", edit[0])
			}

			broken := strings.Replace(validStateJSON, edit[0], edit[1], 1)
			if _, err := NewStore(writeState(t, broken)); err == nil {
				t.Fatal("invalid state was accepted")
			}
		})
	}
}

func TestNewStoreRejectsDuplicates(t *testing.T) {
	profile := `{"id": "profile_%s", "name": "%s", "status": "unconfigured", "unique_ip_required": true,
      "kill_switch_required": true, "created_at": "2026-11-20T10:00:00Z"}`
	endpoint := `{"id": "proxy_%s", "name": "%s", "protocol": "socks5", "listen_host": "127.0.0.1",
      "port": %d, "profile_id": "profile_0000000000000001", "status": "draft", "created_at": "2026-11-20T10:00:00Z"}`

	state := func(profiles, endpoints []string) string {
		return `{"version": 1, "profiles": [` + strings.Join(profiles, ",") +
			`], "endpoints": [` + strings.Join(endpoints, ",") + `]}`
	}

	p := func(id, name string) string { return fmt.Sprintf(profile, id, name) }
	e := func(id, name string, port int) string { return fmt.Sprintf(endpoint, id, name, port) }

	cases := map[string]string{
		"profile id": state([]string{p("0000000000000001", "One"), p("0000000000000001", "Two")}, nil),
		"profile name (case-insensitive)": state(
			[]string{p("0000000000000001", "Office"), p("0000000000000002", "OFFICE")}, nil),
		"endpoint port": state([]string{p("0000000000000001", "One")},
			[]string{e("0000000000000001", "A1", 1080), e("0000000000000002", "B1", 1080)}),
		"endpoint name": state([]string{p("0000000000000001", "One")},
			[]string{e("0000000000000001", "Same", 1080), e("0000000000000002", "same", 1081)}),
	}

	valid := state([]string{p("0000000000000001", "One")},
		[]string{e("0000000000000001", "A1", 1080), e("0000000000000002", "B1", 1081)})
	if _, err := NewStore(writeState(t, valid)); err != nil {
		t.Fatalf("baseline state rejected: %v", err)
	}

	for name, contents := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := NewStore(writeState(t, contents))
			if !errors.Is(err, ErrInvalidState) {
				t.Fatalf("expected ErrInvalidState, got %v", err)
			}
		})
	}
}
