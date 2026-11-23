package control

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

const healthyAgentBody = `{"status":"running","mode":"read-only","network_ready":false}`

func testAgentToken() string {
	return strings.Repeat("ab", 32)
}

func TestAgentClientConfiguration(t *testing.T) {
	if _, err := NewAgentClient(""); err == nil {
		t.Fatal("expected missing token to fail")
	}

	if _, err := NewAgentClient("invalid"); err == nil {
		t.Fatal("expected invalid token to fail")
	}

	invalidAddresses := []string{
		"https://127.0.0.1:8788",
		"http://example.com:8788",
		"http://localhost:8788",
		"http://127.0.0.1",
		"http://user@127.0.0.1:8788",
		"http://127.0.0.1:8788/api",
		"http://127.0.0.1:8788?x=1",
	}

	for _, address := range invalidAddresses {
		if _, err := newAgentClient(address, testAgentToken()); err == nil {
			t.Errorf("address %q accepted", address)
		}
	}

	if _, err := NewAgentClient(testAgentToken()); err != nil {
		t.Fatal(err)
	}
}

func TestAgentClientOnline(t *testing.T) {
	token := testAgentToken()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/health" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}

		if r.Method != http.MethodGet {
			t.Errorf("unexpected method: %s", r.Method)
		}

		if r.Header.Get("Authorization") != "Bearer "+token {
			t.Error("missing or invalid Authorization header")
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(healthyAgentBody))
	}))
	defer server.Close()

	client, err := newAgentClient(server.URL, token)
	if err != nil {
		t.Fatal(err)
	}

	got := client.Snapshot(context.Background())

	if got.Status != "online" {
		t.Errorf("expected online, got %s", got.Status)
	}

	if got.Mode != "read-only" {
		t.Errorf("unexpected mode: %s", got.Mode)
	}

	if got.NetworkReady {
		t.Error("network must not be ready")
	}
}

func TestAgentClientFailureModes(t *testing.T) {
	cases := []struct {
		name       string
		httpStatus int
		body       string
		expected   string
	}{
		{
			name:       "unauthorized",
			httpStatus: http.StatusUnauthorized,
			expected:   "unauthorized",
		},
		{
			name:       "server error",
			httpStatus: http.StatusServiceUnavailable,
			expected:   "error",
		},
		{
			name:       "malformed JSON",
			httpStatus: http.StatusOK,
			body:       `{"status":`,
			expected:   "invalid_response",
		},
		{
			name:       "unexpected status",
			httpStatus: http.StatusOK,
			body:       `{"status":"stopped","mode":"read-only"}`,
			expected:   "invalid_response",
		},
		{
			name:       "unexpected mode",
			httpStatus: http.StatusOK,
			body:       `{"status":"running","mode":"enforcing"}`,
			expected:   "invalid_response",
		},
		{
			name:       "unverified readiness",
			httpStatus: http.StatusOK,
			body:       `{"status":"running","mode":"read-only","network_ready":true}`,
			expected:   "invalid_response",
		},
		{
			name:       "oversized body",
			httpStatus: http.StatusOK,
			body:       healthyAgentBody + strings.Repeat(" ", maxHealthBytes),
			expected:   "invalid_response",
		},
	}

	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tt.httpStatus)
				_, _ = w.Write([]byte(tt.body))
			}))
			defer server.Close()

			client, err := newAgentClient(server.URL, testAgentToken())
			if err != nil {
				t.Fatal(err)
			}

			got := client.Snapshot(context.Background())

			if got.Status != tt.expected {
				t.Errorf("expected %s, got %s", tt.expected, got.Status)
			}

			if got.NetworkReady {
				t.Error("unexpected network readiness")
			}
		})
	}
}

func TestAgentClientUnreachable(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	client, err := newAgentClient(server.URL, testAgentToken())
	if err != nil {
		t.Fatal(err)
	}

	server.Close()

	got := client.Snapshot(context.Background())

	if got.Status != "unreachable" {
		t.Errorf("expected unreachable, got %s", got.Status)
	}
}

func TestAgentClientRejectsRedirect(t *testing.T) {
	var redirectedRequests atomic.Int32

	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		redirectedRequests.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer target.Close()

	source := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL+"/health", http.StatusFound)
	}))
	defer source.Close()

	client, err := newAgentClient(source.URL, testAgentToken())
	if err != nil {
		t.Fatal(err)
	}

	got := client.Snapshot(context.Background())

	if got.Status != "error" {
		t.Errorf("expected error, got %s", got.Status)
	}

	if redirectedRequests.Load() != 0 {
		t.Fatal("client unexpectedly followed redirect")
	}
}

func getAgents(t *testing.T, api *API) (int, string, []AgentStatus) {
	t.Helper()

	request := httptest.NewRequest(http.MethodGet, "http://127.0.0.1:8787/api/v1/agents", nil)
	recorder := httptest.NewRecorder()

	api.Handler().ServeHTTP(recorder, request)

	var result struct {
		Items []AgentStatus `json:"items"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}

	return recorder.Code, recorder.Body.String(), result.Items
}

func newTestStore(t *testing.T) *Store {
	t.Helper()

	store, err := NewStore(filepath.Join(t.TempDir(), "state.json"))
	if err != nil {
		t.Fatal(err)
	}

	return store
}

func TestControllerAgentsAPI(t *testing.T) {
	agentServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(healthyAgentBody))
	}))
	defer agentServer.Close()

	client, err := newAgentClient(agentServer.URL, testAgentToken())
	if err != nil {
		t.Fatal(err)
	}

	api := &API{
		Store:   newTestStore(t),
		Started: time.Now(),
		Agent:   client,
	}

	code, body, items := getAgents(t, api)

	if code != http.StatusOK {
		t.Fatalf("unexpected status: %d", code)
	}

	if len(items) != 1 {
		t.Fatalf("expected one agent, got %d", len(items))
	}

	if items[0].Status != "online" {
		t.Errorf("unexpected status: %s", items[0].Status)
	}

	if strings.Contains(body, testAgentToken()) {
		t.Fatal("agent secret leaked through Controller API")
	}
}

func TestControllerWithoutAgent(t *testing.T) {
	api := &API{
		Store:   newTestStore(t),
		Started: time.Now(),
	}

	code, _, items := getAgents(t, api)

	if code != http.StatusOK || items == nil || len(items) != 0 {
		t.Fatal("expected an empty agent list")
	}
}
