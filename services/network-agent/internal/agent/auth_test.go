package agent

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestAuthenticationConfiguration(t *testing.T) {
	invalid := []string{
		"",
		"short-token",
		strings.Repeat("z", 64),
		strings.Repeat("ab", 31),
		strings.Repeat("ab", 32) + "\n",
	}

	for _, token := range invalid {
		if _, err := NewAuthenticatedHTTPHandler(token); err == nil {
			t.Errorf("token %q accepted", token)
		}
	}
}

func TestAuthenticatedHTTPHandler(t *testing.T) {
	token := strings.Repeat("ab", 32)
	handler, err := NewAuthenticatedHTTPHandler(token)
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name          string
		authorization []string
		host          string
		origin        string
		wantStatus    int
		wantCode      string
	}{
		{
			name:       "missing token",
			wantStatus: http.StatusUnauthorized,
			wantCode:   "UNAUTHORIZED",
		},
		{
			name:          "wrong token",
			authorization: []string{"Bearer wrong"},
			wantStatus:    http.StatusUnauthorized,
			wantCode:      "UNAUTHORIZED",
		},
		{
			name:          "wrong scheme",
			authorization: []string{"Basic " + token},
			wantStatus:    http.StatusUnauthorized,
			wantCode:      "UNAUTHORIZED",
		},
		{
			name:          "valid token",
			authorization: []string{"Bearer " + token},
			wantStatus:    http.StatusOK,
		},
		{
			name:          "uppercase token",
			authorization: []string{"Bearer " + strings.ToUpper(token)},
			wantStatus:    http.StatusOK,
		},
		{
			name:          "lowercase scheme",
			authorization: []string{"bearer " + token},
			wantStatus:    http.StatusOK,
		},
		{
			name:          "token with trailing whitespace",
			authorization: []string{"Bearer " + token + " "},
			wantStatus:    http.StatusUnauthorized,
			wantCode:      "UNAUTHORIZED",
		},
		{
			name: "duplicate authorization headers",
			authorization: []string{
				"Bearer " + token,
				"Bearer " + token,
			},
			wantStatus: http.StatusUnauthorized,
			wantCode:   "UNAUTHORIZED",
		},
		{
			name:          "blocked host",
			authorization: []string{"Bearer " + token},
			host:          "attacker.example:8788",
			wantStatus:    http.StatusForbidden,
			wantCode:      "HOST_BLOCKED",
		},
		{
			name:          "blocked origin",
			authorization: []string{"Bearer " + token},
			origin:        "http://attacker.example",
			wantStatus:    http.StatusForbidden,
			wantCode:      "ORIGIN_BLOCKED",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodGet, "http://127.0.0.1:8788/health", nil)

			for _, value := range tt.authorization {
				request.Header.Add("Authorization", value)
			}

			if tt.host != "" {
				request.Host = tt.host
			}

			if tt.origin != "" {
				request.Header.Set("Origin", tt.origin)
			}

			recorder := httptest.NewRecorder()

			handler.ServeHTTP(recorder, request)

			if recorder.Code != tt.wantStatus {
				t.Fatalf("expected status %d, got %d", tt.wantStatus, recorder.Code)
			}

			if tt.wantCode != "" {
				var response ErrorResponse
				if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
					t.Fatal(err)
				}

				if response.Error.Code != tt.wantCode {
					t.Errorf("expected error code %s, got %s", tt.wantCode, response.Error.Code)
				}
			}

			// The response must never reveal the secret.
			if strings.Contains(recorder.Body.String(), token) {
				t.Error("secret was exposed in response")
			}
		})
	}
}

func TestAuthRejectsRequestBeforeNextHandler(t *testing.T) {
	key := bytes.Repeat([]byte{0xab}, agentTokenBytes)
	calls := 0

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.WriteHeader(http.StatusOK)
	})

	handler := requireBearerToken(next, key)
	request := httptest.NewRequest(http.MethodGet, "http://127.0.0.1:8788/health", nil)
	recorder := httptest.NewRecorder()

	handler.ServeHTTP(recorder, request)

	if calls != 0 {
		t.Fatal("unauthorized request reached the next handler")
	}

	if recorder.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", recorder.Code)
	}

	if recorder.Header().Get("WWW-Authenticate") == "" {
		t.Error("missing WWW-Authenticate header")
	}
}

func TestAuthAcceptsConfiguredUppercaseToken(t *testing.T) {
	handler, err := NewAuthenticatedHTTPHandler(strings.Repeat("AB", 32))
	if err != nil {
		t.Fatal(err)
	}

	request := httptest.NewRequest(http.MethodGet, "http://127.0.0.1:8788/health", nil)

	request.Header.Set("Authorization", "Bearer "+strings.Repeat("ab", 32))

	recorder := httptest.NewRecorder()

	handler.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", recorder.Code)
	}
}

func TestAuthRejectsEmptyKey(t *testing.T) {
	handler := requireBearerToken(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}),
		nil,
	)

	request := httptest.NewRequest(http.MethodGet, "http://127.0.0.1:8788/health", nil)
	recorder := httptest.NewRecorder()

	handler.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", recorder.Code)
	}
}
