package agent

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestHealthEndpoint(t *testing.T) {
	handler := NewHTTPHandler()

	request := httptest.NewRequest(http.MethodGet, "/health", nil)

	recorder := httptest.NewRecorder()

	handler.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf(
			"expected status %d, got %d",
			http.StatusOK,
			recorder.Code,
		)
	}

	contentType := recorder.Header().Get("Content-Type")

	if !strings.HasPrefix(contentType, "application/json") {
		t.Fatalf(
			"expected JSON content type, got %s",
			contentType,
		)
	}

	var response HealthResponse

	if err := json.Unmarshal(
		recorder.Body.Bytes(),
		&response,
	); err != nil {
		t.Fatalf("invalid JSON response: %v", err)
	}

	if response.Status != "running" {
		t.Errorf("expected running, got %s", response.Status)
	}

	if response.Mode != "read-only" {
		t.Errorf("expected read-only, got %s", response.Mode)
	}

	if response.NetworkReady {
		t.Error("expected network_ready to be false")
	}
}

func TestHealthEndpointMethodNotAllowed(t *testing.T) {

	handler := NewHTTPHandler()

	request := httptest.NewRequest(
		http.MethodPost,
		"/health",
		nil,
	)

	recorder := httptest.NewRecorder()

	handler.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusMethodNotAllowed {
		t.Fatalf(
			"expected status %d, got %d",
			http.StatusMethodNotAllowed,
			recorder.Code,
		)
	}
}

func TestUnknownEndpoint(t *testing.T) {

	handler := NewHTTPHandler()

	request := httptest.NewRequest(
		http.MethodGet,
		"/unknown",
		nil,
	)

	recorder := httptest.NewRecorder()

	handler.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusNotFound {
		t.Fatalf(
			"expected status %d, got %d",
			http.StatusNotFound,
			recorder.Code,
		)
	}
}
