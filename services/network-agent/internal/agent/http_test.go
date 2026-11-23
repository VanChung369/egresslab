package agent

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"runtime"
	"strings"
	"testing"
)

// newTestRequest builds a request addressed to the agent's loopback listener,
// so it passes the Host check like a real local client would.
func newTestRequest(method, path string) *http.Request {
	return httptest.NewRequest(
		method,
		"http://127.0.0.1:8788"+path,
		nil,
	)
}

// assertErrorResponse checks the status code and the
// {"error": {"code", "message"}} envelope shared with the controller.
func assertErrorResponse(
	t *testing.T,
	recorder *httptest.ResponseRecorder,
	status int,
	code string,
) {

	t.Helper()

	if recorder.Code != status {
		t.Fatalf(
			"expected status %d, got %d",
			status,
			recorder.Code,
		)
	}

	var response ErrorResponse

	if err := json.Unmarshal(
		recorder.Body.Bytes(),
		&response,
	); err != nil {
		t.Fatalf("invalid JSON error response: %v", err)
	}

	if response.Error.Code != code {
		t.Errorf(
			"expected error code %s, got %s",
			code,
			response.Error.Code,
		)
	}

	if response.Error.Message == "" {
		t.Error("expected error message")
	}
}

func TestHealthEndpoint(t *testing.T) {

	handler := NewHTTPHandler()

	request := newTestRequest(http.MethodGet, "/health")

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
		t.Errorf(
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

func TestSystemInfoEndpoint(t *testing.T) {

	handler := NewHTTPHandler()

	request := newTestRequest(http.MethodGet, "/system/info")

	recorder := httptest.NewRecorder()

	handler.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf(
			"expected status %d, got %d",
			http.StatusOK,
			recorder.Code,
		)
	}

	var response SystemInfoResponse

	if err := json.Unmarshal(
		recorder.Body.Bytes(),
		&response,
	); err != nil {
		t.Fatalf("invalid JSON response: %v", err)
	}

	if response.OS != runtime.GOOS {
		t.Errorf(
			"expected OS %s, got %s",
			runtime.GOOS,
			response.OS,
		)
	}

	if response.Architecture != runtime.GOARCH {
		t.Errorf(
			"expected architecture %s, got %s",
			runtime.GOARCH,
			response.Architecture,
		)
	}

	if response.GoVersion == "" {
		t.Error("expected Go version to be present")
	}
}

func TestSystemInfoError(t *testing.T) {

	handler := newHTTPHandler(
		nil,
		func() (SystemInfoResponse, error) {
			return SystemInfoResponse{}, errors.New("simulated failure")
		},
	)

	request := newTestRequest(http.MethodGet, "/system/info")

	recorder := httptest.NewRecorder()

	handler.ServeHTTP(recorder, request)

	assertErrorResponse(
		t,
		recorder,
		http.StatusInternalServerError,
		"INTERNAL_ERROR",
	)
}

func TestNetworkInterfacesEndpoint(t *testing.T) {

	expected := []NetworkInterface{
		{
			Index:        1,
			Name:         "lo",
			MTU:          65536,
			HardwareAddr: "",
			Flags:        []string{"up", "loopback"},
			Addresses:    []string{"127.0.0.1/8"},
		},
	}

	handler := newHTTPHandler(
		func() ([]NetworkInterface, error) {
			return expected, nil
		},
		nil,
	)

	request := newTestRequest(http.MethodGet, "/network/interfaces")

	recorder := httptest.NewRecorder()

	handler.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf(
			"expected status %d, got %d",
			http.StatusOK,
			recorder.Code,
		)
	}

	var response NetworkInterfacesResponse

	if err := json.Unmarshal(
		recorder.Body.Bytes(),
		&response,
	); err != nil {
		t.Fatalf("invalid JSON response: %v", err)
	}

	if !reflect.DeepEqual(response.Interfaces, expected) {
		t.Errorf(
			"expected %+v, got %+v",
			expected,
			response.Interfaces,
		)
	}
}

func TestNetworkInterfacesNilBecomesEmptyArray(t *testing.T) {

	handler := newHTTPHandler(
		func() ([]NetworkInterface, error) {
			return nil, nil
		},
		nil,
	)

	request := newTestRequest(http.MethodGet, "/network/interfaces")

	recorder := httptest.NewRecorder()

	handler.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf(
			"expected status %d, got %d",
			http.StatusOK,
			recorder.Code,
		)
	}

	var response map[string]json.RawMessage

	if err := json.Unmarshal(
		recorder.Body.Bytes(),
		&response,
	); err != nil {
		t.Fatalf("invalid JSON response: %v", err)
	}

	if got := string(response["interfaces"]); got != "[]" {
		t.Errorf("expected interfaces to be [], got %s", got)
	}
}

func TestNetworkInterfacesError(t *testing.T) {

	handler := newHTTPHandler(
		func() ([]NetworkInterface, error) {
			return nil, errors.New("simulated failure")
		},
		nil,
	)

	request := newTestRequest(http.MethodGet, "/network/interfaces")

	recorder := httptest.NewRecorder()

	handler.ServeHTTP(recorder, request)

	assertErrorResponse(
		t,
		recorder,
		http.StatusInternalServerError,
		"INTERNAL_ERROR",
	)
}

func TestUnknownEndpoint(t *testing.T) {

	handler := NewHTTPHandler()

	request := newTestRequest(http.MethodGet, "/unknown")

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

func TestHealthEndpointMethodNotAllowed(t *testing.T) {

	handler := NewHTTPHandler()

	request := newTestRequest(http.MethodPost, "/health")

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

// Checks the Content-Type of the JSON response.
func TestNetworkInterfacesContentType(t *testing.T) {

	handler := newHTTPHandler(
		func() ([]NetworkInterface, error) {
			return []NetworkInterface{}, nil
		},
		nil,
	)

	request := newTestRequest(http.MethodGet, "/network/interfaces")

	recorder := httptest.NewRecorder()

	handler.ServeHTTP(recorder, request)

	contentType := recorder.Header().Get("Content-Type")

	if !strings.HasPrefix(contentType, "application/json") {
		t.Errorf(
			"expected JSON content type, got %s",
			contentType,
		)
	}
}

func TestAllowsLoopbackHosts(t *testing.T) {

	handler := NewHTTPHandler()

	hosts := []string{
		"127.0.0.1:8788",
		"localhost:8788",
		"LOCALHOST:8788",
		"[::1]:8788",
		"localhost",
	}

	for _, host := range hosts {
		t.Run(host, func(t *testing.T) {

			request := newTestRequest(http.MethodGet, "/health")
			request.Host = host

			recorder := httptest.NewRecorder()

			handler.ServeHTTP(recorder, request)

			if recorder.Code != http.StatusOK {
				t.Errorf(
					"expected status %d, got %d",
					http.StatusOK,
					recorder.Code,
				)
			}
		})
	}
}

// A DNS-rebinding page reaches 127.0.0.1 but the browser still sends the
// attacker's hostname, so anything that is not a loopback Host is rejected.
func TestRejectsNonLoopbackHost(t *testing.T) {

	handler := NewHTTPHandler()

	hosts := []string{
		"attacker.example:8788",
		"attacker.example",
		"127.0.0.1.attacker.example:8788",
		"localhost.attacker.example:8788",
		"192.168.1.10:8788",
		"",
	}

	for _, host := range hosts {
		t.Run(host, func(t *testing.T) {

			request := newTestRequest(http.MethodGet, "/system/info")
			request.Host = host

			recorder := httptest.NewRecorder()

			handler.ServeHTTP(recorder, request)

			assertErrorResponse(
				t,
				recorder,
				http.StatusForbidden,
				"HOST_BLOCKED",
			)
		})
	}
}

func TestRejectsBrowserOrigin(t *testing.T) {

	handler := NewHTTPHandler()

	origins := []string{
		"http://attacker.example",
		"null",
	}

	for _, origin := range origins {
		t.Run(origin, func(t *testing.T) {

			request := newTestRequest(http.MethodGet, "/network/interfaces")
			request.Header.Set("Origin", origin)

			recorder := httptest.NewRecorder()

			handler.ServeHTTP(recorder, request)

			assertErrorResponse(
				t,
				recorder,
				http.StatusForbidden,
				"ORIGIN_BLOCKED",
			)
		})
	}
}
