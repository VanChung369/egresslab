package agent

import (
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"reflect"
	"runtime"
	"strings"
	"testing"
)

func TestHealthEndpoint(t *testing.T) {

	handler := NewHTTPHandler()

	request := httptest.NewRequest(
		http.MethodGet,
		"/health",
		nil,
	)

	recorder := httptest.NewRecorder()

	handler.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf(
			"expected status %d, got %d",
			http.StatusOK,
			recorder.Code,
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

	if response.NetworkReady {
		t.Error("expected network_ready to be false")
	}
}

func TestSystemInfoEndpoint(t *testing.T) {

	handler := NewHTTPHandler()

	request := httptest.NewRequest(
		http.MethodGet,
		"/system/info",
		nil,
	)

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
	)

	request := httptest.NewRequest(
		http.MethodGet,
		"/network/interfaces",
		nil,
	)

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

	if len(response.Interfaces) != 1 {
		t.Fatalf(
			"expected 1 interface, got %d",
			len(response.Interfaces),
		)
	}

	actual := response.Interfaces[0]

	if actual.Name != "lo" {
		t.Errorf("expected lo, got %s", actual.Name)
	}

	if actual.MTU != 65536 {
		t.Errorf("expected MTU 65536, got %d", actual.MTU)
	}

	if !reflect.DeepEqual(
		actual.Flags,
		[]string{"up", "loopback"},
	) {
		t.Errorf("unexpected flags: %v", actual.Flags)
	}
}

func TestNetworkInterfacesError(t *testing.T) {

	handler := newHTTPHandler(
		func() ([]NetworkInterface, error) {
			return nil, errors.New("simulated failure")
		},
	)

	request := httptest.NewRequest(
		http.MethodGet,
		"/network/interfaces",
		nil,
	)

	recorder := httptest.NewRecorder()

	handler.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusInternalServerError {
		t.Fatalf(
			"expected status %d, got %d",
			http.StatusInternalServerError,
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

	if response.Error == "" {
		t.Error("expected error message")
	}
}

func TestInterfaceFlags(t *testing.T) {

	flags := net.FlagUp | net.FlagLoopback

	result := interfaceFlags(flags)

	expected := []string{"up", "loopback"}

	if !reflect.DeepEqual(result, expected) {
		t.Errorf(
			"expected %v, got %v",
			expected,
			result,
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

// Kiểm tra Content-Type của JSON response.
func TestNetworkInterfacesContentType(t *testing.T) {

	handler := newHTTPHandler(
		func() ([]NetworkInterface, error) {
			return []NetworkInterface{}, nil
		},
	)

	request := httptest.NewRequest(
		http.MethodGet,
		"/network/interfaces",
		nil,
	)

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
