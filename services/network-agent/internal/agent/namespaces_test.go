package agent

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestListNamedNamespaces(t *testing.T) {

	root := t.TempDir()

	for _, name := range []string{
		"vpn-b",
		"vpn-a",
	} {

		path := filepath.Join(root, name)

		if err := os.WriteFile(
			path,
			nil,
			0600,
		); err != nil {
			t.Fatal(err)
		}
	}

	if err := os.Mkdir(
		filepath.Join(root, "folder"),
		0700,
	); err != nil {
		t.Fatal(err)
	}

	got, err := listNamedNamespaces(root)
	if err != nil {
		t.Fatal(err)
	}

	expected := []NamedNamespace{
		{Name: "vpn-a"},
		{Name: "vpn-b"},
	}

	if !reflect.DeepEqual(got, expected) {
		t.Errorf(
			"expected %+v, got %+v",
			expected,
			got,
		)
	}
}

func TestMissingNamespaceDirectory(t *testing.T) {

	root := filepath.Join(
		t.TempDir(),
		"missing",
	)

	got, err := listNamedNamespaces(root)
	if err != nil {
		t.Fatal(err)
	}

	if got == nil || len(got) != 0 {
		t.Fatalf("expected empty slice, got %+v", got)
	}
}

func TestNamespaceDirectoryError(t *testing.T) {

	path := filepath.Join(
		t.TempDir(),
		"not-a-directory",
	)

	if err := os.WriteFile(
		path,
		nil,
		0600,
	); err != nil {
		t.Fatal(err)
	}

	_, err := listNamedNamespaces(path)

	if err == nil {
		t.Fatal("expected directory read error")
	}
}

func TestNamespacesEndpoint(t *testing.T) {

	provider := func() ([]NamedNamespace, error) {
		return []NamedNamespace{
			{Name: "egresslab-profile-a"},
		}, nil
	}

	handler := handleNamespaces(provider)

	request := httptest.NewRequest(
		http.MethodGet,
		"/network/namespaces",
		nil,
	)

	recorder := httptest.NewRecorder()

	handler.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf(
			"expected 200, got %d",
			recorder.Code,
		)
	}

	var response NamedNamespacesResponse

	if err := json.Unmarshal(
		recorder.Body.Bytes(),
		&response,
	); err != nil {
		t.Fatal(err)
	}

	if response.Scope != "named" {
		t.Errorf("unexpected scope: %s", response.Scope)
	}

	if len(response.Namespaces) != 1 {
		t.Fatalf("expected one namespace")
	}

	if response.Namespaces[0].Name != "egresslab-profile-a" {
		t.Errorf("unexpected namespace name")
	}
}

func TestNamespacesUnsupported(t *testing.T) {

	handler := handleNamespaces(
		func() ([]NamedNamespace, error) {
			return nil, ErrLinuxRequired
		},
	)

	recorder := httptest.NewRecorder()

	request := httptest.NewRequest(
		http.MethodGet,
		"/network/namespaces",
		nil,
	)

	handler.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusNotImplemented {
		t.Fatalf(
			"expected 501, got %d",
			recorder.Code,
		)
	}
}

func TestNamespacesUnavailable(t *testing.T) {

	handler := handleNamespaces(
		func() ([]NamedNamespace, error) {
			return nil, errors.New("simulated filesystem error")
		},
	)

	recorder := httptest.NewRecorder()

	request := httptest.NewRequest(
		http.MethodGet,
		"/network/namespaces",
		nil,
	)

	handler.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusServiceUnavailable {
		t.Fatalf(
			"expected 503, got %d",
			recorder.Code,
		)
	}
}
