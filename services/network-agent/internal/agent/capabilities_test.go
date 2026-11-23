package agent

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os/exec"
	"runtime"
	"testing"
)

func TestCapabilitiesOnMac(t *testing.T) {

	got := detectCapabilities(capabilityProbe{
		OS: "darwin",
	})

	if got.NetworkReady {
		t.Fatal("network must not be ready")
	}

	if len(got.Checks) != 5 {
		t.Fatalf("expected 5 checks, got %d", len(got.Checks))
	}

	for key, check := range got.Checks {
		if check.Status != "unsupported" {
			t.Errorf("%s: expected unsupported, got %s", key, check.Status)
		}
	}
}

func TestCapabilitiesOnLinux(t *testing.T) {

	got := detectCapabilities(capabilityProbe{
		OS: "linux",

		LookPath: func(name string) (string, error) {
			if name == "wg" {
				return "", exec.ErrNotFound
			}
			return "/usr/bin/" + name, nil
		},

		NamespaceHandle: func() (bool, error) {
			return true, nil
		},

		NetAdminEffective: func() (bool, error) {
			return false, nil
		},
	})

	expected := map[string]string{
		"iproute2":                "detected",
		"wireguard_tools":         "missing",
		"nftables":                "detected",
		"network_namespace":       "detected",
		"cap_net_admin_effective": "missing",
	}

	if len(got.Checks) != len(expected) {
		t.Fatalf("expected %d checks, got %d", len(expected), len(got.Checks))
	}

	for key, want := range expected {
		if got.Checks[key].Status != want {
			t.Errorf(
				"%s: expected %s, got %s",
				key,
				want,
				got.Checks[key].Status,
			)
		}
	}

	if got.NetworkReady {
		t.Error("capability detection must not enable networking")
	}
}

func TestCapabilityProbeFailures(t *testing.T) {

	probeErr := errors.New("permission denied")

	got := detectCapabilities(capabilityProbe{
		OS: "linux",

		LookPath: func(string) (string, error) {
			return "", probeErr
		},

		NamespaceHandle: func() (bool, error) {
			return false, probeErr
		},

		NetAdminEffective: func() (bool, error) {
			return false, probeErr
		},
	})

	if len(got.Checks) != 5 {
		t.Fatalf("expected 5 checks, got %d", len(got.Checks))
	}

	for key, check := range got.Checks {
		if check.Status != "unknown" {
			t.Errorf("%s: expected unknown, got %s", key, check.Status)
		}
	}
}

func TestParseEffectiveNetAdmin(t *testing.T) {

	tests := []struct {
		name    string
		input   string
		want    bool
		wantErr bool
	}{
		{
			name:  "CAP_NET_ADMIN present",
			input: "CapEff:\t0000000000001000\n",
			want:  true,
		},
		{
			name:  "CAP_NET_ADMIN absent",
			input: "CapEff:\t0000000000000000\n",
			want:  false,
		},
		{
			name:  "docker default root capabilities",
			input: "CapPrm:\t00000000a80425fb\nCapEff:\t00000000a80425fb\n",
			want:  false,
		},
		{
			name:  "docker root with --cap-add NET_ADMIN",
			input: "CapPrm:\t00000000a80435fb\nCapEff:\t00000000a80435fb\n",
			want:  true,
		},
		{
			name:    "missing CapEff",
			input:   "Name:\tagent\n",
			wantErr: true,
		},
		{
			name:    "invalid hex",
			input:   "CapEff:\tINVALID\n",
			wantErr: true,
		},
		{
			name:    "malformed CapEff",
			input:   "CapEff:\n",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			got, err := parseEffectiveNetAdmin([]byte(tt.input))

			if (err != nil) != tt.wantErr {
				t.Fatalf("unexpected error: %v", err)
			}

			if got != tt.want {
				t.Errorf("expected %v, got %v", tt.want, got)
			}
		})
	}
}

func TestCapabilitiesEndpoint(t *testing.T) {

	handler := NewHTTPHandler()

	request := newTestRequest(http.MethodGet, "/capabilities")

	recorder := httptest.NewRecorder()

	handler.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", recorder.Code)
	}

	var response CapabilitiesResponse

	if err := json.Unmarshal(
		recorder.Body.Bytes(),
		&response,
	); err != nil {
		t.Fatal(err)
	}

	if response.OS != runtime.GOOS {
		t.Errorf("unexpected OS: %s", response.OS)
	}

	if response.NetworkReady {
		t.Error("network_ready must be false")
	}

	if len(response.Checks) != 5 {
		t.Errorf("expected 5 checks, got %d", len(response.Checks))
	}
}
