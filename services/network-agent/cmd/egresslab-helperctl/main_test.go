package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"github.com/VanChung369/egresslab/services/network-agent/internal/helperipc"
)

const validCapability = `{"claims":{"version":1,"intent":{"operation":"CreateLab","profile_id":"profile_0123456789abcdef","namespace":""},` +
	`"helper_id":"helper_0123456789abcdef0123456789abcdef","nonce":"00112233445566778899aabbccddeeff",` +
	`"issued_at":1795500000,"not_after":1795500030},"signature":"x"}`

func TestReadCapability(t *testing.T) {
	capability, err := readCapability(strings.NewReader(validCapability + "\n"))
	if err != nil || capability.Claims.Intent.ProfileID != "profile_0123456789abcdef" {
		t.Fatalf("valid capability: %+v %v", capability, err)
	}

	for name, input := range map[string]string{
		"empty":         "",
		"oversized":     strings.Repeat(" ", maxCapabilityBytes) + validCapability,
		"unknown field": strings.Replace(validCapability, `"signature"`, `"admin":true,"signature"`, 1),
		"nested field":  strings.Replace(validCapability, `"nonce"`, `"scope":"all","nonce"`, 1),
		"trailing data": validCapability + validCapability,
		"not JSON":      "capability",
	} {
		if _, err := readCapability(strings.NewReader(input)); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}

func TestRunRejectsBadArguments(t *testing.T) {
	for _, args := range [][]string{
		nil,
		{"ping", "extra"},
		{"create-lab"},
		{"create-lab", "profile_0123"},
		{"verify-lab", "profile_0123456789abcdef"},
		{"delete-lab", "profile_0123456789abcdef", "../default"},
		{"connect-tunnel", "profile_0123456789abcdef"},
		{"connect-tunnel", "profile_0123456789abcdef", "egresslab-lab-0123456789abcdef"},
		{"connect-tunnel", "profile_0123456789abcdef", "egresslab-lab-0123456789abcdef", "wgstage_x"},
		{"connect-tunnel", "profile_0123456789abcdef", "../default", "wgstage_0123456789abcdef0123456789abcdef"},
		{"connect-tunnel", "profile_0123456789abcdef", "egresslab-lab-0123456789abcdef",
			"wgstage_0123456789abcdef0123456789abcdef", "extra"},
		{"disconnect", "profile_0123456789abcdef"},
		{"disconnect", "profile_0123456789abcdef", "egresslab-lab-x"},
		{"disconnect", "profile_0123456789abcdef", "egresslab-lab-0123456789abcdef", "extra"},
		{"stage-info"},
		{"stage-info", "profile_x"},
		{"stage-info", "profile_0123456789abcdef", "extra"},
		{"probe-egress", "profile_0123456789abcdef"},
		{"probe-egress", "profile_0123456789abcdef", "egresslab-lab-x"},
		{"probe-egress", "profile_0123456789abcdef", "egresslab-lab-0123456789abcdef", "1.1.1.1"},
		{"probe-egress", "profile_0123456789abcdef", "egresslab-lab-0123456789abcdef", "https://example.com"},
	} {
		var out bytes.Buffer
		if err := run(args, strings.NewReader(validCapability), &out); err == nil || !strings.Contains(err.Error(), "usage") {
			t.Errorf("%q: %v", args, err)
		}

		if out.Len() != 0 {
			t.Errorf("%q printed output", args)
		}
	}

	// The capability is checked before any socket is touched.
	if err := run([]string{"create-lab", "profile_0123456789abcdef"}, strings.NewReader("{}{}"), &bytes.Buffer{}); err == nil ||
		err.Error() != "trailing capability data" {
		t.Fatalf("bad capability: %v", err)
	}

	connect := []string{"connect-tunnel", "profile_0123456789abcdef", "egresslab-lab-0123456789abcdef",
		"wgstage_0123456789abcdef0123456789abcdef"}
	if err := run(connect, strings.NewReader("{}{}"), &bytes.Buffer{}); err == nil || err.Error() != "trailing capability data" {
		t.Fatalf("bad tunnel capability: %v", err)
	}

	probe := []string{"probe-egress", "profile_0123456789abcdef", "egresslab-lab-0123456789abcdef"}
	err := run(probe, strings.NewReader("{}{}"), &bytes.Buffer{})
	if err == nil || err.Error() != "trailing capability data" {
		t.Fatalf("bad probe capability: %v", err)
	}
}

func TestFailureOutputCarriesCode(t *testing.T) {
	for _, tt := range []struct {
		err  error
		code string
	}{
		{&helperipc.Error{Code: helperipc.CodeLabBusy, Message: "busy"}, helperipc.CodeLabBusy},
		{usageError(), helperipc.CodeInvalidRequest},
		{errors.New("helper returned an invalid response"), helperipc.CodeInternal},
	} {
		var out bytes.Buffer
		writeFailure(&out, tt.err)

		var resp helperipc.Response
		if err := json.Unmarshal(out.Bytes(), &resp); err != nil || resp.OK || resp.Code != tt.code ||
			resp.Error != tt.err.Error() || resp.Version != helperipc.Version {
			t.Errorf("%v: %s", tt.err, out.String())
		}
	}

	if _, err := readCapability(strings.NewReader("")); helperipc.ErrorCode(err) != helperipc.CodeInvalidRequest {
		t.Errorf("capability error code: %v", err)
	}
}

func TestMultiProbeCommandArguments(t *testing.T) {
	profile := "profile_0123456789abcdef"
	namespace := "egresslab-lab-0123456789abcdef"

	for _, args := range [][]string{
		{"multi-probe-policy", "extra"},
		{"probe-egress-multi"},
		{"probe-egress-multi", profile},
		{"probe-egress-multi", "invalid-profile", namespace},
		{"probe-egress-multi", profile, "../default"},
		{"probe-egress-multi", profile, namespace, "9.9.9.9"},
		{"probe-egress-multi", profile, namespace, "https://example.com/"},
		{"probe-egress-multi", profile, namespace, "--insecure"},
		{"multi-probe-target"},
		{"multi-probe-target", profile},
		{"multi-probe-target", profile, "../default"},
		{"multi-probe-target", profile, namespace, "extra"},
		{"multi-probe-target", "invalid-profile", namespace},
	} {
		var out bytes.Buffer

		err := run(args, strings.NewReader(validCapability), &out)
		if err == nil || !strings.Contains(err.Error(), "usage") || out.Len() != 0 {
			t.Fatalf("invalid arguments accepted: %v %v", args, err)
		}
	}
}

// Every input is refused before the helper is contacted, including a well-formed capability for
// another operation.
func TestMultiProbeRequiresCapability(t *testing.T) {
	args := []string{"probe-egress-multi", "profile_0123456789abcdef", "egresslab-lab-0123456789abcdef"}

	for _, input := range []string{"", "not JSON", "{}{}", validCapability} {
		var out bytes.Buffer

		err := run(args, strings.NewReader(input), &out)
		if helperipc.ErrorCode(err) != helperipc.CodeInvalidRequest || out.Len() != 0 {
			t.Fatalf("invalid capability %q accepted: %v", input, err)
		}
	}
}

func TestCandidateCommandArguments(t *testing.T) {
	profile := "profile_0123456789abcdef"
	namespace := "egresslab-lab-0123456789abcdef"

	for _, args := range [][]string{
		{"reserve-egress-candidate"},
		{"reserve-egress-candidate", profile},
		{"reserve-egress-candidate", profile, "../default"},
		{"reserve-egress-candidate", "invalid", namespace},
		{"reserve-egress-candidate", profile, namespace, "8.8.4.4"},
		{"reserve-egress-candidate", profile, namespace, "--force"},
	} {
		var out bytes.Buffer

		err := run(args, strings.NewReader(validCapability), &out)
		if err == nil || !strings.Contains(err.Error(), "usage") || out.Len() != 0 {
			t.Fatalf("invalid candidate arguments accepted: %v %v", args, err)
		}
	}
}

// Refused before the helper is contacted, including a capability for another operation.
func TestCandidateCommandRequiresCapability(t *testing.T) {
	args := []string{"reserve-egress-candidate", "profile_0123456789abcdef", "egresslab-lab-0123456789abcdef"}
	v2 := `{"claims":{"version":1,"intent":{"operation":"PermitMultiProbeV2","profile_id":"profile_0123456789abcdef",` +
		`"namespace":"egresslab-lab-0123456789abcdef","probe_ipv4":"9.9.9.9",` +
		`"tunnel_generation":"tunnelgen_0123456789abcdef0123456789abcdef"},` +
		`"helper_id":"helper_0123456789abcdef0123456789abcdef","nonce":"00112233445566778899aabbccddeeff",` +
		`"issued_at":1795500000,"not_after":1795500030},"signature":"x"}`
	foreignProfile := `{"claims":{"version":1,"intent":{"operation":"ReserveEgressCandidateV1",` +
		`"profile_id":"profile_ffffffffffffffff","namespace":"egresslab-lab-0123456789abcdef","probe_ipv4":"9.9.9.9",` +
		`"tunnel_generation":"tunnelgen_0123456789abcdef0123456789abcdef",` +
		`"evidence_nonce":"ffeeddccbbaa99887766554433221100"},` +
		`"helper_id":"helper_0123456789abcdef0123456789abcdef","nonce":"00112233445566778899aabbccddeeff",` +
		`"issued_at":1795500000,"not_after":1795500030},"signature":"x"}`

	for _, input := range []string{
		"",
		"not JSON",
		"{}{}",
		validCapability,
		`{"claims":{"intent":{"operation":"PermitMultiProbeV2"}}}`,
		v2,
		foreignProfile,
	} {
		var out bytes.Buffer

		err := run(args, strings.NewReader(input), &out)
		if helperipc.ErrorCode(err) != helperipc.CodeInvalidRequest || out.Len() != 0 {
			t.Fatalf("invalid candidate capability %q accepted: %v", input, err)
		}
	}
}

// A capability that matches the arguments passes every local check and reaches the socket, which
// here does not exist: the command is wired, and nothing local refused it.
func TestCandidateCommandReachesHelper(t *testing.T) {
	previous := socketPath
	socketPath = filepath.Join(t.TempDir(), "missing.sock")
	t.Cleanup(func() { socketPath = previous })

	capability := `{"claims":{"version":1,"intent":{"operation":"ReserveEgressCandidateV1",` +
		`"profile_id":"profile_0123456789abcdef","namespace":"egresslab-lab-0123456789abcdef","probe_ipv4":"9.9.9.9",` +
		`"tunnel_generation":"tunnelgen_0123456789abcdef0123456789abcdef",` +
		`"evidence_nonce":"ffeeddccbbaa99887766554433221100"},` +
		`"helper_id":"helper_0123456789abcdef0123456789abcdef","nonce":"00112233445566778899aabbccddeeff",` +
		`"issued_at":1795500000,"not_after":1795500030},"signature":"x"}`

	var out bytes.Buffer

	err := run([]string{"reserve-egress-candidate", "profile_0123456789abcdef", "egresslab-lab-0123456789abcdef"},
		strings.NewReader(capability), &out)
	if helperipc.ErrorCode(err) != helperipc.CodeRuntimeUnavailable || out.Len() != 0 {
		t.Fatalf("candidate command did not reach the helper socket: %v", err)
	}
}

func TestMultiProbeV1CapabilityRefused(t *testing.T) {
	v1 := `{"claims":{"version":1,"intent":{"operation":"PermitMultiProbeV1","profile_id":"profile_0123456789abcdef",` +
		`"namespace":"egresslab-lab-0123456789abcdef","probe_ipv4":"9.9.9.9"},` +
		`"helper_id":"helper_0123456789abcdef0123456789abcdef","nonce":"00112233445566778899aabbccddeeff",` +
		`"issued_at":1795500000,"not_after":1795500030},"signature":"x"}`
	v1WithGeneration := strings.Replace(v1, `"probe_ipv4":"9.9.9.9"`,
		`"probe_ipv4":"9.9.9.9","tunnel_generation":"tunnelgen_0123456789abcdef0123456789abcdef"`, 1)
	args := []string{"probe-egress-multi", "profile_0123456789abcdef", "egresslab-lab-0123456789abcdef"}

	for _, input := range []string{v1, v1WithGeneration} {
		var out bytes.Buffer

		if err := run(args, strings.NewReader(input), &out); helperipc.ErrorCode(err) != helperipc.CodeInvalidRequest ||
			!strings.Contains(err.Error(), "generation-bound") || out.Len() != 0 {
			t.Fatalf("V1 capability reached IPC: %v", err)
		}
	}
}
