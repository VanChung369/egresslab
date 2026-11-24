package main

import (
	"bytes"
	"encoding/json"
	"errors"
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
		{"stage-info"},
		{"stage-info", "profile_x"},
		{"stage-info", "profile_0123456789abcdef", "extra"},
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
