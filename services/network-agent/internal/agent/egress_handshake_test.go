package agent

import (
	"errors"
	"strings"
	"testing"
	"time"
)

func TestValidateVPNLabHandshake(t *testing.T) {
	now := time.Date(
		2026, 11, 23,
		12, 0, 0, 0,
		time.UTC,
	)

	tests := []struct {
		name      string
		handshake time.Time
		wantError bool
	}{
		{
			name:      "missing",
			handshake: time.Time{},
			wantError: true,
		},
		{
			name:      "fresh",
			handshake: now.Add(-30 * time.Second),
			wantError: false,
		},
		{
			name:      "exact expiry",
			handshake: now.Add(-maxVPNLabHandshakeAge),
			wantError: false,
		},
		{
			name: "stale",
			handshake: now.Add(
				-maxVPNLabHandshakeAge - time.Second,
			),
			wantError: true,
		},
		{
			name:      "minor clock skew",
			handshake: now.Add(3 * time.Second),
			wantError: false,
		},
		{
			name: "future",
			handshake: now.Add(
				maxVPNLabFutureSkew + time.Second,
			),
			wantError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateVPNLabHandshake(
				now,
				tt.handshake,
			)

			if tt.wantError &&
				!errors.Is(
					err,
					ErrVPNHandshakeNotRecent,
				) {

				t.Fatalf(
					"expected invalid handshake, got %v",
					err,
				)
			}

			if !tt.wantError && err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestValidateVPNLabHandshakeExplainsWhy(t *testing.T) {
	now := time.Date(2026, 11, 23, 12, 0, 0, 0, time.UTC)

	cases := map[string]struct {
		latest time.Time
		reason string
	}{
		"missing": {time.Time{}, "no handshake has completed"},
		"future":  {now.Add(10 * time.Second), "in the future"},
		"stale":   {now.Add(-10 * time.Minute), "last handshake 10m0s ago"},
	}

	for name, c := range cases {
		err := ValidateVPNLabHandshake(now, c.latest)
		if !errors.Is(err, ErrVPNHandshakeNotRecent) || !strings.Contains(err.Error(), c.reason) {
			t.Errorf("%s: got %v, want reason %q", name, err, c.reason)
		}
	}

	// A busy healthy tunnel sits around REKEY_AFTER_TIME (120 s) plus the handshake round trip.
	if err := ValidateVPNLabHandshake(now, now.Add(-125*time.Second)); err != nil {
		t.Fatalf("handshake just past the rekey interval rejected: %v", err)
	}
}
