package agent

import (
	"errors"
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
