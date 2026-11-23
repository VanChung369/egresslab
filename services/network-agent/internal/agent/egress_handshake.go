package agent

import (
	"errors"
	"time"
)

var ErrVPNHandshakeNotRecent = errors.New(
	"WireGuard tunnel has no recent valid handshake",
)

const maxVPNLabHandshakeAge = 2 * time.Minute
const maxVPNLabFutureSkew = 5 * time.Second

func ValidateVPNLabHandshake(
	now, latest time.Time,
) error {
	if latest.IsZero() ||
		latest.After(now.Add(maxVPNLabFutureSkew)) ||
		now.Sub(latest) > maxVPNLabHandshakeAge {

		return ErrVPNHandshakeNotRecent
	}

	return nil
}
