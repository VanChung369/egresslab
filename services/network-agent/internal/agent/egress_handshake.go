package agent

import (
	"errors"
	"fmt"
	"time"
)

var ErrVPNHandshakeNotRecent = errors.New(
	"WireGuard tunnel has no recent valid handshake",
)

// WireGuard rejects session keys older than REJECT_AFTER_TIME (180 s); REKEY_AFTER_TIME (120 s)
// is when it starts a new handshake, so a healthy busy tunnel routinely shows ~120 s plus the
// round trip. A latest handshake older than the limit below means no session is usable right now.
const maxVPNLabHandshakeAge = 180*time.Second + 5*time.Second

const maxVPNLabFutureSkew = 5 * time.Second

// ValidateVPNLabHandshake reports whether the tunnel has a usable session at now. Each failure
// wraps ErrVPNHandshakeNotRecent with its reason, so clock skew is not mistaken for a dead tunnel.
func ValidateVPNLabHandshake(
	now, latest time.Time,
) error {
	switch {
	case latest.IsZero():
		return fmt.Errorf("%w: no handshake has completed", ErrVPNHandshakeNotRecent)

	case latest.After(now.Add(maxVPNLabFutureSkew)):
		return fmt.Errorf("%w: handshake is %s in the future (clock skew?)",
			ErrVPNHandshakeNotRecent, latest.Sub(now).Round(time.Second))

	case now.Sub(latest) > maxVPNLabHandshakeAge:
		return fmt.Errorf("%w: last handshake %s ago (limit %s)",
			ErrVPNHandshakeNotRecent, now.Sub(latest).Round(time.Second), maxVPNLabHandshakeAge)
	}

	return nil
}
