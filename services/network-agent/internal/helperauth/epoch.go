package helperauth

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"time"
)

// ErrAuthorizationClockUnsafe wraps ErrInvalidCapability. Once returned, the verifier refuses every
// capability until the helper restarts with a fresh epoch.
var ErrAuthorizationClockUnsafe = fmt.Errorf(
	"%w: helper clock unsafe; restart required",
	ErrInvalidCapability,
)

// NewHelperID creates a fresh random 128-bit helper epoch. A helper generates one at every start
// and never reuses an identity from a previous process, so capabilities minted for an earlier
// process are refused even if they have not expired.
func NewHelperID() (string, error) {
	var random [16]byte

	if _, err := rand.Read(random[:]); err != nil {
		return "", fmt.Errorf("generate helper epoch: %w", err)
	}

	return "helper_" + hex.EncodeToString(random[:]), nil
}

func ValidHelperID(id string) bool {
	return helperPattern.MatchString(id)
}

// Identity returns public metadata only: the helper ID and the lowercase hex SHA-256 of the raw
// 32-byte Ed25519 public key. The key itself is not returned. A nil verifier returns two empty
// strings.
func (v *Verifier) Identity() (helperID, publicKeySHA256 string) {
	if v == nil {
		return "", ""
	}

	digest := sha256.Sum256(v.key)

	return v.helperID, hex.EncodeToString(digest[:])
}

// checkedTimeLocked reads the wall clock. It must be called with v.mu held.
//
// If the wall clock reads earlier than at a previous call, to the second, authorization stays
// disabled for this verifier. Nonces are pruned only at times recorded here, so a pruned nonce can
// never become valid again: its not_after is at or before the last recorded time.
func (v *Verifier) checkedTimeLocked() (time.Time, error) {
	if v.clockFailed {
		return time.Time{}, ErrAuthorizationClockUnsafe
	}

	now := v.now()
	seconds := now.Unix()

	if seconds <= 0 || (v.lastWall != 0 && seconds < v.lastWall) {
		v.clockFailed = true

		return time.Time{}, ErrAuthorizationClockUnsafe
	}

	v.lastWall = seconds

	return now, nil
}
