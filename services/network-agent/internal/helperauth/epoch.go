package helperauth

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log"
	"sync"
	"time"
)

// ErrAuthorizationClockUnsafe wraps ErrInvalidCapability. The verifier returns it while the wall
// clock reads earlier than the latest second it has seen, and accepts capabilities again once the
// clock has caught up.
var ErrAuthorizationClockUnsafe = fmt.Errorf(
	"%w: helper clock behind the latest time seen",
	ErrInvalidCapability,
)

var (
	verifierLogs   = make(chan string, 8)
	verifierLogger sync.Once
)

// logDetached never blocks the verifier, which logs under its lock: a stalled sink drops lines.
func logDetached(format string, args ...any) {
	verifierLogger.Do(func() {
		go func() {
			for line := range verifierLogs {
				log.Print(line)
			}
		}()
	})

	select {
	case verifierLogs <- fmt.Sprintf(format, args...):
	default:
	}
}

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
// While the wall clock reads earlier than the latest second recorded here, every capability is
// refused, and the latest second is never lowered. Nonces are pruned only at times recorded here,
// so a pruned nonce has its not_after at or before the latest second: it could only look valid
// again at an earlier time, which is refused. Once the clock catches up, authorization resumes.
// Until 2026-11-27 a rollback disabled authorization until the helper restarted.
func (v *Verifier) checkedTimeLocked() (time.Time, error) {
	now := v.now()
	seconds := now.Unix()

	if seconds <= 0 || (v.lastWall != 0 && seconds < v.lastWall) {
		if !v.clockBehind {
			v.clockBehind = true
			v.logf("Authorization paused: the wall clock went back %ds behind the latest time seen; "+
				"capabilities are refused until it catches up", v.lastWall-seconds)
		}

		return time.Time{}, ErrAuthorizationClockUnsafe
	}

	if v.clockBehind {
		v.clockBehind = false
		v.logf("Authorization resumed: the wall clock caught up")
	}

	v.lastWall = seconds

	return now, nil
}
