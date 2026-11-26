package control

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
)

// ErrInvalidState means persisted state broke an invariant; the controller must refuse to start
// rather than act on it.
var ErrInvalidState = errors.New("invalid persisted state")

var (
	profileIDPattern  = regexp.MustCompile(`^profile_[0-9a-f]{16}$`)
	endpointIDPattern = regexp.MustCompile(`^proxy_[0-9a-f]{16}$`)
)

// validateSnapshot re-checks every invariant the Store enforces on writes, so a hand-edited or
// corrupted state file can never introduce a resource the API itself would have rejected.
func validateSnapshot(state snapshot) error {
	ids := map[string]bool{}
	profileNames := map[string]bool{}
	profiles := map[string]bool{}

	for i, p := range state.Profiles {
		where := fmt.Sprintf("profiles[%d]", i)

		if !profileIDPattern.MatchString(p.ID) {
			return invalidState(where, "malformed id")
		}

		if ids[p.ID] {
			return invalidState(where, "duplicate id")
		}
		ids[p.ID] = true
		profiles[p.ID] = true

		if err := validateStoredName(p.Name); err != nil {
			return invalidState(where, err.Error())
		}

		folded := strings.ToLower(p.Name)
		if profileNames[folded] {
			return invalidState(where, "duplicate name")
		}
		profileNames[folded] = true

		if p.Status != "unconfigured" {
			return invalidState(where, "unsupported status")
		}

		// Nothing can attach a tunnel in state version 1.
		if p.TunnelID != "" {
			return invalidState(where, "tunnel_id is not supported in state version 1")
		}

		if !p.UniqueIPRequired || !p.KillSwitchRequired {
			return invalidState(where, "unique IP and kill-switch policies must stay enabled")
		}

		if p.CreatedAt.IsZero() {
			return invalidState(where, "missing created_at")
		}
	}

	endpointNames := map[string]bool{}
	ports := map[int]bool{}

	for i, e := range state.Endpoints {
		where := fmt.Sprintf("endpoints[%d]", i)

		if !endpointIDPattern.MatchString(e.ID) {
			return invalidState(where, "malformed id")
		}

		if ids[e.ID] {
			return invalidState(where, "duplicate id")
		}
		ids[e.ID] = true

		if err := validateStoredName(e.Name); err != nil {
			return invalidState(where, err.Error())
		}

		folded := strings.ToLower(e.Name)
		if endpointNames[folded] {
			return invalidState(where, "duplicate name")
		}
		endpointNames[folded] = true

		if e.Protocol != "socks5" && e.Protocol != "http-connect" {
			return invalidState(where, "unsupported protocol")
		}

		if e.ListenHost != "127.0.0.1" {
			return invalidState(where, "listen_host must be 127.0.0.1")
		}

		if e.Port < 1024 || e.Port > 65535 {
			return invalidState(where, "port must be 1024-65535")
		}

		if ports[e.Port] {
			return invalidState(where, "duplicate port")
		}
		ports[e.Port] = true

		if !profiles[e.ProfileID] {
			return invalidState(where, "profile_id does not reference a stored profile")
		}

		if e.Status != "draft" {
			return invalidState(where, "unsupported status")
		}

		if e.CreatedAt.IsZero() {
			return invalidState(where, "missing created_at")
		}
	}

	return nil
}

// validateStoredName accepts only names exactly as validateName would have stored them.
func validateStoredName(name string) error {
	trimmed, err := validateName(name)
	if err != nil {
		return errors.New("name must be 2-64 characters")
	}

	if trimmed != name {
		return errors.New("name has surrounding whitespace")
	}

	return nil
}

func invalidState(where, reason string) error {
	return fmt.Errorf("%w: %s: %s", ErrInvalidState, where, reason)
}

func ValidEndpointID(id string) bool {
	return endpointIDPattern.MatchString(id)
}
