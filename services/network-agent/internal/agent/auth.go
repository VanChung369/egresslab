package agent

import (
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"net/http"
	"strings"
)

const agentTokenBytes = 32

func NewAuthenticatedHTTPHandler(token string) (http.Handler, error) {
	key, err := parseAgentToken(token)
	if err != nil {
		return nil, err
	}

	return requireBearerToken(NewHTTPHandler(), key), nil
}

func parseAgentToken(token string) ([]byte, error) {
	key, err := hex.DecodeString(token)
	if err != nil || len(key) != agentTokenBytes {
		return nil, errors.New("EGRESSLAB_AGENT_TOKEN must contain 64 hex characters (32 bytes)")
	}

	return key, nil
}

func requireBearerToken(next http.Handler, key []byte) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")

		if !hasBearerToken(r.Header.Values("Authorization"), key) {
			w.Header().Set("WWW-Authenticate", `Bearer realm="egresslab-agent"`)
			writeError(w, http.StatusUnauthorized, "UNAUTHORIZED", "Valid agent token required")
			return
		}

		next.ServeHTTP(w, r)
	})
}

func hasBearerToken(values []string, key []byte) bool {
	if len(values) != 1 {
		return false
	}

	scheme, credential, found := strings.Cut(values[0], " ")
	if !found || !strings.EqualFold(scheme, "Bearer") {
		return false
	}

	supplied, err := parseAgentToken(credential)
	if err != nil {
		return false
	}

	return subtle.ConstantTimeCompare(supplied, key) == 1
}
