package agent

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"net/http"
	"strings"
)

const agentTokenBytes = 32

func NewAuthenticatedHTTPHandler(token string) (http.Handler, error) {
	if err := validateAgentToken(token); err != nil {
		return nil, err
	}

	return requireBearerToken(
		NewHTTPHandler(),
		token,
	), nil
}

func validateAgentToken(token string) error {
	data, err := hex.DecodeString(token)

	if err != nil || len(data) != agentTokenBytes {
		return errors.New(
			"EGRESSLAB_AGENT_TOKEN must contain " +
				"64 hex characters (32 bytes)",
		)
	}

	return nil
}

func requireBearerToken(
	next http.Handler,
	secret string,
) http.Handler {

	expected := sha256.Sum256([]byte(secret))

	return http.HandlerFunc(func(
		w http.ResponseWriter,
		r *http.Request,
	) {

		w.Header().Set("Cache-Control", "no-store")

		values := r.Header.Values("Authorization")

		supplied := ""

		if len(values) == 1 {
			scheme, credential, found := strings.Cut(
				values[0],
				" ",
			)

			if found &&
				strings.EqualFold(scheme, "Bearer") &&
				credential != "" &&
				!strings.ContainsAny(
					credential,
					" \t\r\n",
				) {

				supplied = credential
			}
		}

		// Compare fixed-size SHA-256 digests.
		actual := sha256.Sum256([]byte(supplied))

		if subtle.ConstantTimeCompare(
			actual[:],
			expected[:],
		) != 1 {

			w.Header().Set(
				"WWW-Authenticate",
				`Bearer realm="egresslab-agent"`,
			)

			writeError(
				w,
				http.StatusUnauthorized,
				"UNAUTHORIZED",
				"Valid agent token required",
			)

			return
		}

		next.ServeHTTP(w, r)
	})

}
