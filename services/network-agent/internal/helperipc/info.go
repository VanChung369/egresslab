package helperipc

import (
	"crypto/sha256"
	"encoding/hex"

	"github.com/VanChung369/egresslab/services/network-agent/internal/helperauth"
)

// OpHelperInfo reads the helper's current epoch and public-key fingerprint. It is read-only.
const OpHelperInfo = "HelperInfo"

// HelperInfo is public metadata only: no private key, WireGuard config or vault content.
//
// AuthorizationConfigured means a public key is loaded. It does not mean every capability will be
// accepted (an observed clock rollback, for example, disables authorization). The fingerprint is
// not authenticated to the client; the controller must compare it with the key it pinned.
type HelperInfo struct {
	AuthorizationConfigured bool   `json:"authorization_configured"`
	HelperID                string `json:"helper_id,omitempty"`
	PublicKeySHA256         string `json:"public_key_sha256,omitempty"`
}

func (i *HelperInfo) valid() bool {
	if i == nil {
		return false
	}

	if !i.AuthorizationConfigured {
		return i.HelperID == "" && i.PublicKeySHA256 == ""
	}

	digest, err := hex.DecodeString(i.PublicKeySHA256)

	return helperauth.ValidHelperID(i.HelperID) &&
		err == nil &&
		len(digest) == sha256.Size &&
		hex.EncodeToString(digest) == i.PublicKeySHA256
}
