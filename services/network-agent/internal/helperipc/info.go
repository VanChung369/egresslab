package helperipc

import (
	"crypto/sha256"
	"encoding/hex"
	"regexp"

	"github.com/VanChung369/egresslab/services/network-agent/internal/helperauth"
)

// OpHelperInfo reads the helper's current epoch, public-key fingerprint and runtime ID.
const OpHelperInfo = "HelperInfo"

var runtimeIDPattern = regexp.MustCompile(`^runtime_[0-9a-f]{32}$`)

func ValidRuntimeID(id string) bool { return runtimeIDPattern.MatchString(id) }

// HelperInfo is public metadata only: no private key, WireGuard config or vault content.
//
// AuthorizationConfigured means a public key is loaded. It does not mean every capability will be
// accepted (an observed clock rollback, for example, disables authorization). RuntimeID names the
// Linux installation, not the process; images cloned from one installation share it. None of this
// is authenticated to the client: the controller compares it with what it pinned.
type HelperInfo struct {
	AuthorizationConfigured bool   `json:"authorization_configured"`
	HelperID                string `json:"helper_id,omitempty"`
	PublicKeySHA256         string `json:"public_key_sha256,omitempty"`
	RuntimeID               string `json:"runtime_id,omitempty"`
}

func (i *HelperInfo) valid() bool {
	if i == nil || (i.RuntimeID != "" && !ValidRuntimeID(i.RuntimeID)) {
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
