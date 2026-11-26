package control

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"regexp"
	"time"
)

// Must match the network agent's helperauth wire format (pinned there by golden tests).
const labCapabilityDomain = "egresslab/helper-capability/v1\x00"

var (
	labHelperIDPattern    = regexp.MustCompile(`^helper_[0-9a-f]{32}$`)
	labNamespacePattern   = regexp.MustCompile(`^egresslab-lab-[0-9a-f]{16}$`)
	labFingerprintPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)
	labRuntimeIDPattern   = regexp.MustCompile(`^runtime_[0-9a-f]{32}$`)
)

const (
	LabSealed           = "sealed"
	LabFaulted          = "faulted"
	LabDeleted          = "deleted"
	LabTunnelConfigured = "tunnel_configured" // a configured WireGuard link; no handshake or egress checked
)

type LabHelperInfo struct {
	AuthorizationConfigured bool   `json:"authorization_configured"`
	HelperID                string `json:"helper_id,omitempty"`
	PublicKeySHA256         string `json:"public_key_sha256,omitempty"`
	RuntimeID               string `json:"runtime_id,omitempty"`
}

func (i LabHelperInfo) Valid() bool {
	if i.RuntimeID != "" && !ValidRuntimeID(i.RuntimeID) {
		return false
	}

	if !i.AuthorizationConfigured {
		return i.HelperID == "" && i.PublicKeySHA256 == ""
	}

	return labHelperIDPattern.MatchString(i.HelperID) && labFingerprintPattern.MatchString(i.PublicKeySHA256)
}

type LabInfo struct {
	ProfileID string `json:"profile_id"`
	Namespace string `json:"namespace"`
	State     string `json:"state"`
}

// Field order matters: it is the signed JSON. Namespace has no omitempty, so CreateLab signs
// "namespace":"".
type LabIntent struct {
	Operation string `json:"operation"`
	ProfileID string `json:"profile_id"`
	Namespace string `json:"namespace"`
	StageID   string `json:"stage_id,omitempty"`
	ProbeIPv4 string `json:"probe_ipv4,omitempty"`

	TunnelGeneration string `json:"tunnel_generation,omitempty"`
	EvidenceNonce    string `json:"evidence_nonce,omitempty"` // ReserveEgressCandidateV1, Prepare- and RevokeEgressLeaseV1

	// PrepareEgressLeaseV1 and RevokeEgressLeaseV1 only, in helperauth.Intent's order.
	ReservationNonce string `json:"reservation_nonce,omitempty"`
	RuntimeID        string `json:"runtime_id,omitempty"`
	AuthorityID      string `json:"authority_id,omitempty"`
	ReservationID    string `json:"reservation_id,omitempty"`
	EgressIPv4       string `json:"egress_ipv4,omitempty"`

	// RecoverRetiredGenerationV1 only, last as in helperauth.Intent.
	OriginalHelperID string `json:"original_helper_id,omitempty"`
}

type LabClaims struct {
	Version  int       `json:"version"`
	Intent   LabIntent `json:"intent"`
	HelperID string    `json:"helper_id"`
	Nonce    string    `json:"nonce"`
	IssuedAt int64     `json:"issued_at"`
	NotAfter int64     `json:"not_after"`
}

type LabCapability struct {
	Claims    LabClaims `json:"claims"`
	Signature string    `json:"signature"`
}

// LabSigner is implemented by the platform key stores; the private key never leaves them.
type LabSigner interface {
	PublicKey() (ed25519.PublicKey, error)
	Sign(message []byte) ([]byte, error)
}

func ValidProfileID(id string) bool { return profileIDPattern.MatchString(id) }

func ValidLabNamespace(name string) bool { return labNamespacePattern.MatchString(name) }

func ValidRuntimeID(id string) bool { return labRuntimeIDPattern.MatchString(id) }

// LabPublicKeySHA256 is the fingerprint the helper reports in HelperInfo.
func LabPublicKeySHA256(public ed25519.PublicKey) string {
	digest := sha256.Sum256(public)
	return hex.EncodeToString(digest[:])
}

func signLabClaims(signer LabSigner, claims LabClaims) (LabCapability, error) {
	raw, err := json.Marshal(claims)
	if err != nil {
		return LabCapability{}, err
	}

	signature, err := signer.Sign(append([]byte(labCapabilityDomain), raw...))
	if err != nil {
		return LabCapability{}, err
	}

	if len(signature) != ed25519.SignatureSize {
		return LabCapability{}, errors.New("signer returned an invalid signature")
	}

	return LabCapability{Claims: claims, Signature: base64.RawURLEncoding.EncodeToString(signature)}, nil
}

// MintCreateLab signs a CreateLab capability. It signs nothing unless the profile keeps its
// policies and the helper reports this signer's public key.
func MintCreateLab(signer LabSigner, profile RoutingProfile, info LabHelperInfo, now time.Time) (LabCapability, error) {
	if !ValidProfileID(profile.ID) ||
		!profile.UniqueIPRequired ||
		!profile.KillSwitchRequired ||
		profile.Status != "unconfigured" ||
		profile.TunnelID != "" {
		return LabCapability{}, errors.New("profile does not satisfy sealed lab policy")
	}

	return mintLabCapability(signer, LabIntent{Operation: "CreateLab", ProfileID: profile.ID}, info, now)
}

// mintLabCapability holds the checks every capability shares: helper identity, key fingerprint,
// clock, a fresh nonce and the 30 s lifetime.
func mintLabCapability(signer LabSigner, intent LabIntent, info LabHelperInfo, now time.Time) (LabCapability, error) {
	if !info.AuthorizationConfigured || !info.Valid() {
		return LabCapability{}, errors.New("helper authorization is unavailable")
	}

	public, err := signer.PublicKey()
	if err != nil {
		return LabCapability{}, err
	}

	if len(public) != ed25519.PublicKeySize || LabPublicKeySHA256(public) != info.PublicKeySHA256 {
		return LabCapability{}, errors.New("helper public key fingerprint mismatch")
	}

	if now.Unix() <= 0 {
		return LabCapability{}, errors.New("invalid controller clock")
	}

	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return LabCapability{}, err
	}

	return signLabClaims(signer, LabClaims{
		Version:  1,
		Intent:   intent,
		HelperID: info.HelperID,
		Nonce:    hex.EncodeToString(nonce[:]),
		IssuedAt: now.Unix(),
		NotAfter: now.Unix() + 30,
	})
}
