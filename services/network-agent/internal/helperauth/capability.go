// Package helperauth implements signed, single-use capabilities for privileged helper operations.
//
// The controller signs Claims with an Ed25519 private key. The helper holds only the public key and
// accepts a capability once, for exactly the intent it names and its own helper ID, before it
// expires (at most 30 s). The helper ID is a random epoch that changes at every helper start.
// Nothing in this package runs network commands.
package helperauth

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"sync"
	"time"
)

const (
	Version         = 1
	MaxTTL          = 30 * time.Second
	OpConnectTunnel = "ConnectTunnel"
	OpPermitProbe   = "PermitProbe"

	// The helper picks the namespace, so a CreateLab intent signs "namespace":"".
	OpCreateLab = "CreateLab"

	maxLiveNonces = 4096
)

// domain separates EgressLab capability signatures from any other use of the same key. The
// signed message is domain followed by json.Marshal(Claims).
const domain = "egresslab/helper-capability/v1\x00"

var (
	ErrInvalidCapability = errors.New("invalid or expired helper capability")
	ErrCapabilityReplay  = errors.New("helper capability already used")

	profilePattern = regexp.MustCompile(`^profile_[0-9a-f]{16}$`)
	labPattern     = regexp.MustCompile(`^egresslab-lab-[0-9a-f]{16}$`)
	stagePattern   = regexp.MustCompile(`^wgstage_[0-9a-f]{32}$`)
	helperPattern  = regexp.MustCompile(`^helper_[0-9a-f]{32}$`)
	noncePattern   = regexp.MustCompile(`^[0-9a-f]{32}$`)
)

// Intent describes exactly what is authorized. The helper compares it with the intent supplied
// independently in the request.
type Intent struct {
	Operation string `json:"operation"`
	ProfileID string `json:"profile_id"`
	Namespace string `json:"namespace"`
	StageID   string `json:"stage_id,omitempty"`
	ProbeIPv4 string `json:"probe_ipv4,omitempty"`
}

type Claims struct {
	Version  int    `json:"version"`
	Intent   Intent `json:"intent"`
	HelperID string `json:"helper_id"`
	Nonce    string `json:"nonce"`
	IssuedAt int64  `json:"issued_at"`
	NotAfter int64  `json:"not_after"`
}

type SignedCapability struct {
	Claims    Claims `json:"claims"`
	Signature string `json:"signature"` // base64url without padding, 64 bytes decoded
}

func ValidProfileID(id string) bool {
	return profilePattern.MatchString(id)
}

func ValidLabNamespace(name string) bool {
	return labPattern.MatchString(name)
}

func validateIntent(in Intent) error {
	if !ValidProfileID(in.ProfileID) {
		return ErrInvalidCapability
	}

	if in.Operation == OpCreateLab {
		if in.Namespace != "" || in.StageID != "" || in.ProbeIPv4 != "" {
			return ErrInvalidCapability
		}

		return nil
	}

	if !ValidLabNamespace(in.Namespace) {
		return ErrInvalidCapability
	}

	switch in.Operation {
	case OpConnectTunnel:
		if !stagePattern.MatchString(in.StageID) || in.ProbeIPv4 != "" {
			return ErrInvalidCapability
		}

	case OpPermitProbe:
		if in.StageID != "" {
			return ErrInvalidCapability
		}

		ip, err := netip.ParseAddr(in.ProbeIPv4)
		if err != nil || !ip.Is4() || !ip.IsGlobalUnicast() || ip.String() != in.ProbeIPv4 {
			return ErrInvalidCapability
		}

	default:
		return ErrInvalidCapability
	}

	return nil
}

func validateStructure(c Claims) error {
	if c.Version != Version ||
		!helperPattern.MatchString(c.HelperID) ||
		!noncePattern.MatchString(c.Nonce) ||
		c.IssuedAt <= 0 ||
		c.NotAfter <= c.IssuedAt ||
		c.NotAfter-c.IssuedAt > int64(MaxTTL/time.Second) {
		return ErrInvalidCapability
	}

	return validateIntent(c.Intent)
}

func validateTime(c Claims, now time.Time) error {
	if now.Unix() < c.IssuedAt || now.Unix() >= c.NotAfter {
		return ErrInvalidCapability
	}

	return nil
}

// NewClaims creates claims for intent with a random 128-bit nonce and the maximum TTL.
func NewClaims(intent Intent, helperID string, now time.Time) (Claims, error) {
	var random [16]byte
	if _, err := rand.Read(random[:]); err != nil {
		return Claims{}, err
	}

	c := Claims{
		Version:  Version,
		Intent:   intent,
		HelperID: helperID,
		Nonce:    hex.EncodeToString(random[:]),
		IssuedAt: now.Unix(),
		NotAfter: now.Unix() + int64(MaxTTL/time.Second),
	}

	if err := validateStructure(c); err != nil {
		return Claims{}, err
	}

	return c, nil
}

// Mint signs claims with the controller's Ed25519 private key. The key stays in the controller's
// protected storage; it never travels over helper IPC.
func Mint(private ed25519.PrivateKey, c Claims) (SignedCapability, error) {
	if len(private) != ed25519.PrivateKeySize {
		return SignedCapability{}, ErrInvalidCapability
	}

	if err := validateStructure(c); err != nil {
		return SignedCapability{}, err
	}

	msg, err := signingMessage(c)
	if err != nil {
		return SignedCapability{}, err
	}

	return SignedCapability{
		Claims:    c,
		Signature: base64.RawURLEncoding.EncodeToString(ed25519.Sign(private, msg)),
	}, nil
}

// signingMessage is domain + json.Marshal(c). The struct's field order makes it deterministic.
func signingMessage(c Claims) ([]byte, error) {
	raw, err := json.Marshal(c)
	if err != nil {
		return nil, fmt.Errorf("encode helper claims: %w", err)
	}

	msg := make([]byte, 0, len(domain)+len(raw))
	msg = append(msg, domain...)

	return append(msg, raw...), nil
}

// Verifier validates signed capabilities and tracks consumed nonces in memory until they expire.
//
// The replay cache does not survive a restart. Restart-safe replay protection therefore requires
// a fresh helper ID for every process (NewHelperID): capabilities minted for an earlier process
// name another helper and are refused.
//
// An observed wall-clock rollback disables authorization for this verifier.
//
// The verifier must not be copied after use.
type Verifier struct {
	mu       sync.Mutex
	key      ed25519.PublicKey
	helperID string
	used     map[string]int64 // nonce -> not_after
	now      func() time.Time

	lastWall    int64 // latest wall-clock second seen by checkedTimeLocked
	clockFailed bool
}

func NewVerifier(public ed25519.PublicKey, helperID string) (*Verifier, error) {
	if len(public) != ed25519.PublicKeySize || !helperPattern.MatchString(helperID) {
		return nil, ErrInvalidCapability
	}

	return &Verifier{
		key:      append(ed25519.PublicKey(nil), public...),
		helperID: helperID,
		used:     make(map[string]int64),
		now:      time.Now,
	}, nil
}

// VerifyAndConsume checks the signature, the binding to expected and to this helper, the
// validity window and the nonce, then consumes the nonce. A capability that fails any check
// before the replay check leaves its nonce unused. After an observed clock rollback it returns
// ErrAuthorizationClockUnsafe for every capability. It runs no network commands.
func (v *Verifier) VerifyAndConsume(capability SignedCapability, expected Intent) error {
	if v == nil ||
		validateIntent(expected) != nil ||
		validateStructure(capability.Claims) != nil ||
		capability.Claims.Intent != expected ||
		capability.Claims.HelperID != v.helperID {
		return ErrInvalidCapability
	}

	signature, err := base64.RawURLEncoding.DecodeString(capability.Signature)
	if err != nil ||
		len(signature) != ed25519.SignatureSize ||
		base64.RawURLEncoding.EncodeToString(signature) != capability.Signature {
		return ErrInvalidCapability
	}

	msg, err := signingMessage(capability.Claims)
	if err != nil || !ed25519.Verify(v.key, msg, signature) {
		return ErrInvalidCapability
	}

	v.mu.Lock()
	defer v.mu.Unlock()

	now, err := v.checkedTimeLocked()
	if err != nil {
		return err
	}

	if validateTime(capability.Claims, now) != nil {
		return ErrInvalidCapability
	}

	// Expired capabilities are rejected above, so their nonces can be forgotten.
	for nonce, notAfter := range v.used {
		if now.Unix() >= notAfter {
			delete(v.used, nonce)
		}
	}

	if _, used := v.used[capability.Claims.Nonce]; used {
		return ErrCapabilityReplay
	}

	// Bound memory: refuse rather than forget a live nonce.
	if len(v.used) >= maxLiveNonces {
		return ErrInvalidCapability
	}

	v.used[capability.Claims.Nonce] = capability.Claims.NotAfter

	return nil
}
