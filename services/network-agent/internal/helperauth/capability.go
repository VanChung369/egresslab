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

	// OpPermitMultiProbe names the fixed V1 multi-source policy; ProbeIPv4 binds its ident.me pin.
	// A change of sources, endpoints or semantics needs a new operation, not a new meaning for this one.
	OpPermitMultiProbe = "PermitMultiProbeV1"

	// OpPermitMultiProbeV2 is the V1 policy bound to one tunnel generation as well.
	OpPermitMultiProbeV2 = "PermitMultiProbeV2"

	// OpReserveEgressCandidate consumes the helper's evidence of one PermitMultiProbeV2 attempt. It
	// names that attempt, never an address: the address comes from the helper's own evidence.
	OpReserveEgressCandidate = "ReserveEgressCandidateV1"

	// OpPrepareEgressLease binds a local candidate to the controller's durable reservation. It
	// authorizes no application traffic.
	OpPrepareEgressLease = "PrepareEgressLeaseV1"

	// OpRevokeEgressLease names the same reservation as a preparation but only retires its tunnel
	// generation.
	OpRevokeEgressLease = "RevokeEgressLeaseV1"

	// OpRecoverRetiredGeneration is the revocation of an original helper epoch's reservation, answered
	// by a later epoch from its boot-bound witnesses instead of a retirement record.
	OpRecoverRetiredGeneration = "RecoverRetiredGenerationV1"

	// OpOpenProxyStream opens one IPv4 TCP stream for the prepared reservation's tunnel generation,
	// to one destination. It is the only operation that lets traffic through the data-plane gate.
	OpOpenProxyStream = "OpenProxyStreamV1"

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

	tunnelGenerationPattern = regexp.MustCompile(`^tunnelgen_[0-9a-f]{32}$`)
)

// Intent describes exactly what is authorized. The helper compares it with the intent supplied
// independently in the request.
type Intent struct {
	Operation string `json:"operation"`
	ProfileID string `json:"profile_id"`
	Namespace string `json:"namespace"`
	StageID   string `json:"stage_id,omitempty"`
	ProbeIPv4 string `json:"probe_ipv4,omitempty"`

	// Appended in this order and omitted when empty, so every earlier intent signs exactly the same
	// bytes as before. The controller's LabIntent must mirror the order.
	TunnelGeneration string `json:"tunnel_generation,omitempty"`
	EvidenceNonce    string `json:"evidence_nonce,omitempty"` // the consumed V2 attempt's nonce

	// PrepareEgressLeaseV1 and RevokeEgressLeaseV1 only.
	ReservationNonce string `json:"reservation_nonce,omitempty"` // the ReserveEgressCandidateV1 attempt's nonce
	RuntimeID        string `json:"runtime_id,omitempty"`
	AuthorityID      string `json:"authority_id,omitempty"`
	ReservationID    string `json:"reservation_id,omitempty"`
	EgressIPv4       string `json:"egress_ipv4,omitempty"` // the reserved address, not the probe pin

	// RecoverRetiredGenerationV1 only: the hold's epoch; Claims.HelperID names the recovering one.
	OriginalHelperID string `json:"original_helper_id,omitempty"`

	// OpenProxyStreamV1 only: the one destination of the stream.
	DestinationIPv4 string `json:"destination_ipv4,omitempty"`
	DestinationPort uint16 `json:"destination_port,omitempty"`
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

func ValidStageID(id string) bool {
	return stagePattern.MatchString(id)
}

func ValidTunnelGeneration(id string) bool {
	return tunnelGenerationPattern.MatchString(id)
}

func ValidCapabilityNonce(nonce string) bool {
	return noncePattern.MatchString(nonce)
}

func validateIntent(in Intent) error {
	if in.Operation != OpRecoverRetiredGeneration && in.OriginalHelperID != "" {
		return ErrInvalidCapability
	}

	// A recovery binds exactly the revocation of the same reservation.
	if in.Operation == OpRecoverRetiredGeneration {
		if !helperPattern.MatchString(in.OriginalHelperID) {
			return ErrInvalidCapability
		}

		binding := in
		binding.Operation = OpRevokeEgressLease
		binding.OriginalHelperID = ""

		return validateIntent(binding)
	}

	// A proxy stream binds exactly the preparation of the same reservation, plus one destination.
	if in.Operation == OpOpenProxyStream {
		binding := in
		binding.Operation = OpPrepareEgressLease
		binding.DestinationIPv4, binding.DestinationPort = "", 0

		if err := validateIntent(binding); err != nil {
			return err
		}

		if !ValidProxyDestination(in.DestinationIPv4, in.DestinationPort, in.ProbeIPv4) {
			return ErrInvalidCapability
		}

		return nil
	}

	if in.DestinationIPv4 != "" || in.DestinationPort != 0 {
		return ErrInvalidCapability
	}

	if !ValidProfileID(in.ProfileID) {
		return ErrInvalidCapability
	}

	// Only V2, the reservation that consumes it, and the preparation and revocation of that
	// reservation may carry a tunnel generation; only the last three an evidence reference, and only
	// the last two the lease fields.
	switch in.Operation {
	case OpPermitMultiProbeV2, OpReserveEgressCandidate, OpPrepareEgressLease, OpRevokeEgressLease:
	default:
		if in.TunnelGeneration != "" {
			return ErrInvalidCapability
		}
	}

	if in.Operation != OpReserveEgressCandidate && in.Operation != OpPrepareEgressLease &&
		in.Operation != OpRevokeEgressLease && in.EvidenceNonce != "" {
		return ErrInvalidCapability
	}

	if in.Operation != OpPrepareEgressLease && in.Operation != OpRevokeEgressLease && in.HasLeaseFields() {
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
		if !ValidStageID(in.StageID) || in.ProbeIPv4 != "" {
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

	case OpPermitMultiProbe:
		if in.StageID != "" || !ValidMultiProbePin(in.ProbeIPv4) {
			return ErrInvalidCapability
		}

	case OpPermitMultiProbeV2:
		if in.StageID != "" || !ValidMultiProbePin(in.ProbeIPv4) || !ValidTunnelGeneration(in.TunnelGeneration) {
			return ErrInvalidCapability
		}

	case OpReserveEgressCandidate:
		if in.StageID != "" || !ValidMultiProbePin(in.ProbeIPv4) || !ValidTunnelGeneration(in.TunnelGeneration) ||
			!ValidCapabilityNonce(in.EvidenceNonce) {
			return ErrInvalidCapability
		}

	case OpPrepareEgressLease, OpRevokeEgressLease:
		if !validPrepareLeaseFields(in) {
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

// MaxIssueSkew is how far a capability's issued_at may lie ahead of the helper's clock: the
// controller mints with the host's clock, and a VM's clock can run behind it. Expiry has no skew,
// and the nonce stays single-use until not_after. It is a second under the controller's 5 s
// allowance for evidence, so that issued_at's truncation to the second never lets the helper accept
// an attempt that the controller then refuses.
const MaxIssueSkew = 4 * time.Second

func validateTime(c Claims, now time.Time) error {
	if now.Unix() < c.IssuedAt-int64(MaxIssueSkew/time.Second) || now.Unix() >= c.NotAfter {
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
// While the wall clock reads earlier than the latest second it has seen, the verifier refuses
// every capability.
//
// The verifier must not be copied after use.
type Verifier struct {
	mu       sync.Mutex
	key      ed25519.PublicKey
	helperID string
	used     map[string]int64 // nonce -> not_after
	now      func() time.Time
	logf     func(format string, args ...any)

	lastWall    int64 // latest wall-clock second seen by checkedTimeLocked
	clockBehind bool  // the clock now reads earlier than lastWall
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
		logf:     logDetached,
	}, nil
}

// VerifyAndConsume checks the signature, the binding to expected and to this helper, the
// validity window and the nonce, then consumes the nonce. A capability that fails any check
// before the replay check leaves its nonce unused. While the wall clock reads earlier than the
// latest second it has seen, it returns ErrAuthorizationClockUnsafe for every capability. It runs
// no network commands.
func (v *Verifier) VerifyAndConsume(capability SignedCapability, expected Intent) error {
	return v.verify(capability, expected, true)
}

// Check runs every check of VerifyAndConsume, the replay check included, without consuming the
// nonce. It lets a request prove it is authorized before it may interrupt other work.
func (v *Verifier) Check(capability SignedCapability, expected Intent) error {
	return v.verify(capability, expected, false)
}

// Unexpired reads the clock as an authorization does and reports whether a capability consumed
// earlier is still before its not_after: work queued since its arrival checks it before it acts.
func (v *Verifier) Unexpired(capability SignedCapability) bool {
	if v == nil {
		return false
	}

	v.mu.Lock()
	defer v.mu.Unlock()

	now, err := v.checkedTimeLocked()

	return err == nil && now.Unix() < capability.Claims.NotAfter
}

// ClockSafe reads the clock as an authorization does: false while the wall clock reads earlier
// than the latest second seen. Work authorized earlier checks it again before it acts.
func (v *Verifier) ClockSafe() bool {
	if v == nil {
		return false
	}

	v.mu.Lock()
	defer v.mu.Unlock()

	_, err := v.checkedTimeLocked()

	return err == nil
}

func (v *Verifier) verify(capability SignedCapability, expected Intent, consume bool) error {
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

	if !consume {
		return nil
	}

	// Bound memory: refuse rather than forget a live nonce.
	if len(v.used) >= maxLiveNonces {
		return ErrInvalidCapability
	}

	v.used[capability.Claims.Nonce] = capability.Claims.NotAfter

	return nil
}
