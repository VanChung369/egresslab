package control

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/netip"
	"time"
)

const LabReserveEgressCandidateOp = "ReserveEgressCandidateV1"

var (
	ErrReservationCandidateInvalid = errors.New("invalid egress candidate admission")
	ErrReservationCandidateExpired = errors.New("egress candidate freshness expired")
)

// LabCandidateInfo is the helper's CandidateInfo on the wire: a local candidate, not a
// reservation. Valid checks its structure only.
type LabCandidateInfo struct {
	LabMultiProbeTarget

	EvidenceNonce    string `json:"evidence_nonce"`
	ReservationNonce string `json:"reservation_nonce"`

	IPv4       netip.Addr `json:"ipv4"`
	ObservedAt time.Time  `json:"observed_at"`
	ExpiresAt  time.Time  `json:"expires_at"`
}

func (c LabCandidateInfo) Valid() bool {
	return c.LabMultiProbeTarget.Valid() &&
		validLabPublicIPv4(c.IPv4) &&
		labProbeNoncePattern.MatchString(c.EvidenceNonce) &&
		labProbeNoncePattern.MatchString(c.ReservationNonce) &&
		c.EvidenceNonce != c.ReservationNonce &&
		c.ObservedAt.Unix() > 0 &&
		c.ExpiresAt.After(c.ObservedAt) &&
		c.ExpiresAt.Sub(c.ObservedAt) <= labGenerationProbeFreshness
}

// NewLabReserveEgressCandidateIntent must stay identical to the helper's
// helperauth.NewReserveEgressCandidateIntent; the golden vector pins the signed bytes.
func NewLabReserveEgressCandidateIntent(profileID, namespace, identPin, generation, evidenceNonce string) (LabIntent, error) {
	if !ValidProfileID(profileID) || !ValidLabNamespace(namespace) || !ValidLabMultiProbePin(identPin) ||
		!ValidLabTunnelGeneration(generation) || !labProbeNoncePattern.MatchString(evidenceNonce) {
		return LabIntent{}, ErrReservationCandidateInvalid
	}

	return LabIntent{
		Operation:        LabReserveEgressCandidateOp,
		ProfileID:        profileID,
		Namespace:        namespace,
		ProbeIPv4:        identPin,
		TunnelGeneration: generation,
		EvidenceNonce:    evidenceNonce,
	}, nil
}

// MatchesCapability binds the receipt to the reservation request structurally; the helper checked
// the signature.
func (c LabCandidateInfo) MatchesCapability(capability LabCapability) bool {
	if !c.Valid() {
		return false
	}

	expected, err := NewLabReserveEgressCandidateIntent(c.ProfileID, c.Namespace, c.IdentIPv4, c.TunnelGeneration,
		c.EvidenceNonce)
	claims := capability.Claims

	return err == nil &&
		claims.Version == 1 &&
		claims.Intent == expected &&
		claims.HelperID == c.HelperID &&
		claims.Nonce == c.ReservationNonce
}

// candidateAdmission is internal controller input. The trusted orchestration path assembles it
// from the current runtime transport, controller state and the capabilities this controller
// issued, with timestamps from time.Now (monotonic, never reloaded from storage). It must never be
// built from an HTTP request body or a user-supplied receipt: the receipt carries no helper
// signature, so only the transport it arrived on vouches for it.
type candidateAdmission struct {
	profile RoutingProfile
	binding RuntimeBinding
	runtime TrustedRuntime
	helper  LabHelperInfo
	lab     LabInfo

	publicKey ed25519.PublicKey

	target LabMultiProbeTarget

	probe           LabMultiProbeInfo
	probeCapability LabCapability
	probeSentAt     time.Time
	probeReceivedAt time.Time

	receipt           LabCandidateInfo
	reserveCapability LabCapability
	reserveSentAt     time.Time
	reserveReceivedAt time.Time
}

type admittedCandidate struct {
	owner         LeaseOwner
	receipt       LabCandidateInfo
	eligibleUntil time.Time
}

// verifyIssuedLabCapability checks a capability against the pinned controller public key. It does
// not prove that the helper consumed it.
func verifyIssuedLabCapability(public ed25519.PublicKey, capability LabCapability) bool {
	if len(public) != ed25519.PublicKeySize {
		return false
	}

	signature, err := base64.RawURLEncoding.DecodeString(capability.Signature)
	if err != nil || len(signature) != ed25519.SignatureSize ||
		base64.RawURLEncoding.EncodeToString(signature) != capability.Signature {
		return false
	}

	raw, err := json.Marshal(capability.Claims)
	if err != nil {
		return false
	}

	return ed25519.Verify(public, append([]byte(labCapabilityDomain), raw...), signature)
}

// stableReservationClock requires to after from, with wall-clock progress within 1 s of monotonic
// progress (when both carry a monotonic reading).
func stableReservationClock(from, to time.Time) bool {
	if from.Unix() <= 0 || to.Unix() <= 0 {
		return false
	}

	elapsed := to.Sub(from)
	step := to.Round(0).Sub(from.Round(0)) - elapsed

	return elapsed >= 0 && step >= -time.Second && step <= time.Second
}

// eligibleAt checks the monotonic deadline fixed at admission and, on the wall clock, that deadline
// and the helper's cutoff again, so a wall-clock step after admission can neither carry eligibility
// past the cutoff nor produce a record whose stored times are out of order.
func eligibleAt(eligibleUntil, candidateExpiresAt, at time.Time) bool {
	wall := at.Round(0)

	return at.Before(eligibleUntil) && wall.Before(eligibleUntil.Round(0)) &&
		wall.Before(candidateExpiresAt.Add(-labProbeClockSkew))
}

// validateCandidateAdmission requires every identity and piece of evidence to agree: the trusted
// runtime and its pinned key, the strict profile and its configured lab, the helper epoch, the
// original V2 probe (target, nonce, address, observation time), the reservation request, both
// controller signatures and a consistent controller clock. The eligibility deadline never extends
// the evidence: it is the earlier of 60 s after the probe was sent and the helper's deadline minus
// the 5 s clock-skew margin.
func validateCandidateAdmission(a candidateAdmission, now time.Time) (admittedCandidate, error) {
	invalid := ErrReservationCandidateInvalid

	if err := validateProbeTarget(a.profile, a.binding, a.helper, a.lab); err != nil {
		return admittedCandidate{}, invalid
	}

	if !a.target.Matches(a.helper, a.binding) ||
		a.runtime.ID != a.target.RuntimeID ||
		a.runtime.PublicKeySHA256 != a.target.PublicKeySHA256 ||
		!validRuntimeTarget(a.runtime.Provider, a.runtime.Target) ||
		a.runtime.TrustedAt.IsZero() ||
		a.runtime.TrustedAt.After(a.probeSentAt) {
		return admittedCandidate{}, invalid
	}

	if len(a.publicKey) != ed25519.PublicKeySize || LabPublicKeySHA256(a.publicKey) != a.runtime.PublicKeySHA256 {
		return admittedCandidate{}, invalid
	}

	expectedProbe, err := NewLabGenerationProbeIntent(a.target.ProfileID, a.target.Namespace, a.target.IdentIPv4,
		a.target.TunnelGeneration)
	if err != nil ||
		a.probeCapability.Claims.Intent != expectedProbe ||
		a.probeCapability.Claims.HelperID != a.helper.HelperID ||
		!a.probe.ValidForCapability(a.probeCapability, a.probeSentAt, a.probeReceivedAt) {
		return admittedCandidate{}, invalid
	}

	c := a.receipt

	if !c.MatchesCapability(a.reserveCapability) ||
		c.LabMultiProbeTarget != a.target ||
		c.EvidenceNonce != a.probeCapability.Claims.Nonce ||
		c.EvidenceNonce != a.probe.AttemptNonce ||
		c.IPv4 != a.probe.IPv4 ||
		!c.ObservedAt.Equal(a.probe.ObservedAt) {
		return admittedCandidate{}, invalid
	}

	if !verifyIssuedLabCapability(a.publicKey, a.probeCapability) ||
		!verifyIssuedLabCapability(a.publicKey, a.reserveCapability) {
		return admittedCandidate{}, invalid
	}

	claims := a.reserveCapability.Claims

	if claims.IssuedAt <= 0 ||
		claims.NotAfter <= claims.IssuedAt ||
		claims.NotAfter-claims.IssuedAt > 30 ||
		// IssuedAt has 1 s resolution; the monotonic order of probe receipt and send is checked below.
		claims.IssuedAt < a.probeReceivedAt.Unix() ||
		a.reserveSentAt.Before(time.Unix(claims.IssuedAt, 0)) ||
		a.reserveSentAt.Unix() >= claims.NotAfter {
		return admittedCandidate{}, invalid
	}

	// One controller operation, one host clock, in order.
	if !stableReservationClock(a.probeSentAt, a.probeReceivedAt) ||
		!stableReservationClock(a.probeReceivedAt, a.reserveSentAt) ||
		!stableReservationClock(a.reserveSentAt, a.reserveReceivedAt) ||
		!stableReservationClock(a.reserveReceivedAt, now) ||
		!stableReservationClock(a.probeSentAt, now) {
		return admittedCandidate{}, invalid
	}

	helperRemaining := c.ExpiresAt.Add(-labProbeClockSkew).Round(0).Sub(now.Round(0))
	hostRemaining := a.probeSentAt.Add(labGenerationProbeFreshness).Sub(now)

	remaining := min(helperRemaining, hostRemaining)
	if remaining <= 0 {
		return admittedCandidate{}, ErrReservationCandidateExpired
	}

	owner := LeaseOwner{
		ProfileID:        c.ProfileID,
		RuntimeID:        c.RuntimeID,
		HelperEpoch:      c.HelperID,
		Namespace:        c.Namespace,
		TunnelGeneration: c.TunnelGeneration,
	}

	if !owner.Valid() {
		return admittedCandidate{}, invalid
	}

	return admittedCandidate{owner: owner, receipt: c, eligibleUntil: now.Add(remaining)}, nil
}
