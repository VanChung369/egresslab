package control

import (
	"errors"
	"regexp"
	"time"
)

const (
	LabMultiProbeV2Op     = "PermitMultiProbeV2"
	LabMultiProbeTargetOp = "MultiProbeTarget"

	labGenerationProbeFreshness = 60 * time.Second
)

var (
	labTunnelGenerationPattern = regexp.MustCompile(`^tunnelgen_[0-9a-f]{32}$`)
	labProbeNoncePattern       = regexp.MustCompile(`^[0-9a-f]{32}$`)
)

func ValidLabTunnelGeneration(id string) bool { return labTunnelGenerationPattern.MatchString(id) }

// LabMultiProbeTarget is the helper's report of one configured tunnel generation and the V2 policy
// of the helper generation that tracks it. It authorizes nothing.
type LabMultiProbeTarget struct {
	ProfileID        string `json:"profile_id"`
	Namespace        string `json:"namespace"`
	TunnelGeneration string `json:"tunnel_generation"`

	LabMultiProbePolicy
}

func (t LabMultiProbeTarget) Valid() bool {
	return ValidProfileID(t.ProfileID) &&
		ValidLabNamespace(t.Namespace) &&
		ValidLabTunnelGeneration(t.TunnelGeneration) &&
		t.Policy == LabMultiProbeV2Op &&
		t.LabMultiProbePolicy.Valid()
}

func (t LabMultiProbeTarget) Matches(info LabHelperInfo, binding RuntimeBinding) bool {
	return t.Valid() &&
		t.LabMultiProbePolicy.Matches(info) &&
		t.ProfileID == binding.ProfileID &&
		t.Namespace == binding.Namespace &&
		t.RuntimeID == binding.RuntimeID &&
		t.HelperID == binding.HelperEpoch
}

func NewLabGenerationProbeIntent(profileID, namespace, identPin, generation string) (LabIntent, error) {
	if !ValidProfileID(profileID) || !ValidLabNamespace(namespace) || !ValidLabMultiProbePin(identPin) ||
		!ValidLabTunnelGeneration(generation) {
		return LabIntent{}, errors.New("invalid generation-bound probe intent")
	}

	return LabIntent{
		Operation:        LabMultiProbeV2Op,
		ProfileID:        profileID,
		Namespace:        namespace,
		ProbeIPv4:        identPin,
		TunnelGeneration: generation,
	}, nil
}

// MintPermitMultiProbeV2 signs one attempt for exactly the tunnel generation the target names. The
// generation is never taken from the binding, which outlives the tunnel.
func MintPermitMultiProbeV2(
	signer LabSigner,
	profile RoutingProfile,
	binding RuntimeBinding,
	info LabHelperInfo,
	lab LabInfo,
	target LabMultiProbeTarget,
	now time.Time,
) (LabCapability, error) {
	if err := validateProbeTarget(profile, binding, info, lab); err != nil {
		return LabCapability{}, err
	}

	if !target.Matches(info, binding) {
		return LabCapability{}, errors.New("generation-bound target identity mismatch")
	}

	intent, err := NewLabGenerationProbeIntent(profile.ID, binding.Namespace, target.IdentIPv4, target.TunnelGeneration)
	if err != nil {
		return LabCapability{}, err
	}

	return mintLabCapability(signer, intent, info, now)
}

// MatchesCapability binds the response to the V2 intent and nonce this client sent. It is a
// request-response binding, not a signature over the evidence.
func (p LabMultiProbeInfo) MatchesCapability(capability LabCapability) bool {
	claims := capability.Claims

	return claims.Version == 1 &&
		claims.Intent.Operation == LabMultiProbeV2Op &&
		labHelperIDPattern.MatchString(claims.HelperID) &&
		labProbeNoncePattern.MatchString(claims.Nonce) &&
		p.MatchesIntent(claims.Intent) &&
		p.AttemptNonce == claims.Nonce
}

// ValidForCapability adds the request timing and the 60 s V2 freshness on the controller's clock.
// The helper's monotonic evidence deadline stays authoritative.
func (p LabMultiProbeInfo) ValidForCapability(capability LabCapability, sentAt, receivedAt time.Time) bool {
	claims := capability.Claims

	if !p.MatchesCapability(capability) ||
		claims.IssuedAt <= 0 ||
		claims.NotAfter <= claims.IssuedAt ||
		claims.NotAfter-claims.IssuedAt > 30 ||
		sentAt.Unix() >= claims.NotAfter {
		return false
	}

	if !p.validForTiming(time.Unix(claims.IssuedAt, 0), sentAt, receivedAt) {
		return false
	}

	return receivedAt.Before(p.ObservedAt.Add(labGenerationProbeFreshness))
}
