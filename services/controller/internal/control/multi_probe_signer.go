package control

import (
	"errors"
	"net/netip"
	"time"
)

const (
	LabMultiProbePolicyOp = "MultiProbePolicy"
	LabMultiProbeOp       = "PermitMultiProbeV1"

	LabMultiProbeIdentSource = "ident_me"
)

// LabMultiProbePolicy is the helper's public policy metadata. It is trusted only as the
// root-managed configuration of a runtime the operator trusts, and only when it names the same
// helper generation as HelperInfo; it does not prove who operates the pin.
type LabMultiProbePolicy struct {
	Policy          string `json:"policy"`
	IdentIPv4       string `json:"ident_ipv4"`
	HelperID        string `json:"helper_id"`
	RuntimeID       string `json:"runtime_id"`
	PublicKeySHA256 string `json:"public_key_sha256"`
}

// ValidLabMultiProbePin checks the V1 policy's one variable destination: a canonical public IPv4
// address other than Cloudflare's.
func ValidLabMultiProbePin(raw string) bool {
	ip, err := netip.ParseAddr(raw)

	return err == nil && validLabPublicIPv4(ip) && ip.String() == raw && raw != LabProbeIPv4
}

func (p LabMultiProbePolicy) Valid() bool {
	return (p.Policy == LabMultiProbeOp || p.Policy == LabMultiProbeV2Op) &&
		ValidLabMultiProbePin(p.IdentIPv4) &&
		ValidRuntimeID(p.RuntimeID) &&
		labHelperIDPattern.MatchString(p.HelperID) &&
		labFingerprintPattern.MatchString(p.PublicKeySHA256)
}

// Matches binds the policy to the helper generation whose identity was checked separately.
func (p LabMultiProbePolicy) Matches(info LabHelperInfo) bool {
	return p.Valid() &&
		info.Valid() &&
		info.AuthorizationConfigured &&
		p.RuntimeID == info.RuntimeID &&
		p.HelperID == info.HelperID &&
		p.PublicKeySHA256 == info.PublicKeySHA256
}

func NewLabMultiProbeIntent(profileID, namespace, identPin string) (LabIntent, error) {
	if !ValidProfileID(profileID) || !ValidLabNamespace(namespace) || !ValidLabMultiProbePin(identPin) {
		return LabIntent{}, errors.New("invalid multi-source probe intent")
	}

	return LabIntent{
		Operation: LabMultiProbeOp,
		ProfileID: profileID,
		Namespace: namespace,
		ProbeIPv4: identPin,
	}, nil
}

// MintPermitMultiProbe signs exactly one attempt against the fixed V1 policy that the current,
// trusted helper generation advertises. It authorizes neither a lease nor traffic.
func MintPermitMultiProbe(
	signer LabSigner,
	profile RoutingProfile,
	binding RuntimeBinding,
	info LabHelperInfo,
	lab LabInfo,
	policy LabMultiProbePolicy,
	now time.Time,
) (LabCapability, error) {
	if err := validateProbeTarget(profile, binding, info, lab); err != nil {
		return LabCapability{}, err
	}

	if policy.Policy != LabMultiProbeOp || !policy.Matches(info) {
		return LabCapability{}, errors.New("multi-source policy identity mismatch")
	}

	intent, err := NewLabMultiProbeIntent(profile.ID, binding.Namespace, policy.IdentIPv4)
	if err != nil {
		return LabCapability{}, err
	}

	return mintLabCapability(signer, intent, info, now)
}

type LabMultiProbeSourceInfo struct {
	Source          string     `json:"source"`
	DestinationIPv4 netip.Addr `json:"destination_ipv4"`
	IPv4            netip.Addr `json:"ipv4"`
	ObservedAt      time.Time  `json:"observed_at"`
}

// LabMultiProbeInfo is diagnostic evidence from one multi-source attempt, never a lease.
type LabMultiProbeInfo struct {
	ProfileID   string     `json:"profile_id"`
	Namespace   string     `json:"namespace"`
	IPv4        netip.Addr `json:"ipv4"`
	StartedAt   time.Time  `json:"started_at"`
	FinishedAt  time.Time  `json:"finished_at"`
	ObservedAt  time.Time  `json:"observed_at"`
	HandshakeAt time.Time  `json:"handshake_at"`

	Sources []LabMultiProbeSourceInfo `json:"sources"`

	TunnelGeneration string `json:"tunnel_generation,omitempty"`
	AttemptNonce     string `json:"attempt_nonce,omitempty"`
}

// Valid checks the evidence on its own, independently of the helper and the network agent: the
// two V1 sources in execution order with their destinations, one public IPv4 address they all
// report, observation times in order inside an interval of at most 80 s, the earliest as
// ObservedAt, and a handshake at most 180 whole seconds old at FinishedAt (the helper's rule).
func (p LabMultiProbeInfo) Valid() bool {
	if !ValidProfileID(p.ProfileID) ||
		!ValidLabNamespace(p.Namespace) ||
		!validLabPublicIPv4(p.IPv4) ||
		len(p.Sources) != 2 {
		return false
	}

	// V1 evidence carries neither field; V2 carries both.
	if (p.TunnelGeneration != "" || p.AttemptNonce != "") &&
		(!ValidLabTunnelGeneration(p.TunnelGeneration) || !labProbeNoncePattern.MatchString(p.AttemptNonce)) {
		return false
	}

	identPin := p.Sources[1].DestinationIPv4.String()
	if !ValidLabMultiProbePin(identPin) {
		return false
	}

	if p.StartedAt.Unix() <= 0 || p.FinishedAt.Unix() <= 0 || p.ObservedAt.Unix() <= 0 || p.HandshakeAt.Unix() <= 0 ||
		p.FinishedAt.Before(p.StartedAt) || p.FinishedAt.Sub(p.StartedAt) > labProbeOperation {
		return false
	}

	if p.HandshakeAt.After(p.FinishedAt) ||
		p.FinishedAt.Unix()-p.HandshakeAt.Unix() > int64(labProbeHandshakeAge/time.Second) {
		return false
	}

	expected := []struct{ source, destination string }{
		{LabProbeSource, LabProbeIPv4},
		{LabMultiProbeIdentSource, identPin},
	}

	previous := p.StartedAt

	for i, sample := range p.Sources {
		if sample.Source != expected[i].source ||
			sample.DestinationIPv4.String() != expected[i].destination ||
			sample.IPv4 != p.IPv4 ||
			sample.ObservedAt.Before(previous) ||
			sample.ObservedAt.After(p.FinishedAt) {
			return false
		}

		previous = sample.ObservedAt
	}

	return p.ObservedAt.Equal(p.Sources[0].ObservedAt)
}

// MatchesIntent requires the evidence for exactly the signed intent: its profile, namespace, ident.me
// pin and, for V2, tunnel generation, not a policy the response chose.
func (p LabMultiProbeInfo) MatchesIntent(intent LabIntent) bool {
	if !p.Valid() {
		return false
	}

	var expected LabIntent
	var err error

	switch intent.Operation {
	case LabMultiProbeOp:
		if p.TunnelGeneration != "" || p.AttemptNonce != "" {
			return false
		}

		expected, err = NewLabMultiProbeIntent(intent.ProfileID, intent.Namespace, intent.ProbeIPv4)
	case LabMultiProbeV2Op:
		if p.TunnelGeneration != intent.TunnelGeneration || !labProbeNoncePattern.MatchString(p.AttemptNonce) {
			return false
		}

		expected, err = NewLabGenerationProbeIntent(intent.ProfileID, intent.Namespace, intent.ProbeIPv4,
			intent.TunnelGeneration)
	default:
		return false
	}

	return err == nil &&
		intent == expected &&
		p.ProfileID == intent.ProfileID &&
		p.Namespace == intent.Namespace &&
		p.Sources[1].DestinationIPv4.String() == intent.ProbeIPv4
}

// ValidFor is the legacy V1 check; V2 evidence must also match the signed nonce (ValidForCapability).
func (p LabMultiProbeInfo) ValidFor(intent LabIntent, issuedAt, sentAt, receivedAt time.Time) bool {
	return intent.Operation == LabMultiProbeOp && p.MatchesIntent(intent) && p.validForTiming(issuedAt, sentAt, receivedAt)
}

// validForTiming binds the evidence to the request: it started after the capability was issued and
// after the request was sent, finished before the answer arrived, is at most 90 s old at receipt,
// and its handshake fits the helper's 180 s policy, all with 5 s of host/runtime clock skew.
func (p LabMultiProbeInfo) validForTiming(issuedAt, sentAt, receivedAt time.Time) bool {
	if issuedAt.Unix() <= 0 || sentAt.Unix() <= 0 || receivedAt.Unix() <= 0 ||
		sentAt.Before(issuedAt) || receivedAt.Before(sentAt) {
		return false
	}

	return !p.StartedAt.Before(issuedAt.Add(-labProbeClockSkew)) &&
		!p.StartedAt.Before(sentAt.Add(-labProbeClockSkew)) &&
		!p.FinishedAt.After(receivedAt.Add(labProbeClockSkew)) &&
		!p.ObservedAt.Before(receivedAt.Add(-labProbeFreshness)) &&
		!p.HandshakeAt.After(receivedAt.Add(labProbeClockSkew)) &&
		!p.HandshakeAt.Before(receivedAt.Add(-labProbeHandshakeAge-labProbeClockSkew))
}
