package control

import (
	"errors"
	"net/netip"
	"time"
)

const (
	LabProbeIPv4   = "1.1.1.1"
	LabProbeSource = "cloudflare_trace"

	labProbeHandshakeAge = 180 * time.Second
	labProbeOperation    = 80 * time.Second

	// Controller policy: how old an observation may be when it arrives, and how far the host and
	// runtime clocks may disagree.
	labProbeFreshness = 90 * time.Second
	labProbeClockSkew = 5 * time.Second
)

// LabProbeInfo is diagnostic evidence from one source, never an active lease.
type LabProbeInfo struct {
	ProfileID   string     `json:"profile_id"`
	Namespace   string     `json:"namespace"`
	IPv4        netip.Addr `json:"ipv4"`
	ObservedAt  time.Time  `json:"observed_at"`
	HandshakeAt time.Time  `json:"handshake_at"`
	Source      string     `json:"source"`
}

// reservedProbeIPv4, with IsGlobalUnicast and IsPrivate, refuses the same addresses as the network
// agent's parseCandidateIPv4 (reservedIPv4): keep the two aligned.
var reservedProbeIPv4 = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("192.0.0.0/24"),
	netip.MustParsePrefix("192.0.2.0/24"),
	netip.MustParsePrefix("192.88.99.0/24"),
	netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("198.51.100.0/24"),
	netip.MustParsePrefix("203.0.113.0/24"),
	netip.MustParsePrefix("240.0.0.0/4"),
}

// Valid checks the observation on its own: identity format, a public IPv4 address, the fixed
// source, and a handshake that fits the helper's 180 s freshness policy.
func (p LabProbeInfo) Valid() bool {
	if !ValidProfileID(p.ProfileID) ||
		!ValidLabNamespace(p.Namespace) ||
		!p.IPv4.Is4() ||
		!p.IPv4.IsGlobalUnicast() ||
		p.IPv4.IsPrivate() ||
		p.Source != LabProbeSource ||
		p.ObservedAt.Unix() <= 0 ||
		p.HandshakeAt.Unix() <= 0 {
		return false
	}

	for _, prefix := range reservedProbeIPv4 {
		if prefix.Contains(p.IPv4) {
			return false
		}
	}

	return !p.HandshakeAt.Before(p.ObservedAt.Add(-labProbeHandshakeAge)) &&
		!p.HandshakeAt.After(p.ObservedAt.Add(labProbeOperation))
}

// ValidFor also requires the probe asked for, observed after the capability was issued and at
// most 90 s before it arrived, with 5 s of clock skew between host and runtime. The capability
// only had to be valid when the helper accepted it; the probe may finish after it expired.
func (p LabProbeInfo) ValidFor(profileID, namespace string, issuedAt, receivedAt time.Time) bool {
	return p.Valid() &&
		p.ProfileID == profileID &&
		p.Namespace == namespace &&
		!p.ObservedAt.Before(issuedAt.Add(-labProbeClockSkew)) &&
		!p.ObservedAt.After(receivedAt.Add(labProbeClockSkew)) &&
		!p.ObservedAt.Before(receivedAt.Add(-labProbeFreshness)) &&
		!p.HandshakeAt.After(receivedAt.Add(labProbeClockSkew)) &&
		!p.HandshakeAt.Before(receivedAt.Add(-labProbeHandshakeAge-labProbeClockSkew))
}

// MintPermitProbe signs one probe of the profile's own configured tunnel, in the helper process
// the binding names, for the fixed destination only. It authorizes no lease and no proxy.
func MintPermitProbe(
	signer LabSigner,
	profile RoutingProfile,
	binding RuntimeBinding,
	info LabHelperInfo,
	lab LabInfo,
	now time.Time,
) (LabCapability, error) {
	if !ValidProfileID(profile.ID) ||
		!profile.UniqueIPRequired ||
		!profile.KillSwitchRequired ||
		profile.Status != "unconfigured" ||
		profile.TunnelID != "" {
		return LabCapability{}, errors.New("profile does not satisfy probe policy")
	}

	if binding.ProfileID != profile.ID ||
		!ValidRuntimeID(binding.RuntimeID) ||
		binding.RuntimeID != info.RuntimeID ||
		binding.HelperEpoch != info.HelperID ||
		!ValidLabNamespace(binding.Namespace) {
		return LabCapability{}, errors.New("stale or mismatched runtime binding")
	}

	if lab.ProfileID != profile.ID || lab.Namespace != binding.Namespace || lab.State != LabTunnelConfigured {
		return LabCapability{}, errors.New("probe requires the profile's configured tunnel")
	}

	return mintLabCapability(signer, LabIntent{
		Operation: "PermitProbe",
		ProfileID: profile.ID,
		Namespace: binding.Namespace,
		ProbeIPv4: LabProbeIPv4,
	}, info, now)
}
