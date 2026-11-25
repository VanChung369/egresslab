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

func validLabPublicIPv4(ip netip.Addr) bool {
	if !ip.Is4() || !ip.IsGlobalUnicast() || ip.IsPrivate() {
		return false
	}

	for _, prefix := range reservedProbeIPv4 {
		if prefix.Contains(ip) {
			return false
		}
	}

	return true
}

// Valid checks the observation on its own: identity format, a public IPv4 address, the fixed
// source, and a handshake that fits the helper's 180 s freshness policy.
func (p LabProbeInfo) Valid() bool {
	if !ValidProfileID(p.ProfileID) ||
		!ValidLabNamespace(p.Namespace) ||
		!validLabPublicIPv4(p.IPv4) ||
		p.Source != LabProbeSource ||
		p.ObservedAt.Unix() <= 0 ||
		p.HandshakeAt.Unix() <= 0 {
		return false
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

// validateProbeTarget is the policy every probe signer applies: a strict, unconfigured profile, the
// runtime binding of the current helper process, and the profile's own configured tunnel.
func validateProbeTarget(profile RoutingProfile, binding RuntimeBinding, info LabHelperInfo, lab LabInfo) error {
	if !ValidProfileID(profile.ID) ||
		!profile.UniqueIPRequired ||
		!profile.KillSwitchRequired ||
		profile.Status != "unconfigured" ||
		profile.TunnelID != "" {
		return errors.New("profile does not satisfy probe policy")
	}

	if binding.ProfileID != profile.ID ||
		!ValidRuntimeID(binding.RuntimeID) ||
		binding.RuntimeID != info.RuntimeID ||
		binding.HelperEpoch != info.HelperID ||
		!ValidLabNamespace(binding.Namespace) {
		return errors.New("stale or mismatched runtime binding")
	}

	if lab.ProfileID != profile.ID || lab.Namespace != binding.Namespace || lab.State != LabTunnelConfigured {
		return errors.New("probe requires the profile's configured tunnel")
	}

	return nil
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
	if err := validateProbeTarget(profile, binding, info, lab); err != nil {
		return LabCapability{}, err
	}

	return mintLabCapability(signer, LabIntent{
		Operation: "PermitProbe",
		ProfileID: profile.ID,
		Namespace: binding.Namespace,
		ProbeIPv4: LabProbeIPv4,
	}, info, now)
}
