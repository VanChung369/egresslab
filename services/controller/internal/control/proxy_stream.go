package control

import (
	"errors"
	"net/netip"
	"time"
)

const LabOpenProxyStreamOp = "OpenProxyStreamV1"

var ErrProxyDestinationNotAllowed = errors.New("proxy destination not allowed")

// ValidLabProxyDestination mirrors helperauth.ValidProxyDestination: a canonical public IPv4 address
// other than the probe sources, and a TCP port other than 0 and the DNS ports.
func ValidLabProxyDestination(destination netip.AddrPort, identPin string) bool {
	ip, port := destination.Addr(), destination.Port()

	return validLabPublicIPv4(ip) && ip.String() != LabProbeIPv4 && ip.String() != identPin &&
		port != 0 && port != 53 && port != 853
}

// NewLabOpenProxyStreamIntent must stay identical to helperauth.NewOpenProxyStreamIntent: the
// preparation's binding under its own operation, plus one destination. The tenth golden vector pins
// the signed bytes.
func NewLabOpenProxyStreamIntent(binding LabIntent, destination netip.AddrPort) (LabIntent, error) {
	if binding.Operation != LabPrepareEgressLeaseOp {
		return LabIntent{}, ErrReservationReleaseInvalid
	}

	if !ValidLabProxyDestination(destination, binding.ProbeIPv4) {
		return LabIntent{}, ErrProxyDestinationNotAllowed
	}

	expected, err := NewLabPrepareEgressLeaseIntent(binding.ProfileID, binding.Namespace, binding.ProbeIPv4,
		binding.TunnelGeneration, binding.EvidenceNonce, binding.ReservationNonce, binding.RuntimeID,
		binding.AuthorityID, binding.ReservationID, binding.EgressIPv4)
	if err != nil || expected != binding {
		return LabIntent{}, ErrReservationReleaseInvalid
	}

	expected.Operation = LabOpenProxyStreamOp
	expected.DestinationIPv4 = destination.Addr().String()
	expected.DestinationPort = destination.Port()

	return expected, nil
}

// MintProxyStream signs one stream to destination for a durable hold, only for the very helper
// epoch that prepared it: the hold proves ownership, the helper's prepared lease and fresh
// monitoring health decide whether traffic may flow. A recovered hold never opens a stream.
func (a *ReservationAuthority) MintProxyStream(
	reservationID string,
	destination netip.AddrPort,
	signer LabSigner,
	rt TrustedRuntime,
	helper LabHelperInfo,
	now time.Time,
) (LabCapability, error) {
	hold, err := a.Lookup(reservationID)
	if err != nil {
		return LabCapability{}, err
	}

	if !releaseRuntimeMatchesHold(a.info, hold, rt, now) || !releaseHelperMatchesHold(hold, helper) {
		return LabCapability{}, ErrReservationReleaseInvalid
	}

	binding, err := NewLabPrepareEgressLeaseIntent(hold.Owner.ProfileID, hold.Owner.Namespace, hold.IdentIPv4,
		hold.Owner.TunnelGeneration, hold.EvidenceNonce, hold.ReservationNonce, hold.Owner.RuntimeID, a.info.ID,
		hold.ID, hold.IPv4.String())
	if err != nil {
		return LabCapability{}, err
	}

	intent, err := NewLabOpenProxyStreamIntent(binding, destination)
	if err != nil {
		return LabCapability{}, err
	}

	return mintLabCapability(signer, intent, helper, now)
}
