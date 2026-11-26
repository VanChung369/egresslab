package helperauth

import (
	"net/netip"
	"regexp"
)

var (
	leaseRuntimeIDPattern     = regexp.MustCompile(`^runtime_[0-9a-f]{32}$`)
	leaseAuthorityIDPattern   = regexp.MustCompile(`^authority_[0-9a-f]{32}$`)
	leaseReservationIDPattern = regexp.MustCompile(`^reservation_[0-9a-f]{32}$`)
)

// HasLeaseFields lets every other operation refuse lease authorization metadata.
func (in Intent) HasLeaseFields() bool {
	return in.ReservationNonce != "" || in.RuntimeID != "" || in.AuthorityID != "" || in.ReservationID != "" ||
		in.EgressIPv4 != "" || in.OriginalHelperID != ""
}

func validPrepareLeaseFields(in Intent) bool {
	ip, err := netip.ParseAddr(in.EgressIPv4)

	return in.StageID == "" &&
		ValidMultiProbePin(in.ProbeIPv4) &&
		ValidTunnelGeneration(in.TunnelGeneration) &&
		ValidCapabilityNonce(in.EvidenceNonce) &&
		ValidCapabilityNonce(in.ReservationNonce) &&
		in.EvidenceNonce != in.ReservationNonce &&
		leaseRuntimeIDPattern.MatchString(in.RuntimeID) &&
		leaseAuthorityIDPattern.MatchString(in.AuthorityID) &&
		leaseReservationIDPattern.MatchString(in.ReservationID) &&
		err == nil &&
		ValidPublicProbeIPv4(ip) &&
		ip.String() == in.EgressIPv4
}

// NewPrepareEgressLeaseIntent binds one local candidate to the controller's durable reservation.
// ProbeIPv4 is the ident.me pin of the source policy; EgressIPv4 the reserved address, which the
// helper checks against its own candidate. It authorizes no application traffic.
func NewPrepareEgressLeaseIntent(
	profileID, namespace, identPin, generation, evidenceNonce, reservationNonce,
	runtimeID, authorityID, reservationID, egressIPv4 string,
) (Intent, error) {
	intent := Intent{
		Operation:        OpPrepareEgressLease,
		ProfileID:        profileID,
		Namespace:        namespace,
		ProbeIPv4:        identPin,
		TunnelGeneration: generation,
		EvidenceNonce:    evidenceNonce,
		ReservationNonce: reservationNonce,
		RuntimeID:        runtimeID,
		AuthorityID:      authorityID,
		ReservationID:    reservationID,
		EgressIPv4:       egressIPv4,
	}

	if err := validateIntent(intent); err != nil {
		return Intent{}, err
	}

	return intent, nil
}
