package control

import "net/netip"

const LabPrepareEgressLeaseOp = "PrepareEgressLeaseV1"

// LabPreparedLeaseInfo is the helper's PreparedLeaseInfo on the wire: a sealed, generation-bound
// preparation. It authorizes no application traffic.
type LabPreparedLeaseInfo struct {
	LabCandidateInfo

	AuthorityID      string `json:"authority_id"`
	ReservationID    string `json:"reservation_id"`
	PreparationNonce string `json:"preparation_nonce"`
}

// NewLabPrepareEgressLeaseIntent must stay identical to the helper's
// helperauth.NewPrepareEgressLeaseIntent; the seventh golden vector pins the signed bytes.
func NewLabPrepareEgressLeaseIntent(
	profileID, namespace, identPin, generation, evidenceNonce, reservationNonce,
	runtimeID, authorityID, reservationID, egressIPv4 string,
) (LabIntent, error) {
	ip, err := netip.ParseAddr(egressIPv4)

	if !ValidProfileID(profileID) ||
		!ValidLabNamespace(namespace) ||
		!ValidLabMultiProbePin(identPin) ||
		!ValidLabTunnelGeneration(generation) ||
		!labProbeNoncePattern.MatchString(evidenceNonce) ||
		!labProbeNoncePattern.MatchString(reservationNonce) ||
		evidenceNonce == reservationNonce ||
		!ValidRuntimeID(runtimeID) ||
		!reservationAuthorityIDPattern.MatchString(authorityID) ||
		!reservationIDPattern.MatchString(reservationID) ||
		err != nil ||
		!validLabPublicIPv4(ip) ||
		ip.String() != egressIPv4 {
		return LabIntent{}, ErrReservationCandidateInvalid
	}

	return LabIntent{
		Operation:        LabPrepareEgressLeaseOp,
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
	}, nil
}

func (p LabPreparedLeaseInfo) intent() (LabIntent, error) {
	return NewLabPrepareEgressLeaseIntent(p.ProfileID, p.Namespace, p.IdentIPv4, p.TunnelGeneration, p.EvidenceNonce,
		p.ReservationNonce, p.RuntimeID, p.AuthorityID, p.ReservationID, p.IPv4.String())
}

func (p LabPreparedLeaseInfo) Valid() bool {
	if !p.LabCandidateInfo.Valid() ||
		!labProbeNoncePattern.MatchString(p.PreparationNonce) ||
		p.PreparationNonce == p.EvidenceNonce ||
		p.PreparationNonce == p.ReservationNonce {
		return false
	}

	_, err := p.intent()

	return err == nil
}

// MatchesCapability binds the receipt to the signed request structurally.
func (p LabPreparedLeaseInfo) MatchesCapability(capability LabCapability) bool {
	if !p.Valid() {
		return false
	}

	expected, err := p.intent()
	claims := capability.Claims

	return err == nil &&
		claims.Version == 1 &&
		claims.Intent == expected &&
		claims.HelperID == p.HelperID &&
		claims.Nonce == p.PreparationNonce
}

// matchesReservation binds the receipt to the durable hold, including what the signed intent does
// not carry: the evidence timestamps and the key fingerprint. A receipt that moved ExpiresAt by a
// second still passes Valid, but not this.
func (p LabPreparedLeaseInfo) matchesReservation(authority ReservationAuthorityInfo, hold EgressReservation) bool {
	return p.Valid() &&
		p.AuthorityID == authority.ID &&
		p.ReservationID == hold.ID &&
		p.ProfileID == hold.Owner.ProfileID &&
		p.RuntimeID == hold.Owner.RuntimeID &&
		p.HelperID == hold.Owner.HelperEpoch &&
		p.Namespace == hold.Owner.Namespace &&
		p.TunnelGeneration == hold.Owner.TunnelGeneration &&
		p.IdentIPv4 == hold.IdentIPv4 &&
		p.PublicKeySHA256 == hold.PublicKeySHA256 &&
		p.PublicKeySHA256 == authority.PublicKeySHA256 &&
		p.IPv4 == hold.IPv4 &&
		p.EvidenceNonce == hold.EvidenceNonce &&
		p.ReservationNonce == hold.ReservationNonce &&
		p.ObservedAt.Equal(hold.ObservedAt) &&
		p.ExpiresAt.Equal(hold.CandidateExpiresAt)
}
