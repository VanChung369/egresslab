package control

import "errors"

const LabRevokeEgressLeaseOp = "RevokeEgressLeaseV1"

var (
	ErrReservationReleaseInvalid = errors.New("invalid reservation release evidence")
	ErrReservationNotFound       = errors.New("reservation is not held")
	ErrReservationOwnerRetired   = errors.New("tunnel generation already retired")
)

// LabRevokedLeaseInfo is the helper's RevokedLeaseInfo on the wire. It confirms the retirement of one
// managed tunnel generation, not that application networking is ready or the runtime is idle.
type LabRevokedLeaseInfo struct {
	Intent LabIntent `json:"intent"`

	HelperID          string `json:"helper_id"`
	PublicKeySHA256   string `json:"public_key_sha256"`
	RevocationNonce   string `json:"revocation_nonce"`
	GenerationRetired bool   `json:"generation_retired"`
}

// NewLabRevokeEgressLeaseIntent must stay identical to the helper's
// helperauth.NewRevokeEgressLeaseIntent: the preparation's binding under its own operation. The
// eighth golden vector pins the signed bytes.
func NewLabRevokeEgressLeaseIntent(binding LabIntent) (LabIntent, error) {
	if binding.Operation != LabPrepareEgressLeaseOp {
		return LabIntent{}, ErrReservationReleaseInvalid
	}

	expected, err := NewLabPrepareEgressLeaseIntent(binding.ProfileID, binding.Namespace, binding.ProbeIPv4,
		binding.TunnelGeneration, binding.EvidenceNonce, binding.ReservationNonce, binding.RuntimeID,
		binding.AuthorityID, binding.ReservationID, binding.EgressIPv4)
	if err != nil || expected != binding {
		return LabIntent{}, ErrReservationReleaseInvalid
	}

	expected.Operation = LabRevokeEgressLeaseOp

	return expected, nil
}

func ValidLabRevokeEgressLeaseIntent(intent LabIntent) bool {
	if intent.Operation != LabRevokeEgressLeaseOp {
		return false
	}

	binding := intent
	binding.Operation = LabPrepareEgressLeaseOp

	expected, err := NewLabRevokeEgressLeaseIntent(binding)

	return err == nil && expected == intent
}

func (r LabRevokedLeaseInfo) Valid() bool {
	return r.GenerationRetired &&
		ValidLabRevokeEgressLeaseIntent(r.Intent) &&
		labHelperIDPattern.MatchString(r.HelperID) &&
		labFingerprintPattern.MatchString(r.PublicKeySHA256) &&
		labProbeNoncePattern.MatchString(r.RevocationNonce) &&
		r.RevocationNonce != r.Intent.EvidenceNonce &&
		r.RevocationNonce != r.Intent.ReservationNonce
}

// MatchesCapability binds the receipt to the request this controller sent; it is not a helper
// signature over the receipt.
func (r LabRevokedLeaseInfo) MatchesCapability(capability LabCapability) bool {
	claims := capability.Claims

	return r.Valid() &&
		claims.Version == 1 &&
		claims.Intent == r.Intent &&
		claims.HelperID == r.HelperID &&
		claims.Nonce == r.RevocationNonce
}

// revokeIntentFromHold rebuilds the revocation for a durable hold. Unlike a preparation, it works
// for a recovered or long expired hold: revocation never depends on the authority it withdraws.
func revokeIntentFromHold(authority ReservationAuthorityInfo, hold EgressReservation) (LabIntent, error) {
	if !authority.valid() || !validateStoredReservation(hold) || hold.PublicKeySHA256 != authority.PublicKeySHA256 {
		return LabIntent{}, ErrReservationReleaseInvalid
	}

	binding, err := NewLabPrepareEgressLeaseIntent(hold.Owner.ProfileID, hold.Owner.Namespace, hold.IdentIPv4,
		hold.Owner.TunnelGeneration, hold.EvidenceNonce, hold.ReservationNonce, hold.Owner.RuntimeID, authority.ID,
		hold.ID, hold.IPv4.String())
	if err != nil {
		return LabIntent{}, err
	}

	return NewLabRevokeEgressLeaseIntent(binding)
}

func (r LabRevokedLeaseInfo) matchesReservation(authority ReservationAuthorityInfo, hold EgressReservation) bool {
	expected, err := revokeIntentFromHold(authority, hold)

	return err == nil &&
		r.Valid() &&
		r.Intent == expected &&
		r.HelperID == hold.Owner.HelperEpoch &&
		r.PublicKeySHA256 == hold.PublicKeySHA256 &&
		r.PublicKeySHA256 == authority.PublicKeySHA256
}
