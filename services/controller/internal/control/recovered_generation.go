package control

import "regexp"

const LabRecoverRetiredGenerationOp = "RecoverRetiredGenerationV1"

var labRecoveryBootPattern = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

func validLabRecoveryBootID(id string) bool {
	return labRecoveryBootPattern.MatchString(id) && id != "00000000-0000-0000-0000-000000000000"
}

// NewLabRecoverRetiredGenerationIntent must stay identical to the helper's
// helperauth.NewRecoverRetiredGenerationIntent; the ninth golden vector pins the signed bytes.
func NewLabRecoverRetiredGenerationIntent(revocation LabIntent, originalHelperID string) (LabIntent, error) {
	if !ValidLabRevokeEgressLeaseIntent(revocation) || !labHelperIDPattern.MatchString(originalHelperID) {
		return LabIntent{}, ErrReservationReleaseInvalid
	}

	revocation.Operation = LabRecoverRetiredGenerationOp
	revocation.OriginalHelperID = originalHelperID

	return revocation, nil
}

func ValidLabRecoverRetiredGenerationIntent(intent LabIntent) bool {
	if intent.Operation != LabRecoverRetiredGenerationOp {
		return false
	}

	revocation := intent
	revocation.Operation = LabRevokeEgressLeaseOp
	revocation.OriginalHelperID = ""

	expected, err := NewLabRecoverRetiredGenerationIntent(revocation, intent.OriginalHelperID)

	return err == nil && expected == intent
}

func ValidLabRetirementIntent(intent LabIntent) bool {
	return ValidLabRevokeEgressLeaseIntent(intent) || ValidLabRecoverRetiredGenerationIntent(intent)
}

// validRecoveryBoundary: a recovery names two distinct kernel boots and another epoch than the
// original; a normal revocation names none.
func (r LabRevokedLeaseInfo) validRecoveryBoundary() bool {
	if r.Intent.Operation == LabRevokeEgressLeaseOp {
		return r.OriginalBootID == "" && r.CurrentBootID == ""
	}

	return ValidLabRecoverRetiredGenerationIntent(r.Intent) &&
		r.Intent.OriginalHelperID != r.HelperID &&
		validLabRecoveryBootID(r.OriginalBootID) &&
		validLabRecoveryBootID(r.CurrentBootID) &&
		r.OriginalBootID != r.CurrentBootID
}
