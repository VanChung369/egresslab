package helperauth

// NewRecoverRetiredGenerationIntent turns a revocation into the recovery of the same reservation
// for its original helper epoch.
func NewRecoverRetiredGenerationIntent(revocation Intent, originalHelperID string) (Intent, error) {
	if !ValidRevokeEgressLeaseIntent(revocation) {
		return Intent{}, ErrInvalidCapability
	}

	revocation.Operation = OpRecoverRetiredGeneration
	revocation.OriginalHelperID = originalHelperID

	if err := validateIntent(revocation); err != nil {
		return Intent{}, err
	}

	return revocation, nil
}

func ValidRecoverRetiredGenerationIntent(intent Intent) bool {
	return intent.Operation == OpRecoverRetiredGeneration && validateIntent(intent) == nil
}

func ValidRetirementIntent(intent Intent) bool {
	return ValidRevokeEgressLeaseIntent(intent) || ValidRecoverRetiredGenerationIntent(intent)
}
