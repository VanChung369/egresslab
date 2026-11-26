package helperauth

// NewRevokeEgressLeaseIntent names the same reservation as the preparation intent binding, but
// grants only the retirement of its tunnel generation. The operation is signed, so a preparation
// capability never becomes a revocation.
func NewRevokeEgressLeaseIntent(binding Intent) (Intent, error) {
	if binding.Operation != OpPrepareEgressLease {
		return Intent{}, ErrInvalidCapability
	}

	if err := validateIntent(binding); err != nil {
		return Intent{}, err
	}

	binding.Operation = OpRevokeEgressLease

	if err := validateIntent(binding); err != nil {
		return Intent{}, err
	}

	return binding, nil
}

func ValidRevokeEgressLeaseIntent(intent Intent) bool {
	if intent.Operation != OpRevokeEgressLease {
		return false
	}

	binding := intent
	binding.Operation = OpPrepareEgressLease

	expected, err := NewRevokeEgressLeaseIntent(binding)

	return err == nil && expected == intent
}
