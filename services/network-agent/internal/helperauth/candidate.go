package helperauth

// NewReserveEgressCandidateIntent authorizes consuming one verified PermitMultiProbeV2 attempt.
// ProbeIPv4 binds the ident.me pin of that attempt's source policy, not the observed egress
// address, which comes only from the helper's evidence.
func NewReserveEgressCandidateIntent(profileID, namespace, identPin, generation, evidenceNonce string) (Intent, error) {
	intent := Intent{
		Operation:        OpReserveEgressCandidate,
		ProfileID:        profileID,
		Namespace:        namespace,
		ProbeIPv4:        identPin,
		TunnelGeneration: generation,
		EvidenceNonce:    evidenceNonce,
	}

	if err := validateIntent(intent); err != nil {
		return Intent{}, err
	}

	return intent, nil
}
