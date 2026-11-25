package control

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"time"
)

// ReservationTransport is the subset of the trusted runtime transport this workflow needs;
// labruntime.HelperTransport implements it.
type ReservationTransport interface {
	MultiProbeTarget(ctx context.Context, profileID, namespace string) (LabMultiProbeTarget, error)
	ProbeEgressMulti(ctx context.Context, profileID, namespace string, capability LabCapability) (LabMultiProbeInfo, error)
	ReserveEgressCandidate(ctx context.Context, profileID, namespace string, capability LabCapability) (LabCandidateInfo, error)
}

// ReservationContext comes from the trusted controller state and the runtime currently in use,
// never from an HTTP request or user-supplied JSON. The transport must belong to the same provider
// target as Runtime, as the CLI's currentRuntime ensures: the workflow cannot check that, and a
// transport to another runtime could echo this runtime's public identity and fabricate evidence.
type ReservationContext struct {
	Profile RoutingProfile
	Binding RuntimeBinding
	Runtime TrustedRuntime
	Helper  LabHelperInfo
	Lab     LabInfo
}

func (c ReservationContext) validAt(now time.Time) bool {
	if err := validateProbeTarget(c.Profile, c.Binding, c.Helper, c.Lab); err != nil {
		return false
	}

	return c.Helper.AuthorizationConfigured &&
		c.Helper.Valid() &&
		c.Runtime.ID == c.Helper.RuntimeID &&
		c.Runtime.PublicKeySHA256 == c.Helper.PublicKeySHA256 &&
		validRuntimeTarget(c.Runtime.Provider, c.Runtime.Target) &&
		!c.Runtime.TrustedAt.IsZero() &&
		!c.Runtime.TrustedAt.After(now) &&
		now.Unix() > 0
}

// ReserveVerifiedEgress performs one verification and durable reservation attempt: no activation,
// retry or release.
func ReserveVerifiedEgress(
	ctx context.Context,
	dataDir string,
	transport ReservationTransport,
	signer LabSigner,
	trust ReservationContext,
) (EgressReservation, error) {
	return reserveVerifiedEgressAt(ctx, dataDir, transport, signer, trust, time.Now)
}

// reservationPreflight only rejects early (missing or corrupt journal, a profile already held, a
// full registry) before any runtime call; the durable transaction decides uniqueness.
func reservationPreflight(dataDir, profileID string) error {
	items, err := inspectReservationJournal(dataDir)
	if err != nil {
		return err
	}

	for _, item := range items {
		if item.Owner.ProfileID == profileID {
			return ErrReservationProfileHeld
		}
	}

	if len(items) >= maxEgressReservations {
		return ErrReservationLimit
	}

	return nil
}

// reservationCapabilitySendValid checks a capability again right before it is submitted: the key
// store (DPAPI, Keychain) can be slow.
func reservationCapabilitySendValid(capability LabCapability, mintedAt, sentAt time.Time) bool {
	claims := capability.Claims

	return claims.Version == 1 &&
		claims.IssuedAt == mintedAt.Unix() &&
		claims.IssuedAt > 0 &&
		claims.NotAfter > claims.IssuedAt &&
		claims.NotAfter-claims.IssuedAt <= 30 &&
		stableReservationClock(mintedAt, sentAt) &&
		sentAt.Unix() >= claims.IssuedAt &&
		sentAt.Unix() < claims.NotAfter
}

// reserveVerifiedEgressAt never holds the journal lock across runtime calls: preflight, then the
// V2 verification and the candidate, then one durable transaction that reloads the journal. A
// phase that fails stops every later one; consumed helper evidence is not restored.
func reserveVerifiedEgressAt(
	ctx context.Context,
	dataDir string,
	transport ReservationTransport,
	signer LabSigner,
	trust ReservationContext,
	now func() time.Time,
) (EgressReservation, error) {
	if ctx == nil || transport == nil || signer == nil || now == nil {
		return EgressReservation{}, ErrReservationUnavailable
	}

	if err := ctx.Err(); err != nil {
		return EgressReservation{}, err
	}

	startedAt := now()
	if !trust.validAt(startedAt) {
		return EgressReservation{}, ErrReservationCandidateInvalid
	}

	public, err := signer.PublicKey()
	if err != nil {
		return EgressReservation{}, err
	}

	if len(public) != ed25519.PublicKeySize || LabPublicKeySHA256(public) != trust.Runtime.PublicKeySHA256 {
		return EgressReservation{}, ErrReservationCandidateInvalid
	}

	profileID, namespace := trust.Profile.ID, trust.Binding.Namespace

	if err := reservationPreflight(dataDir, profileID); err != nil {
		return EgressReservation{}, fmt.Errorf("reservation preflight: %w", err)
	}

	if err := ctx.Err(); err != nil {
		return EgressReservation{}, err
	}

	target, err := transport.MultiProbeTarget(ctx, profileID, namespace)
	if err != nil {
		return EgressReservation{}, fmt.Errorf("discover probe target: %w", err)
	}

	if !target.Matches(trust.Helper, trust.Binding) ||
		target.RuntimeID != trust.Runtime.ID ||
		target.PublicKeySHA256 != trust.Runtime.PublicKeySHA256 {
		return EgressReservation{}, ErrReservationCandidateInvalid
	}

	if err := ctx.Err(); err != nil {
		return EgressReservation{}, err
	}

	// Phase 1: one V2 verification.
	probeMintedAt := now()
	if !stableReservationClock(startedAt, probeMintedAt) {
		return EgressReservation{}, ErrReservationCandidateInvalid
	}

	probeCapability, err := MintPermitMultiProbeV2(signer, trust.Profile, trust.Binding, trust.Helper, trust.Lab,
		target, probeMintedAt)
	if err != nil {
		return EgressReservation{}, err
	}

	probeSentAt := now()
	if !reservationCapabilitySendValid(probeCapability, probeMintedAt, probeSentAt) {
		return EgressReservation{}, ErrReservationCandidateExpired
	}

	if err := ctx.Err(); err != nil {
		return EgressReservation{}, err
	}

	probe, err := transport.ProbeEgressMulti(ctx, profileID, namespace, probeCapability)
	probeReceivedAt := now()

	if err != nil {
		return EgressReservation{}, fmt.Errorf("verify egress: %w", err)
	}

	if !probe.ValidForCapability(probeCapability, probeSentAt, probeReceivedAt) ||
		!stableReservationClock(probeSentAt, probeReceivedAt) {
		return EgressReservation{}, ErrReservationCandidateInvalid
	}

	if err := ctx.Err(); err != nil {
		return EgressReservation{}, err
	}

	// Phase 2: consume exactly that verified attempt.
	reserveMintedAt := now()

	reserveCapability, err := mintReserveEgressCandidate(signer, trust.Profile, trust.Binding, trust.Helper,
		trust.Lab, target, probe, probeCapability, probeSentAt, probeReceivedAt, reserveMintedAt)
	if err != nil {
		return EgressReservation{}, err
	}

	// A slow key store can push the submission past the evidence cutoff; consuming the evidence then
	// would only waste it.
	reserveSentAt := now()
	if !reservationCapabilitySendValid(reserveCapability, reserveMintedAt, reserveSentAt) ||
		!candidateEvidenceFresh(probeSentAt, probe.ObservedAt, reserveSentAt) {
		return EgressReservation{}, ErrReservationCandidateExpired
	}

	if err := ctx.Err(); err != nil {
		return EgressReservation{}, err
	}

	receipt, err := transport.ReserveEgressCandidate(ctx, profileID, namespace, reserveCapability)
	reserveReceivedAt := now()

	if err != nil {
		return EgressReservation{}, fmt.Errorf("consume verified evidence: %w", err)
	}

	// Phase 3: the internal admission, built only from this operation's own observations.
	admission := candidateAdmission{
		profile:   trust.Profile,
		binding:   trust.Binding,
		runtime:   trust.Runtime,
		helper:    trust.Helper,
		lab:       trust.Lab,
		publicKey: public,
		target:    target,

		probe:           probe,
		probeCapability: probeCapability,
		probeSentAt:     probeSentAt,
		probeReceivedAt: probeReceivedAt,

		receipt:           receipt,
		reserveCapability: reserveCapability,
		reserveSentAt:     reserveSentAt,
		reserveReceivedAt: reserveReceivedAt,
	}

	if err := ctx.Err(); err != nil {
		return EgressReservation{}, err
	}

	// Phase 4: the authoritative admission and uniqueness check, under the journal's OS lock.
	hold, err := reserveDurableEgressContext(ctx, dataDir, admission, now)
	if err != nil {
		return EgressReservation{}, fmt.Errorf("commit durable reservation: %w", err)
	}

	// The hold is durable from here on; neither cancellation nor expiry releases it.
	if err := ctx.Err(); err != nil {
		return EgressReservation{}, errors.Join(ErrReservationStateUncertain, err)
	}

	if !hold.FreshAt(now()) {
		return EgressReservation{}, ErrReservationCommittedExpired
	}

	return hold, nil
}
