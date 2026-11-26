package main

import (
	"errors"

	"github.com/VanChung369/egresslab/services/controller/internal/control"
	"github.com/VanChung369/egresslab/services/controller/internal/keystore"
	"github.com/VanChung369/egresslab/services/controller/internal/labruntime"
)

type reservationListResult struct {
	Authority    control.ReservationAuthorityInfo `json:"authority"`
	Reservations []control.EgressReservation      `json:"reservations"`
	NetworkReady bool                             `json:"network_ready"`
}

// reservationCommandResult is diagnostic metadata: a durable hold and its prepared lease, not an
// active lease, and no reusable activation evidence once this process exits.
type reservationCommandResult struct {
	AuthorityID       string                       `json:"authority_id"`
	Reservation       control.EgressReservation    `json:"reservation"`
	PreparedLease     control.LabPreparedLeaseInfo `json:"prepared_lease"`
	State             string                       `json:"state"`
	ActivationAllowed bool                         `json:"activation_allowed"`
	NetworkReady      bool                         `json:"network_ready"`
}

// The controller's own codes; they are not helper codes.
const (
	codeReservationBusy              = "RESERVATION_BUSY"
	codeReservationUnavailable       = "RESERVATION_AUTHORITY_UNAVAILABLE"
	codeReservationAuthorityExists   = "RESERVATION_AUTHORITY_EXISTS"
	codeReservationAuthorityMismatch = "RESERVATION_AUTHORITY_MISMATCH"
	codeReservationJournalCorrupt    = "RESERVATION_JOURNAL_CORRUPT"
	codeReservationCollision         = "EGRESS_IP_COLLISION"
	codeReservationHeld              = "EGRESS_RESERVATION_HELD"
	codeReservationLimit             = "EGRESS_RESERVATION_LIMIT"
	codeReservationExpired           = "EGRESS_CANDIDATE_EXPIRED"
	codeReservationInvalid           = "INVALID_EGRESS_CANDIDATE"
	codeLeasePreparationUnconfirmed  = "EGRESS_PREPARATION_UNCONFIRMED"

	codeReservationNotFound           = "EGRESS_RESERVATION_NOT_FOUND"
	codeReservationOwnerRetired       = "EGRESS_GENERATION_RETIRED"
	codeReservationReleaseInvalid     = "INVALID_EGRESS_RELEASE"
	codeLeaseRevocationUnconfirmed    = "EGRESS_REVOCATION_UNCONFIRMED"
	codeReservationReleaseUnconfirmed = "EGRESS_RELEASE_UNCONFIRMED"
)

// reservationReleaseCommandResult is diagnostic: the released hold and the retirement behind it.
type reservationReleaseCommandResult struct {
	AuthorityID string `json:"authority_id"`

	control.ReleasedEgressResult

	State             string `json:"state"`
	ActivationAllowed bool   `json:"activation_allowed"`
	NetworkReady      bool   `json:"network_ready"`
}

// reservationCommandError maps the authority's errors to stable codes and keeps coded runtime and
// helper errors. An uncertain or committed-expired outcome stays STATE_UNCERTAIN, never "expired":
// the hold may be in the journal.
func reservationCommandError(err error) error {
	if err == nil {
		return nil
	}

	var code string

	switch {
	// After the durable commit: the hold exists whatever the cause, so never a plain refusal.
	case errors.Is(err, control.ErrLeasePreparationUnconfirmed):
		code = codeLeasePreparationUnconfirmed
	case errors.Is(err, control.ErrReservationStateUncertain), errors.Is(err, control.ErrReservationCommittedExpired):
		code = labruntime.CodeStateUncertain
	// After the revocation was sent: list-reservations tells whether the hold stays, and a newly
	// approved release can confirm the retirement.
	case errors.Is(err, control.ErrReservationReleaseUnconfirmed):
		code = codeReservationReleaseUnconfirmed
	case errors.Is(err, control.ErrLeaseRevocationUnconfirmed):
		code = codeLeaseRevocationUnconfirmed
	case errors.Is(err, control.ErrReservationBusy):
		code = codeReservationBusy
	case errors.Is(err, control.ErrReservationAuthorityExists):
		code = codeReservationAuthorityExists
	case errors.Is(err, control.ErrReservationAuthorityMismatch):
		code = codeReservationAuthorityMismatch
	case errors.Is(err, control.ErrReservationJournalCorrupt):
		code = codeReservationJournalCorrupt
	// After corruption: a damaged journal names a retired owner or a missing hold as its cause.
	case errors.Is(err, control.ErrReservationReleaseInvalid):
		code = codeReservationReleaseInvalid
	case errors.Is(err, control.ErrReservationNotFound):
		code = codeReservationNotFound
	case errors.Is(err, control.ErrReservationOwnerRetired):
		code = codeReservationOwnerRetired
	case errors.Is(err, control.ErrReservationIPCollision):
		code = codeReservationCollision
	case errors.Is(err, control.ErrReservationOwnerHeld), errors.Is(err, control.ErrReservationProfileHeld):
		code = codeReservationHeld
	case errors.Is(err, control.ErrReservationLimit):
		code = codeReservationLimit
	case errors.Is(err, control.ErrReservationCandidateExpired):
		code = codeReservationExpired
	case errors.Is(err, control.ErrReservationCandidateInvalid):
		code = codeReservationInvalid
	case errors.Is(err, control.ErrReservationUnavailable):
		code = codeReservationUnavailable
	default:
		return err
	}

	return labruntime.Errorf(code, err.Error())
}

// reservationDependencies never initializes a key: the authority binds the key made earlier.
func (s *session) reservationDependencies() (string, keystore.KeyStore, error) {
	if s.d.reservationRoot == nil {
		return "", nil, control.ErrReservationUnavailable
	}

	root, err := s.d.reservationRoot()
	if err != nil {
		return "", nil, errors.Join(control.ErrReservationUnavailable, err)
	}

	keys, err := s.d.openKeys(s.dataDir)
	if err != nil {
		return "", nil, err
	}

	return root, keys, nil
}

func (s *session) openReservationAuthority() (*control.ReservationAuthority, keystore.KeyStore, error) {
	root, keys, err := s.reservationDependencies()
	if err != nil {
		return nil, nil, reservationCommandError(err)
	}

	authority, err := control.OpenReservationAuthority(root, keys)
	if err != nil {
		return nil, nil, reservationCommandError(err)
	}

	return authority, keys, nil
}

func (s *session) initReservations() error {
	root, keys, err := s.reservationDependencies()
	if err != nil {
		return reservationCommandError(err)
	}

	info, err := control.InitializeReservationAuthority(root, keys)
	if err != nil {
		return reservationCommandError(err)
	}

	return s.print(struct {
		Authority    control.ReservationAuthorityInfo `json:"authority"`
		NetworkReady bool                             `json:"network_ready"`
	}{Authority: info})
}

// listReservations always prints an array for a healthy authority; a missing or damaged one is an
// error, never an empty list.
func (s *session) listReservations() error {
	authority, _, err := s.openReservationAuthority()
	if err != nil {
		return err
	}

	items, err := authority.List()
	if err != nil {
		return reservationCommandError(err)
	}

	return s.print(reservationListResult{
		Authority:    authority.Info(),
		Reservations: append([]control.EgressReservation{}, items...),
	})
}

// reserveEgress runs one signed verification, candidate, durable reservation and lease preparation.
// It refuses an unavailable authority before any runtime call, and changes no profile, endpoint or
// binding: a prepared hold is not an active profile.
func (s *session) reserveEgress(profileID, namespace string) (reservationCommandResult, error) {
	authority, keys, err := s.openReservationAuthority()
	if err != nil {
		return reservationCommandResult{}, err
	}

	profile, err := loadProfile(s.dataDir, profileID)
	if err != nil {
		return reservationCommandResult{}, err
	}

	state, err := control.LoadRuntimeState(s.dataDir)
	if err != nil {
		return reservationCommandResult{}, err
	}

	// The transport and the trusted runtime come from the same provider.
	rt, info, err := s.currentRuntime(state)
	if err != nil {
		return reservationCommandResult{}, err
	}

	if err := requireSigningRuntime(rt, info); err != nil {
		return reservationCommandResult{}, err
	}

	if rt.PublicKeySHA256 != authority.Info().PublicKeySHA256 {
		return reservationCommandResult{}, reservationCommandError(control.ErrReservationAuthorityMismatch)
	}

	binding, exists := state.Binding(profileID)
	if !exists || binding.RuntimeID != rt.ID || binding.Namespace != namespace || binding.HelperEpoch != info.HelperID {
		return reservationCommandResult{}, labruntime.Errorf(labruntime.CodeOwnershipMismatch, "missing or stale lab binding")
	}

	transport := s.provider.Transport()

	labs, err := transport.ListLabs(s.ctx)
	if err != nil {
		return reservationCommandResult{}, err
	}

	var lab control.LabInfo
	for _, item := range labs {
		if item.ProfileID == profileID {
			lab = item
			break
		}
	}

	switch {
	case lab.ProfileID == "":
		return reservationCommandResult{}, labruntime.Errorf(labruntime.CodeLabNotFound, "helper has no lab for this profile")
	case lab.Namespace != namespace:
		return reservationCommandResult{}, labruntime.Errorf(labruntime.CodeOwnershipMismatch, "helper returned a different namespace")
	case lab.State != control.LabTunnelConfigured:
		return reservationCommandResult{}, labruntime.Errorf(labruntime.CodeLabFaulted, "reservation requires a configured tunnel")
	}

	trust := control.ReservationContext{Profile: profile, Binding: binding, Runtime: rt, Helper: info, Lab: lab}

	result, err := authority.ReserveAndPrepareEgress(s.ctx, transport, keys, trust)
	if err != nil {
		return reservationCommandResult{}, reservationCommandError(err)
	}

	return reservationCommandResult{
		AuthorityID:   authority.Info().ID,
		Reservation:   result.Reservation,
		PreparedLease: result.PreparedLease,
		State:         "prepared",
	}, nil
}

// releaseEgress revokes the exact generation of one durable hold and releases its address. It needs
// the runtime that holds it, selected by the provider, and that runtime's original helper epoch, but
// no surviving profile, binding or lab: a deleted lab is no proof of retirement, nor an obstacle.
func (s *session) releaseEgress(reservationID string) (reservationReleaseCommandResult, error) {
	authority, keys, err := s.openReservationAuthority()
	if err != nil {
		return reservationReleaseCommandResult{}, err
	}

	state, err := control.LoadRuntimeState(s.dataDir)
	if err != nil {
		return reservationReleaseCommandResult{}, err
	}

	rt, exists := state.RuntimeFor(s.provider.Kind(), s.provider.Target())
	if !exists {
		return reservationReleaseCommandResult{}, labruntime.Errorf(labruntime.CodeRuntimeUntrusted,
			"selected runtime is not trusted")
	}

	result, err := authority.ReleaseEgress(s.ctx, reservationID, s.provider.Transport(), keys, rt)
	if err != nil {
		return reservationReleaseCommandResult{}, reservationCommandError(err)
	}

	return reservationReleaseCommandResult{
		AuthorityID:          authority.Info().ID,
		ReleasedEgressResult: result,
		State:                "released",
	}, nil
}
