//go:build windows || linux || darwin

package control

import (
	"context"
	"errors"
	"slices"
	"testing"
	"time"
)

// preparationFlowTransport extends the reservation fake with a preparation that requires the
// durable record and checks the real signature and exact binding.
type preparationFlowTransport struct {
	*reservationFlowTransport

	authority *ReservationAuthority
	candidate LabCandidateInfo

	prepareMode string
}

func (f *preparationFlowTransport) ReserveEgressCandidate(ctx context.Context, profileID, namespace string,
	capability LabCapability) (LabCandidateInfo, error) {
	receipt, err := f.reservationFlowTransport.ReserveEgressCandidate(ctx, profileID, namespace, capability)
	if err == nil {
		f.candidate = receipt
	}

	return receipt, err
}

func (f *preparationFlowTransport) PrepareEgressLease(_ context.Context, profileID, namespace string,
	capability LabCapability) (LabPreparedLeaseInfo, error) {
	f.calls = append(f.calls, "prepare")

	items, err := f.authority.List()
	if err != nil {
		return LabPreparedLeaseInfo{}, err
	}

	var hold EgressReservation
	for _, item := range items {
		if item.ID == capability.Claims.Intent.ReservationID {
			hold = item
		}
	}

	if hold.ID == "" {
		return LabPreparedLeaseInfo{}, errors.New("preparation before the durable commit")
	}

	receipt := LabPreparedLeaseInfo{
		LabCandidateInfo: f.candidate,
		AuthorityID:      f.authority.Info().ID,
		ReservationID:    hold.ID,
		PreparationNonce: capability.Claims.Nonce,
	}

	if profileID != hold.Owner.ProfileID || namespace != hold.Owner.Namespace || !receipt.MatchesCapability(capability) ||
		!receipt.matchesReservation(f.authority.Info(), hold) || !verifyIssuedLabCapability(f.fixture.publicKey, capability) {
		return LabPreparedLeaseInfo{}, errTestReservationTransport
	}

	switch f.prepareMode {
	case "refused":
		return LabPreparedLeaseInfo{}, errTestReservationTransport
	case "wrong reservation":
		receipt.ReservationID = "reservation_ffffffffffffffffffffffffffffffff"
	case "wrong preparation nonce":
		receipt.PreparationNonce = "ffffffffffffffffffffffffffffffff"
	case "wrong fingerprint":
		receipt.PublicKeySHA256 = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
	case "changed deadline":
		receipt.ExpiresAt = receipt.ExpiresAt.Add(-time.Second)
	case "expired response":
		f.now = hold.EligibleUntil
	}

	return receipt, nil
}

func newPreparationFlowFixture(t *testing.T, number int, ip string) (*preparationFlowTransport, ReservationContext, *seedSigner) {
	t.Helper()

	base, trust, signer := newReservationFlowFixture(t, number, ip)
	dir := t.TempDir()

	if _, err := InitializeReservationAuthority(dir, signer); err != nil {
		t.Fatal(err)
	}

	authority, err := OpenReservationAuthority(dir, signer)
	if err != nil {
		t.Fatal(err)
	}

	return &preparationFlowTransport{reservationFlowTransport: base, authority: authority}, trust, signer
}

// preparationGateSigner runs a check right before the third signature, the preparation's.
type preparationGateSigner struct {
	*seedSigner
	beforeThirdSignature func() error
}

func (s *preparationGateSigner) Sign(message []byte) ([]byte, error) {
	if s.signs == 2 {
		if err := s.beforeThirdSignature(); err != nil {
			return nil, err
		}
	}

	return s.seedSigner.Sign(message)
}

func TestPreparedLeaseFlowSuccess(t *testing.T) {
	transport, trust, signer := newPreparationFlowFixture(t, 1, "8.8.4.4")
	checked := false

	gated := &preparationGateSigner{seedSigner: signer, beforeThirdSignature: func() error {
		items, err := transport.authority.List()
		if err != nil {
			return err
		}

		if len(items) != 1 || items[0].IPv4.String() != "8.8.4.4" || !items[0].recovered {
			return errors.New("preparation signed before the durable commit")
		}

		checked = true

		return nil
	}}

	result, err := transport.authority.reserveAndPrepareEgressAt(context.Background(), transport, gated, trust, transport.clock)
	if err != nil {
		t.Fatal(err)
	}

	if !checked || signer.signs != 3 {
		t.Fatal("the durable signing gate was not checked")
	}

	if !slices.Equal(transport.calls, []string{"target", "probe", "candidate", "prepare"}) {
		t.Fatalf("wrong operation order: %v", transport.calls)
	}

	if !result.PreparedLease.matchesReservation(transport.authority.Info(), result.Reservation) {
		t.Fatal("prepared lease and hold disagree")
	}
}

func TestPreparedLeaseFlowCollision(t *testing.T) {
	a, trustA, signerA := newPreparationFlowFixture(t, 1, "8.8.4.4")
	b, trustB, signerB := newPreparationFlowFixture(t, 2, "8.8.4.4")

	// Both runtimes use one authority.
	b.authority = a.authority

	first, err := a.authority.reserveAndPrepareEgressAt(context.Background(), a, signerA, trustA, a.clock)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := b.authority.reserveAndPrepareEgressAt(context.Background(), b, signerB, trustB, b.clock); !errors.Is(err, ErrReservationIPCollision) {
		t.Fatalf("duplicate IP admitted: %v", err)
	}

	if signerA.signs != 3 || signerB.signs != 2 || !slices.Equal(b.calls, []string{"target", "probe", "candidate"}) {
		t.Fatal("the collision reached preparation")
	}

	if items, err := a.authority.List(); err != nil || len(items) != 1 || items[0].ID != first.Reservation.ID {
		t.Fatal("the original hold was lost")
	}
}

func TestPreparedLeaseFlowRetainsHoldOnFailure(t *testing.T) {
	for _, mode := range []string{"refused", "wrong reservation", "wrong preparation nonce", "wrong fingerprint",
		"changed deadline", "expired response"} {
		t.Run(mode, func(t *testing.T) {
			transport, trust, signer := newPreparationFlowFixture(t, 1, "8.8.4.4")
			transport.prepareMode = mode

			result, err := transport.authority.reserveAndPrepareEgressAt(context.Background(), transport, signer, trust,
				transport.clock)
			if !errors.Is(err, ErrLeasePreparationUnconfirmed) || result != (PreparedEgressResult{}) {
				t.Fatalf("invalid post-commit outcome: %+v %v", result, err)
			}

			if items, err := transport.authority.List(); err != nil || len(items) != 1 || items[0].IPv4.String() != "8.8.4.4" {
				t.Fatal("a preparation failure released ownership")
			}

			if signer.signs != 3 {
				t.Fatal("the preparation was retried")
			}
		})
	}
}

// Only the live hold of this operation, also present in the journal, authorizes a signature.
func TestPreparedLeaseSigningGate(t *testing.T) {
	transport, trust, signer := newPreparationFlowFixture(t, 1, "8.8.4.4")
	a := transport.authority

	journal, err := a.journal()
	if err != nil {
		t.Fatal(err)
	}

	// Fresh, but held only in an in-memory registry, not in this authority's journal.
	hold := testJournalHold(t, 1, 1, 1, "8.8.4.4")
	if _, err := mintPreparedLeaseAfterCommit(journal, hold, signer, trust, reservationTestBase.Add(11*time.Second)); err == nil ||
		signer.signs != 0 {
		t.Fatal("an uncommitted hold authorized signing")
	}

	live, err := reserveVerifiedEgressJournalAt(context.Background(), journal, transport, signer, trust, transport.clock)
	if err != nil {
		t.Fatal(err)
	}

	items, err := a.List()
	if err != nil || len(items) != 1 || items[0].ID != live.ID {
		t.Fatal("missing durable hold")
	}

	before := signer.signs

	if _, err := mintPreparedLeaseAfterCommit(journal, items[0], signer, trust, transport.clock()); err == nil ||
		signer.signs != before {
		t.Fatal("a recovered hold authorized signing")
	}

	// The live hold is accepted only while its record is unchanged in the journal.
	tampered := live
	tampered.ReservationNonce = "ffffffffffffffffffffffffffffffff"

	if _, err := mintPreparedLeaseAfterCommit(journal, tampered, signer, trust, transport.clock()); !errors.Is(err, ErrReservationAuthorityMismatch) ||
		signer.signs != before {
		t.Fatalf("a hold that disagrees with its record authorized signing: %v", err)
	}

	if _, err := mintPreparedLeaseAfterCommit(journal, live, signer, trust, transport.clock()); err != nil || signer.signs != before+1 {
		t.Fatalf("the live committed hold was refused: %v", err)
	}
}

func TestPreparedLeaseSigningFailure(t *testing.T) {
	transport, trust, signer := newPreparationFlowFixture(t, 1, "8.8.4.4")

	gated := &preparationGateSigner{seedSigner: signer, beforeThirdSignature: func() error {
		return errors.New("key store unavailable")
	}}

	_, err := transport.authority.reserveAndPrepareEgressAt(context.Background(), transport, gated, trust, transport.clock)
	if !errors.Is(err, ErrLeasePreparationUnconfirmed) {
		t.Fatalf("incorrect signing failure: %v", err)
	}

	if !slices.Equal(transport.calls, []string{"target", "probe", "candidate"}) {
		t.Fatal("a failed signature reached the helper")
	}

	if items, err := transport.authority.List(); err != nil || len(items) != 1 {
		t.Fatal("a signing failure lost the durable hold")
	}
}

// Less than labPreparationBudget of eligibility left: nothing is signed or sent, since the helper
// would fault the lab if the deadline passed during its verification.
func TestPreparedLeaseFlowBudget(t *testing.T) {
	transport, trust, signer := newPreparationFlowFixture(t, 1, "8.8.4.4")

	// The reservation reads the clock 12 times; call 13 is the preparation's mint time. The
	// fixture's hold is eligible until base+55 s.
	late := reservationTestBase.Add(52 * time.Second)
	calls := 0
	clock := func() time.Time {
		calls++
		if calls >= 13 {
			return late
		}

		return transport.clock()
	}

	_, err := transport.authority.reserveAndPrepareEgressAt(context.Background(), transport, signer, trust, clock)
	if !errors.Is(err, ErrLeasePreparationUnconfirmed) || !errors.Is(err, ErrReservationCandidateExpired) {
		t.Fatalf("late preparation: %v", err)
	}

	if signer.signs != 2 || slices.Contains(transport.calls, "prepare") {
		t.Fatalf("a late preparation was signed or sent: %d %v", signer.signs, transport.calls)
	}

	if items, err := transport.authority.List(); err != nil || len(items) != 1 {
		t.Fatal("the late preparation lost the hold")
	}
}
