//go:build windows || linux || darwin

package control

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"
)

// releaseFlowTransport is a trusted runtime that retires the generation without a kernel; the
// capabilities and the journal are real.
type releaseFlowTransport struct {
	fixture releaseTestFixture
	now     time.Time

	mode  string
	calls []string

	helperEdit  func(*LabHelperInfo)
	capability  LabCapability
	afterRevoke func()
}

func (f *releaseFlowTransport) clock() time.Time { return f.now }

func (f *releaseFlowTransport) HelperInfo(context.Context) (LabHelperInfo, error) {
	f.calls = append(f.calls, "helper")

	helper := f.fixture.admission.helper
	if f.helperEdit != nil {
		f.helperEdit(&helper)
	}

	return helper, nil
}

func (f *releaseFlowTransport) RevokeEgressLease(_ context.Context, profileID, namespace string,
	capability LabCapability) (LabRevokedLeaseInfo, error) {
	f.calls = append(f.calls, "revoke")
	f.capability = capability

	fixture := f.fixture
	hold := fixture.admission.hold

	expected, err := revokeIntentFromHold(fixture.authority.Info(), hold)
	if err != nil || profileID != hold.Owner.ProfileID || namespace != hold.Owner.Namespace ||
		capability.Claims.Intent != expected || !verifyIssuedLabCapability(fixture.admission.publicKey, capability) {
		return LabRevokedLeaseInfo{}, errors.New("incorrect revocation")
	}

	// The hold stays durable while the helper cleans up.
	if current, err := fixture.authority.Lookup(hold.ID); err != nil || current.ID != hold.ID {
		return LabRevokedLeaseInfo{}, errors.New("ownership released too early")
	}

	f.now = f.now.Add(40 * time.Second)

	switch f.mode {
	case "lost response":
		return LabRevokedLeaseInfo{}, errors.New("synthetic response loss")
	case "denied":
		return LabRevokedLeaseInfo{}, errors.New("AUTHORIZATION_DENIED: candidate record unavailable")
	}

	receipt := LabRevokedLeaseInfo{
		Intent:            expected,
		HelperID:          hold.Owner.HelperEpoch,
		PublicKeySHA256:   hold.PublicKeySHA256,
		RevocationNonce:   capability.Claims.Nonce,
		GenerationRetired: true,
	}

	if f.mode == "wrong receipt" {
		receipt.Intent.ReservationID = "reservation_ffffffffffffffffffffffffffffffff"
	}

	if f.afterRevoke != nil {
		f.afterRevoke()
	}

	return receipt, nil
}

func (f releaseTestFixture) releaseWith(ctx context.Context, transport *releaseFlowTransport, signer LabSigner,
	rt TrustedRuntime) (ReleasedEgressResult, error) {
	return f.authority.releaseEgressAt(ctx, f.admission.hold.ID, transport, signer, rt, transport.clock)
}

func TestReleaseFlowSuccess(t *testing.T) {
	f := newReleaseTestFixture(t)
	transport := &releaseFlowTransport{fixture: f, now: f.now}
	before := f.signer.signs

	result, err := f.releaseWith(context.Background(), transport, f.signer, f.admission.runtime)
	if err != nil {
		t.Fatal(err)
	}

	if result.Reservation.ID != f.admission.hold.ID || !result.RevokedLease.MatchesCapability(transport.capability) ||
		!result.RevokedLease.GenerationRetired || !result.ReleasedAt.Equal(transport.now) || f.signer.signs != before+1 {
		t.Fatalf("incorrect release result: %+v", result)
	}

	if !slices.Equal(transport.calls, []string{"helper", "revoke"}) {
		t.Fatalf("incorrect operation order: %v", transport.calls)
	}

	if items, err := f.authority.List(); err != nil || len(items) != 0 {
		t.Fatal("durable release not committed")
	}

	if _, err := f.releaseWith(context.Background(), transport, f.signer, f.admission.runtime); !errors.Is(err,
		ErrReservationNotFound) || len(transport.calls) != 2 || f.signer.signs != before+1 {
		t.Fatal("a released reservation reached the helper again")
	}

	if _, err := f.authority.Lookup("reservation_1"); !errors.Is(err, ErrReservationReleaseInvalid) {
		t.Fatal("malformed reservation ID looked up")
	}
}

// Every refusal before the receipt leaves the hold, and the early ones stop before the helper
// call or the signature.
func TestReleaseFlowRefusalPreservesHold(t *testing.T) {
	otherSigner := &seedSigner{private: ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x24}, ed25519.SeedSize))}

	for _, tt := range []struct {
		name    string
		runtime func(*TrustedRuntime)
		helper  func(*LabHelperInfo)
		signer  LabSigner
		mode    string
		calls   []string
		signs   int
		want    error
	}{
		{name: "foreign runtime", runtime: func(rt *TrustedRuntime) { rt.ID = "runtime_ffffffffffffffffffffffffffffffff" },
			want: ErrReservationReleaseInvalid},
		{name: "runtime key", runtime: func(rt *TrustedRuntime) { rt.PublicKeySHA256 = strings.Repeat("f", 64) },
			want: ErrReservationReleaseInvalid},
		{name: "runtime target", runtime: func(rt *TrustedRuntime) { rt.Target = "" }, want: ErrReservationReleaseInvalid},
		{name: "never trusted", runtime: func(rt *TrustedRuntime) { rt.TrustedAt = time.Time{} },
			want: ErrReservationReleaseInvalid},
		{name: "trusted in the future", runtime: func(rt *TrustedRuntime) { rt.TrustedAt = time.Now().Add(time.Hour) },
			want: ErrReservationReleaseInvalid},
		{name: "another signing key", signer: otherSigner, want: ErrReservationAuthorityMismatch},
		{name: "foreign helper", helper: func(h *LabHelperInfo) { h.HelperID = "helper_ffffffffffffffffffffffffffffffff" },
			calls: []string{"helper"}, want: ErrReservationReleaseInvalid},
		{name: "helper unconfigured", helper: func(h *LabHelperInfo) { *h = LabHelperInfo{RuntimeID: h.RuntimeID} },
			calls: []string{"helper"}, want: ErrReservationReleaseInvalid},
		{name: "helper runtime", helper: func(h *LabHelperInfo) { h.RuntimeID = "runtime_ffffffffffffffffffffffffffffffff" },
			calls: []string{"helper"}, want: ErrReservationReleaseInvalid},
		{name: "helper key", helper: func(h *LabHelperInfo) { h.PublicKeySHA256 = strings.Repeat("f", 64) },
			calls: []string{"helper"}, want: ErrReservationReleaseInvalid},
		{name: "lost response", mode: "lost response", calls: []string{"helper", "revoke"}, signs: 1,
			want: ErrLeaseRevocationUnconfirmed},
		{name: "denied", mode: "denied", calls: []string{"helper", "revoke"}, signs: 1,
			want: ErrLeaseRevocationUnconfirmed},
		{name: "wrong receipt", mode: "wrong receipt", calls: []string{"helper", "revoke"}, signs: 1,
			want: ErrLeaseRevocationUnconfirmed},
	} {
		t.Run(tt.name, func(t *testing.T) {
			f := newReleaseTestFixture(t)

			rt := f.admission.runtime
			if tt.runtime != nil {
				tt.runtime(&rt)
			}

			signer := LabSigner(f.signer)
			if tt.signer != nil {
				signer = tt.signer
			}

			transport := &releaseFlowTransport{fixture: f, now: f.now, mode: tt.mode, helperEdit: tt.helper}
			before := f.signer.signs

			result, err := f.releaseWith(context.Background(), transport, signer, rt)
			if !errors.Is(err, tt.want) || result != (ReleasedEgressResult{}) {
				t.Fatalf("invalid release outcome: %+v %v", result, err)
			}

			if !slices.Equal(transport.calls, tt.calls) || f.signer.signs != before+tt.signs {
				t.Fatalf("incorrect failure sequencing: %v, %d signatures", transport.calls, f.signer.signs-before)
			}

			if items, err := f.authority.List(); err != nil || len(items) != 1 || items[0].ID != f.admission.hold.ID {
				t.Fatal("a refusal lost durable ownership")
			}

			if tt.mode == "denied" && !strings.Contains(err.Error(), "AUTHORIZATION_DENIED") {
				t.Fatalf("the helper's refusal is not visible: %v", err)
			}

			if tt.signs == 1 && !strings.Contains(err.Error(), "keep the helper running") {
				t.Fatalf("no recovery advice after the revocation was sent: %v", err)
			}
		})
	}
}

// The helper retired the generation, the controller was canceled before the commit: the address
// stays held, and a newly approved release confirms the retirement.
func TestReleaseFlowCanceledAfterRetirement(t *testing.T) {
	f := newReleaseTestFixture(t)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	transport := &releaseFlowTransport{fixture: f, now: f.now, afterRevoke: cancel}

	_, err := f.releaseWith(ctx, transport, f.signer, f.admission.runtime)
	if !errors.Is(err, ErrReservationReleaseUnconfirmed) || !errors.Is(err, context.Canceled) {
		t.Fatalf("incorrect cancellation result: %v", err)
	}

	if items, err := f.authority.List(); err != nil || len(items) != 1 {
		t.Fatal("a canceled release lost ownership")
	}

	again := &releaseFlowTransport{fixture: f, now: transport.now.Add(time.Second)}
	if _, err := f.releaseWith(context.Background(), again, f.signer, f.admission.runtime); err != nil {
		t.Fatalf("confirmation after the cancellation: %v", err)
	}

	if again.capability.Claims.Nonce == transport.capability.Claims.Nonce {
		t.Fatal("the confirmation reused the earlier capability")
	}
}

// The cleanup holds no journal lock, so another transaction may hold it when the receipt arrives:
// no waiting, no retry, the hold stays.
func TestReleaseFlowBusyAfterRetirement(t *testing.T) {
	f := newReleaseTestFixture(t)

	var handle reservationJournalHandle

	transport := &releaseFlowTransport{fixture: f, now: f.now, afterRevoke: func() {
		var err error

		handle, err = f.journal.open()
		if err != nil {
			t.Fatal(err)
		}
	}}

	_, err := f.releaseWith(context.Background(), transport, f.signer, f.admission.runtime)
	if !errors.Is(err, ErrReservationReleaseUnconfirmed) || !errors.Is(err, ErrReservationBusy) ||
		!strings.Contains(err.Error(), "keep the helper running") {
		t.Fatalf("incorrect lock contention: %v", err)
	}

	if err := handle.Close(); err != nil {
		t.Fatal(err)
	}

	if items, err := f.authority.List(); err != nil || len(items) != 1 || items[0].ID != f.admission.hold.ID {
		t.Fatal("a busy journal lost ownership")
	}
}

// Another process released the same hold while this one waited for its helper.
func TestReleaseFlowReleasedMeanwhile(t *testing.T) {
	f := newReleaseTestFixture(t)
	before := f.journalBytes(t)

	transport := &releaseFlowTransport{fixture: f, now: f.now}
	transport.afterRevoke = func() {
		if _, err := f.release(); err != nil {
			t.Fatal(err)
		}
	}

	_, err := f.releaseWith(context.Background(), transport, f.signer, f.admission.runtime)
	if !errors.Is(err, ErrReservationReleaseUnconfirmed) || !errors.Is(err, ErrReservationNotFound) {
		t.Fatalf("a second release committed: %v", err)
	}

	state, err := parseReservationJournalRecords(f.journalBytes(t), f.journal.header, f.journal.authority)
	if err != nil || len(state.registry.snapshot()) != 0 || len(f.journalBytes(t)) <= len(before) {
		t.Fatalf("unexpected journal after the concurrent release: %v", err)
	}
}

func TestReleaseFlowArguments(t *testing.T) {
	f := newReleaseTestFixture(t)
	transport := &releaseFlowTransport{fixture: f, now: f.now}

	if _, err := f.authority.releaseEgressAt(context.Background(), f.admission.hold.ID, nil, f.signer,
		f.admission.runtime, transport.clock); !errors.Is(err, ErrReservationUnavailable) {
		t.Fatal("release without a transport")
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	if _, err := f.releaseWith(ctx, transport, f.signer, f.admission.runtime); !errors.Is(err, context.Canceled) ||
		len(transport.calls) != 0 {
		t.Fatal("a canceled release reached the helper")
	}

	// The controller's clock stepped back before the hold was made.
	early := &releaseFlowTransport{fixture: f, now: f.admission.hold.ReservedAt.Add(-time.Second)}
	if _, err := f.releaseWith(context.Background(), early, f.signer, f.admission.runtime); !errors.Is(err,
		ErrReservationReleaseInvalid) || len(early.calls) != 1 {
		t.Fatalf("a revocation minted before the hold: %v %v", err, early.calls)
	}
}

// A slow key store: the capability expired between its signature and its submission.
func TestReleaseFlowExpiredBeforeSubmission(t *testing.T) {
	f := newReleaseTestFixture(t)
	transport := &releaseFlowTransport{fixture: f, now: f.now}

	readings := 0
	clock := func() time.Time {
		readings++
		if readings >= 3 {
			return f.now.Add(31 * time.Second)
		}

		return f.now
	}

	before := f.signer.signs

	if _, err := f.authority.releaseEgressAt(context.Background(), f.admission.hold.ID, transport, f.signer,
		f.admission.runtime, clock); !errors.Is(err, ErrReservationReleaseInvalid) ||
		!slices.Equal(transport.calls, []string{"helper"}) || f.signer.signs != before+1 {
		t.Fatalf("an expired revocation was sent: %v %v", err, transport.calls)
	}

	if items, err := f.authority.List(); err != nil || len(items) != 1 {
		t.Fatal("the hold was lost")
	}
}
