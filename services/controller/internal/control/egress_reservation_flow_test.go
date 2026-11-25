//go:build windows || linux || darwin

package control

import (
	"context"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

var errTestReservationTransport = errors.New("synthetic transport failure")

// reservationFlowTransport returns synthetic observations, but checks the real Ed25519 signatures
// and the exact signed intents it receives.
type reservationFlowTransport struct {
	fixture candidateAdmission
	now     time.Time

	mode  string
	calls []string

	probe             LabMultiProbeInfo
	probeCapability   LabCapability
	reserveCapability LabCapability
}

func (f *reservationFlowTransport) clock() time.Time {
	return f.now
}

func (f *reservationFlowTransport) MultiProbeTarget(_ context.Context, profileID, namespace string) (LabMultiProbeTarget, error) {
	f.calls = append(f.calls, "target")

	target := f.fixture.target
	if target.ProfileID != profileID || target.Namespace != namespace {
		return LabMultiProbeTarget{}, errTestReservationTransport
	}

	if f.mode == "foreign target" {
		target.HelperID = "helper_ffffffffffffffffffffffffffffffff"
	}

	return target, nil
}

func (f *reservationFlowTransport) ProbeEgressMulti(_ context.Context, profileID, namespace string,
	capability LabCapability) (LabMultiProbeInfo, error) {
	f.calls = append(f.calls, "probe")
	f.probeCapability = capability

	target := f.fixture.target

	expected, err := NewLabGenerationProbeIntent(profileID, namespace, target.IdentIPv4, target.TunnelGeneration)
	if err != nil || capability.Claims.Intent != expected || !verifyIssuedLabCapability(f.fixture.publicKey, capability) {
		return LabMultiProbeInfo{}, errTestReservationTransport
	}

	if f.mode == "probe failure" {
		return LabMultiProbeInfo{}, errTestReservationTransport
	}

	probe := f.fixture.probe
	probe.AttemptNonce = capability.Claims.Nonce
	f.now = f.fixture.probeReceivedAt

	switch f.mode {
	case "wrong probe generation":
		probe.TunnelGeneration = "tunnelgen_ffffffffffffffffffffffffffffffff"
	case "probe too old":
		f.now = f.fixture.probeSentAt.Add(59 * time.Second)
	case "late probe":
		f.now = f.fixture.probeSentAt.Add(40 * time.Second)
	case "live":
		now := time.Now().UTC()
		probe.StartedAt, probe.FinishedAt, probe.ObservedAt, probe.HandshakeAt = now, now, now, now.Add(-time.Second)
		probe.Sources = slices.Clone(probe.Sources)
		for i := range probe.Sources {
			probe.Sources[i].ObservedAt = now
		}
	}

	f.probe = probe

	return probe, nil
}

func (f *reservationFlowTransport) ReserveEgressCandidate(_ context.Context, profileID, namespace string,
	capability LabCapability) (LabCandidateInfo, error) {
	f.calls = append(f.calls, "candidate")
	f.reserveCapability = capability

	target := f.fixture.target

	expected, err := NewLabReserveEgressCandidateIntent(profileID, namespace, target.IdentIPv4, target.TunnelGeneration,
		f.probeCapability.Claims.Nonce)
	if err != nil || capability.Claims.Intent != expected || capability.Claims.Nonce == f.probeCapability.Claims.Nonce ||
		!verifyIssuedLabCapability(f.fixture.publicKey, capability) {
		return LabCandidateInfo{}, errTestReservationTransport
	}

	if f.mode == "candidate failure" {
		return LabCandidateInfo{}, errTestReservationTransport
	}

	receipt := f.fixture.receipt
	receipt.EvidenceNonce = f.probeCapability.Claims.Nonce
	receipt.ReservationNonce = capability.Claims.Nonce
	f.now = f.fixture.reserveReceivedAt

	switch f.mode {
	case "live":
		receipt.ObservedAt = f.probe.ObservedAt
		receipt.ExpiresAt = f.probe.ObservedAt.Add(labGenerationProbeFreshness)
	case "wrong receipt IP":
		receipt.IPv4 = netip.MustParseAddr("8.8.8.8")
	case "wrong receipt nonce":
		receipt.ReservationNonce = "ffffffffffffffffffffffffffffffff"
	case "expired receipt":
		f.now = receipt.ExpiresAt
	}

	return receipt, nil
}

func newReservationFlowFixture(t *testing.T, number int, ip string) (*reservationFlowTransport, ReservationContext, *seedSigner) {
	t.Helper()

	base := reservationTestBase
	admission := testReservationAdmission(t, number, number, number, ip, base)

	transport := &reservationFlowTransport{fixture: admission, now: base}
	trust := ReservationContext{
		Profile: admission.profile,
		Binding: admission.binding,
		Runtime: admission.runtime,
		Helper:  admission.helper,
		Lab:     admission.lab,
	}

	signer := newSeedSigner()

	public, err := signer.PublicKey()
	if err != nil || LabPublicKeySHA256(public) != trust.Runtime.PublicKeySHA256 {
		t.Fatal("fixture signing key mismatch")
	}

	return transport, trust, signer
}

func TestReservationFlowSuccess(t *testing.T) {
	dir := newTestReservationJournal(t)
	transport, trust, signer := newReservationFlowFixture(t, 1, "8.8.4.4")

	hold, err := reserveVerifiedEgressAt(context.Background(), dir, transport, signer, trust, transport.clock)
	if err != nil {
		t.Fatal(err)
	}

	if !slices.Equal(transport.calls, []string{"target", "probe", "candidate"}) {
		t.Fatalf("unexpected operation sequence: %v", transport.calls)
	}

	if signer.signs != 2 {
		t.Fatalf("signed %d operations, want 2", signer.signs)
	}

	if hold.IPv4.String() != "8.8.4.4" ||
		hold.Owner.ProfileID != trust.Profile.ID ||
		hold.Owner.RuntimeID != trust.Runtime.ID ||
		hold.Owner.HelperEpoch != trust.Helper.HelperID ||
		hold.Owner.Namespace != trust.Binding.Namespace ||
		hold.Owner.TunnelGeneration != transport.fixture.target.TunnelGeneration ||
		hold.EvidenceNonce != transport.probeCapability.Claims.Nonce ||
		hold.ReservationNonce != transport.reserveCapability.Claims.Nonce ||
		!hold.FreshAt(transport.clock()) {
		t.Fatalf("incorrect reservation: %+v", hold)
	}

	items, err := inspectReservationJournal(dir)
	if err != nil || len(items) != 1 || items[0].ID != hold.ID || !items[0].recovered || items[0].FreshAt(transport.clock()) {
		t.Fatalf("incorrect persistent ownership: %v", err)
	}
}

func TestReservationFlowFailureStops(t *testing.T) {
	through := func(n int) []string { return []string{"target", "probe", "candidate"}[:n] }

	for _, tt := range []struct {
		mode  string
		calls []string
		want  error
	}{
		{"foreign target", through(1), ErrReservationCandidateInvalid},
		{"probe failure", through(2), errTestReservationTransport},
		{"wrong probe generation", through(2), ErrReservationCandidateInvalid},
		{"probe too old", through(2), ErrReservationCandidateExpired},
		{"candidate failure", through(3), errTestReservationTransport},
		{"wrong receipt IP", through(3), ErrReservationCandidateInvalid},
		{"wrong receipt nonce", through(3), ErrReservationCandidateInvalid},
		{"expired receipt", through(3), ErrReservationCandidateExpired},
	} {
		t.Run(tt.mode, func(t *testing.T) {
			dir := newTestReservationJournal(t)
			transport, trust, signer := newReservationFlowFixture(t, 1, "8.8.4.4")
			transport.mode = tt.mode

			hold, err := reserveVerifiedEgressAt(context.Background(), dir, transport, signer, trust, transport.clock)
			if !errors.Is(err, tt.want) || hold != (EgressReservation{}) {
				t.Fatalf("unexpected result: %+v %v", hold, err)
			}

			if !slices.Equal(transport.calls, tt.calls) {
				t.Fatalf("operation continued after the failure: %v", transport.calls)
			}

			if items, err := inspectReservationJournal(dir); err != nil || len(items) != 0 {
				t.Fatal("failed flow created durable ownership")
			}
		})
	}
}

func TestReservationFlowCollision(t *testing.T) {
	dir := newTestReservationJournal(t)
	a, trustA, signerA := newReservationFlowFixture(t, 1, "8.8.4.4")
	b, trustB, signerB := newReservationFlowFixture(t, 2, "8.8.4.4")

	first, err := reserveVerifiedEgressAt(context.Background(), dir, a, signerA, trustA, a.clock)
	if err != nil {
		t.Fatal(err)
	}

	second, err := reserveVerifiedEgressAt(context.Background(), dir, b, signerB, trustB, b.clock)
	if !errors.Is(err, ErrReservationIPCollision) || second != (EgressReservation{}) {
		t.Fatalf("duplicate public IPv4 allocated: %v", err)
	}

	// Both runtimes got a local candidate; only the shared authority grants ownership.
	if !slices.Equal(b.calls, []string{"target", "probe", "candidate"}) {
		t.Fatalf("incorrect collision flow: %v", b.calls)
	}

	items, err := inspectReservationJournal(dir)
	if err != nil || len(items) != 1 || items[0].ID != first.ID || items[0].Owner.RuntimeID != trustA.Runtime.ID {
		t.Fatal("collision replaced the original hold")
	}
}

func TestReservationFlowPreflight(t *testing.T) {
	refusedBeforeRuntime := func(t *testing.T, dir string, want error) {
		t.Helper()

		transport, trust, signer := newReservationFlowFixture(t, 1, "8.8.4.4")

		_, err := reserveVerifiedEgressAt(context.Background(), dir, transport, signer, trust, transport.clock)
		if !errors.Is(err, want) || len(transport.calls) != 0 || signer.signs != 0 {
			t.Fatalf("refusal after a runtime call or signature: %v %v %d", err, transport.calls, signer.signs)
		}
	}

	t.Run("missing journal", func(t *testing.T) {
		refusedBeforeRuntime(t, t.TempDir(), ErrReservationUnavailable)
	})

	t.Run("corrupt journal", func(t *testing.T) {
		dir := newTestReservationJournal(t)
		if err := os.WriteFile(filepath.Join(dir, reservationJournalFile), []byte("damaged"), 0o600); err != nil {
			t.Fatal(err)
		}

		refusedBeforeRuntime(t, dir, ErrReservationJournalCorrupt)
	})

	t.Run("busy authority", func(t *testing.T) {
		dir := newTestReservationJournal(t)

		file, err := openLockedReservationJournal(filepath.Join(dir, reservationJournalFile), false)
		if err != nil {
			t.Fatal(err)
		}
		defer file.Close()

		refusedBeforeRuntime(t, dir, ErrReservationBusy)
	})

	t.Run("existing profile", func(t *testing.T) {
		dir := newTestReservationJournal(t)
		first, trust, signer := newReservationFlowFixture(t, 1, "8.8.4.4")

		if _, err := reserveVerifiedEgressAt(context.Background(), dir, first, signer, trust, first.clock); err != nil {
			t.Fatal(err)
		}

		next, nextTrust, nextSigner := newReservationFlowFixture(t, 1, "8.8.8.8")

		_, err := reserveVerifiedEgressAt(context.Background(), dir, next, nextSigner, nextTrust, next.clock)
		if !errors.Is(err, ErrReservationProfileHeld) || len(next.calls) != 0 || nextSigner.signs != 0 {
			t.Fatal("a profile with a hold started another flow")
		}
	})
}

func TestReservationFlowCanceled(t *testing.T) {
	dir := newTestReservationJournal(t)
	transport, trust, signer := newReservationFlowFixture(t, 1, "8.8.4.4")

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	hold, err := reserveVerifiedEgressAt(ctx, dir, transport, signer, trust, transport.clock)
	if !errors.Is(err, context.Canceled) || hold != (EgressReservation{}) || len(transport.calls) != 0 || signer.signs != 0 {
		t.Fatal("canceled flow performed an operation")
	}
}

// Cancellation before the append leaves nothing durable; after the commit neither cancellation nor
// expiry releases the hold, and neither returns a usable grant.
func TestReservationFlowCommitBoundary(t *testing.T) {
	// The flow reads the clock 7 times before the commit and 4 times inside it (two in reserve,
	// before the append, after the flush); call 12 is its own freshness check afterwards.
	for _, tt := range []struct {
		name      string
		call      int
		cancel    bool
		want      error
		uncertain bool
		holds     int
	}{
		{"canceled before the append", 10, true, context.Canceled, false, 0},
		{"canceled after the flush", 11, true, context.Canceled, true, 1},
		{"expired after the commit", 12, false, ErrReservationCommittedExpired, false, 1},
	} {
		t.Run(tt.name, func(t *testing.T) {
			dir := newTestReservationJournal(t)
			transport, trust, signer := newReservationFlowFixture(t, 1, "8.8.4.4")

			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			calls := 0
			clock := func() time.Time {
				calls++
				if calls == tt.call {
					if tt.cancel {
						cancel()
					} else {
						return transport.fixture.probeSentAt.Add(55 * time.Second)
					}
				}

				return transport.clock()
			}

			hold, err := reserveVerifiedEgressAt(ctx, dir, transport, signer, trust, clock)
			if !errors.Is(err, tt.want) || errors.Is(err, ErrReservationStateUncertain) != tt.uncertain ||
				hold != (EgressReservation{}) {
				t.Fatalf("unexpected result: %+v %v", hold, err)
			}

			if items, err := inspectReservationJournal(dir); err != nil || len(items) != tt.holds {
				t.Fatalf("durable holds: %d %v", len(items), err)
			}
		})
	}
}

// slowSigner models a slow key store (DPAPI, Keychain): signing advances the fake clock.
type slowSigner struct {
	*seedSigner
	onSign func(signs int)
}

func (s *slowSigner) Sign(message []byte) ([]byte, error) {
	signature, err := s.seedSigner.Sign(message)
	s.onSign(s.signs)

	return signature, err
}

// A candidate request signed too slowly is not submitted: the helper would consume the evidence for
// a reservation that can no longer be admitted.
func TestReservationFlowSlowCandidateSigning(t *testing.T) {
	dir := newTestReservationJournal(t)
	transport, trust, seed := newReservationFlowFixture(t, 1, "8.8.4.4")
	transport.mode = "late probe"

	signer := &slowSigner{seedSigner: seed, onSign: func(signs int) {
		if signs == 2 {
			transport.now = transport.fixture.probe.ObservedAt.Add(labGenerationProbeFreshness - labProbeClockSkew)
		}
	}}

	_, err := reserveVerifiedEgressAt(context.Background(), dir, transport, signer, trust, transport.clock)
	if !errors.Is(err, ErrReservationCandidateExpired) || !slices.Equal(transport.calls, []string{"target", "probe"}) {
		t.Fatalf("late candidate request submitted: %v %v", err, transport.calls)
	}
}

// The production entry point on the real clock, through a provisioned authority, with observations
// stamped at call time.
func TestReserveVerifiedEgressRealClock(t *testing.T) {
	dir := t.TempDir()
	transport, trust, signer := newReservationFlowFixture(t, 1, "8.8.4.4")
	transport.mode = "live"

	if _, err := InitializeReservationAuthority(dir, signer); err != nil {
		t.Fatal(err)
	}

	authority, err := OpenReservationAuthority(dir, signer)
	if err != nil {
		t.Fatal(err)
	}

	hold, err := authority.ReserveVerifiedEgress(context.Background(), transport, signer, trust)
	if err != nil || !hold.FreshAt(time.Now()) || hold.IPv4.String() != "8.8.4.4" {
		t.Fatalf("real-clock reservation: %+v %v", hold, err)
	}

	if items, err := authority.List(); err != nil || len(items) != 1 || items[0].ID != hold.ID {
		t.Fatalf("durable hold: %v", err)
	}
}

func TestReservationCapabilitySendValid(t *testing.T) {
	base := reservationTestBase
	capability := LabCapability{Claims: LabClaims{Version: 1, IssuedAt: base.Unix(), NotAfter: base.Unix() + 30}}

	for name, tt := range map[string]struct {
		claims       func(*LabClaims)
		minted, sent time.Time
		want         bool
	}{
		"at once":             {nil, base, base, true},
		"before not_after":    {nil, base, base.Add(29 * time.Second), true},
		"at not_after":        {nil, base, base.Add(30 * time.Second), false},
		"sent before minting": {nil, base.Add(time.Second), base, false},
		"other mint second":   {nil, base.Add(time.Second), base.Add(time.Second), false},
		"version 2":           {func(c *LabClaims) { c.Version = 2 }, base, base, false},
		"31 s lifetime":       {func(c *LabClaims) { c.NotAfter++ }, base, base, false},
	} {
		c := capability
		if tt.claims != nil {
			tt.claims(&c.Claims)
		}

		if got := reservationCapabilitySendValid(c, tt.minted, tt.sent); got != tt.want {
			t.Errorf("%s: %v", name, got)
		}
	}
}

// A trust context that does not agree with itself is refused before the journal, the runtime or
// the signer is touched.
func TestReservationFlowRejectsTrustContext(t *testing.T) {
	for name, mutate := range map[string]func(*ReservationContext){
		"runtime trusted later":       func(c *ReservationContext) { c.Runtime.TrustedAt = reservationTestBase.Add(time.Hour) },
		"runtime never trusted":       func(c *ReservationContext) { c.Runtime.TrustedAt = time.Time{} },
		"other runtime":               func(c *ReservationContext) { c.Runtime.ID = "runtime_ffffffffffffffffffffffffffffffff" },
		"other runtime key":           func(c *ReservationContext) { c.Runtime.PublicKeySHA256 = strings.Repeat("f", 64) },
		"unknown provider":            func(c *ReservationContext) { c.Runtime.Provider = "docker" },
		"helper not authorized":       func(c *ReservationContext) { c.Helper.AuthorizationConfigured = false },
		"sealed lab":                  func(c *ReservationContext) { c.Lab.State = LabSealed },
		"stale binding":               func(c *ReservationContext) { c.Binding.HelperEpoch = "helper_ffffffffffffffffffffffffffffffff" },
		"profile without kill-switch": func(c *ReservationContext) { c.Profile.KillSwitchRequired = false },
	} {
		t.Run(name, func(t *testing.T) {
			dir := newTestReservationJournal(t)
			transport, trust, signer := newReservationFlowFixture(t, 1, "8.8.4.4")
			mutate(&trust)

			_, err := reserveVerifiedEgressAt(context.Background(), dir, transport, signer, trust, transport.clock)
			if !errors.Is(err, ErrReservationCandidateInvalid) || len(transport.calls) != 0 || signer.signs != 0 {
				t.Fatalf("got %v after %v and %d signatures", err, transport.calls, signer.signs)
			}
		})
	}
}
