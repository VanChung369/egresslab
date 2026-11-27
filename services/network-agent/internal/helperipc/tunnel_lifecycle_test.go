package helperipc

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/VanChung369/egresslab/services/network-agent/internal/helperauth"
)

const (
	tunnelTestStage   = "wgstage_0123456789abcdef0123456789abcdef"
	tunnelTestProfile = "profile_fedcba9876543210"
)

type fakeTunnelBackend struct {
	connects int
	verifies int
	cleanups int

	connectErr error
	verifyErr  error
	cleanupErr error
}

func (f *fakeTunnelBackend) ConnectStage(context.Context, string, string, string) error {
	f.connects++
	return f.connectErr
}

func (f *fakeTunnelBackend) VerifyConfigured(context.Context, string) error {
	f.verifies++
	return f.verifyErr
}

func (f *fakeTunnelBackend) CleanupStage(context.Context, string) error {
	f.cleanups++
	return f.cleanupErr
}

type tunnelFixture struct {
	labs     *LabLifecycle
	backend  *fakeLifecycleBackend
	tunnels  *fakeTunnelBackend
	verifier *helperauth.Verifier
	lab      LabInfo
	mint     func(helperauth.Intent) Request
	mintAt   func(helperauth.Intent, time.Time) Request
}

func newTunnelFixture(t *testing.T) *tunnelFixture {
	t.Helper()

	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	id, err := helperauth.NewHelperID()
	if err != nil {
		t.Fatal(err)
	}

	v, err := helperauth.NewVerifier(public, id)
	if err != nil {
		t.Fatal(err)
	}

	mintAt := func(intent helperauth.Intent, issuedAt time.Time) Request {
		t.Helper()

		claims, err := helperauth.NewClaims(intent, id, issuedAt)
		if err != nil {
			t.Fatal(err)
		}

		token, err := helperauth.Mint(private, claims)
		if err != nil {
			t.Fatal(err)
		}

		return Request{Version: Version, Operation: intent.Operation, Intent: &intent, Capability: &token}
	}

	mint := func(intent helperauth.Intent) Request {
		t.Helper()
		return mintAt(intent, time.Now())
	}

	f := &tunnelFixture{
		backend:  &fakeLifecycleBackend{},
		tunnels:  &fakeTunnelBackend{},
		verifier: v,
		mint:     mint,
		mintAt:   mintAt,
	}
	f.labs = NewTunnelLifecycle(f.backend, f.tunnels)
	f.lab = f.createLab(t, lifecycleProfile)

	return f
}

func (f *tunnelFixture) createLab(t *testing.T, profileID string) LabInfo {
	t.Helper()

	lab, err := f.execute(f.mint(helperauth.Intent{Operation: helperauth.OpCreateLab, ProfileID: profileID}))
	if err != nil {
		t.Fatal(err)
	}

	return lab
}

func (f *tunnelFixture) connectRequest() Request {
	return f.connectRequestFor(f.lab)
}

func (f *tunnelFixture) connectRequestFor(lab LabInfo) Request {
	return f.mint(helperauth.Intent{
		Operation: helperauth.OpConnectTunnel,
		ProfileID: lab.ProfileID,
		Namespace: lab.Namespace,
		StageID:   tunnelTestStage,
	})
}

func (f *tunnelFixture) execute(req Request) (LabInfo, error) {
	return f.labs.execute(context.Background(), req, f.verifier)
}

func TestSignedTunnelLifecycle(t *testing.T) {
	f := newTunnelFixture(t)
	req := f.connectRequest()

	unsigned := req
	unsigned.Capability = nil

	if _, err := f.execute(unsigned); !errors.Is(err, errLabAuthorization) {
		t.Fatalf("unsigned tunnel accepted: %v", err)
	}

	tampered := req
	intent := *req.Intent
	intent.StageID = "wgstage_ffffffffffffffffffffffffffffffff"
	tampered.Intent = &intent

	if _, err := f.execute(tampered); !errors.Is(err, errLabAuthorization) {
		t.Fatalf("wrong stage accepted: %v", err)
	}

	if f.tunnels.connects != 0 {
		t.Fatal("unauthorized request reached backend")
	}

	lab, err := f.execute(req)
	if err != nil || lab.State != LabTunnelConfigured {
		t.Fatalf("connect: %+v %v", lab, err)
	}

	if f.tunnels.connects != 1 {
		t.Fatal("unexpected connection count")
	}

	verified, err := f.execute(existingLabRequest(OpVerifyLab, lab))
	if err != nil || verified.State != LabTunnelConfigured || f.tunnels.verifies != 1 || f.backend.verified != 0 {
		t.Fatalf("verify: %+v %v", verified, err)
	}

	disconnected, err := f.execute(existingLabRequest(OpDisconnect, lab))
	if err != nil || disconnected.State != LabSealed {
		t.Fatalf("disconnect: %+v %v", disconnected, err)
	}

	if f.labs.tunnelProfile != "" || f.tunnels.cleanups != 1 || f.backend.verified != 1 {
		t.Fatal("tunnel ownership not released or sealed lab not verified")
	}

	// Disconnect must not make a capability reusable.
	if _, err := f.execute(req); !errors.Is(err, errLabAuthorization) {
		t.Fatalf("replay accepted: %v", err)
	}

	if f.tunnels.connects != 1 {
		t.Fatal("replay reached backend")
	}

	// A fresh capability connects again.
	if lab, err := f.execute(f.connectRequest()); err != nil || lab.State != LabTunnelConfigured {
		t.Fatalf("reconnect: %+v %v", lab, err)
	}
}

func TestTunnelSlotRefusals(t *testing.T) {
	f := newTunnelFixture(t)
	other := f.createLab(t, tunnelTestProfile)

	if _, err := f.execute(f.connectRequest()); err != nil {
		t.Fatal(err)
	}

	again := f.connectRequest()
	if _, err := f.execute(again); !errors.Is(err, errLabBusy) {
		t.Fatalf("second connect on a connected lab: %v", err)
	}

	if _, err := f.execute(f.connectRequestFor(other)); !errors.Is(err, errLabBusy) {
		t.Fatalf("second tunnel: %v", err)
	}

	create := f.mint(helperauth.Intent{Operation: helperauth.OpCreateLab, ProfileID: "profile_00000000000000f3"})
	if _, err := f.execute(create); !errors.Is(err, errLabBusy) || f.backend.preflights != 2 {
		t.Fatalf("lab created while the tunnel slot is held: %v", err)
	}

	if f.tunnels.connects != 1 {
		t.Fatal("refused requests reached the backend")
	}

	// The refusals consumed nothing: the same capabilities work once the slot is free.
	if _, err := f.execute(existingLabRequest(OpDisconnect, f.lab)); err != nil {
		t.Fatal(err)
	}

	if _, err := f.execute(create); err != nil {
		t.Fatalf("create after disconnect: %v", err)
	}

	if lab, err := f.execute(again); err != nil || lab.State != LabTunnelConfigured {
		t.Fatalf("connect after disconnect: %+v %v", lab, err)
	}

	// Other labs keep working while the slot is held.
	if _, err := f.execute(existingLabRequest(OpVerifyLab, other)); err != nil {
		t.Fatal(err)
	}

	if lab, err := f.execute(existingLabRequest(OpDisconnect, other)); err != nil || lab.State != LabSealed {
		t.Fatalf("disconnect without a tunnel: %+v %v", lab, err)
	}

	if _, err := f.execute(existingLabRequest(OpDeleteLab, other)); err != nil || f.tunnels.cleanups != 1 {
		t.Fatalf("delete of a lab without the tunnel: %v", err)
	}
}

func TestStaleStageLeavesLabSealed(t *testing.T) {
	f := newTunnelFixture(t)
	f.tunnels.connectErr = fmt.Errorf("%w: replaced", ErrStageNotFound)

	_, err := f.execute(f.connectRequest())
	if labCode(err) != CodeStageNotFound {
		t.Fatalf("stale stage: %v", err)
	}

	if f.labs.tunnelProfile != "" || f.labs.labs.peek(f.lab.ProfileID).State != LabSealed {
		t.Fatal("a refused stage faulted the lab")
	}

	f.tunnels.connectErr = nil

	if lab, err := f.execute(f.connectRequest()); err != nil || lab.State != LabTunnelConfigured {
		t.Fatalf("connect with the current stage: %+v %v", lab, err)
	}
}

func TestTunnelCleanupFailureBlocksDelete(t *testing.T) {
	f := newTunnelFixture(t)

	lab, err := f.execute(f.connectRequest())
	if err != nil {
		t.Fatal(err)
	}

	f.tunnels.cleanupErr = errors.New("interface removal uncertain")

	if _, err := f.execute(existingLabRequest(OpDeleteLab, lab)); !errors.Is(err, errLabUncertain) {
		t.Fatalf("unexpected delete result: %v", err)
	}

	if f.backend.deleted != 0 ||
		f.labs.tunnelProfile != lab.ProfileID ||
		f.labs.labs.peek(lab.ProfileID).State != LabFaulted {
		t.Fatal("unsafe namespace deletion or lost ownership")
	}

	// Graceful shutdown obeys the same rule.
	if err := f.labs.Close(); err == nil {
		t.Fatal("shutdown accepted failed tunnel cleanup")
	}

	if f.backend.deleted != 0 {
		t.Fatal("shutdown bypassed cleanup guard")
	}

	f.tunnels.cleanupErr = nil

	if err := f.labs.Close(); err != nil {
		t.Fatal(err)
	}

	if f.backend.deleted != 1 || f.labs.labs.count() != 0 || f.labs.tunnelProfile != "" {
		t.Fatal("shutdown cleanup incomplete")
	}
}

func TestTunnelVerificationFailureFaultsLab(t *testing.T) {
	f := newTunnelFixture(t)

	lab, err := f.execute(f.connectRequest())
	if err != nil {
		t.Fatal(err)
	}

	f.tunnels.verifyErr = errors.New("firewall drift")

	if _, err := f.execute(existingLabRequest(OpVerifyLab, lab)); !errors.Is(err, errLabFaulted) {
		t.Fatalf("unexpected verify result: %v", err)
	}

	if f.tunnels.cleanups != 1 || f.labs.labs.peek(lab.ProfileID).State != LabFaulted {
		t.Fatal("verification failure was ignored")
	}

	if _, err := f.execute(f.connectRequest()); !errors.Is(err, errLabFaulted) {
		t.Fatalf("faulted lab reconnected: %v", err)
	}

	if _, err := f.execute(existingLabRequest(OpDeleteLab, lab)); err != nil {
		t.Fatal(err)
	}
}

func TestTunnelVerificationKeepsFailedCleanup(t *testing.T) {
	f := newTunnelFixture(t)

	lab, err := f.execute(f.connectRequest())
	if err != nil {
		t.Fatal(err)
	}

	f.tunnels.verifyErr = errors.New("link vanished")
	f.tunnels.cleanupErr = errors.New("removal unproven")

	if _, err := f.execute(existingLabRequest(OpVerifyLab, lab)); labCode(err) != CodeStateUncertain {
		t.Fatalf("unexpected verify result: %v", err)
	}

	if f.labs.tunnelProfile != lab.ProfileID || f.labs.labs.peek(lab.ProfileID).State != LabFaulted {
		t.Fatal("tunnel slot released after a failed cleanup")
	}
}

func TestFailedTunnelAttemptRetainsOwnership(t *testing.T) {
	f := newTunnelFixture(t)
	f.tunnels.connectErr = errors.New("partial kernel configuration")

	if _, err := f.execute(f.connectRequest()); !errors.Is(err, errLabUncertain) {
		t.Fatalf("unexpected connect failure: %v", err)
	}

	if f.labs.tunnelProfile != f.lab.ProfileID || f.labs.labs.peek(f.lab.ProfileID).State != LabFaulted {
		t.Fatal("failed attempt was forgotten")
	}

	f.tunnels.cleanupErr = errors.New("link survives")

	if _, err := f.execute(existingLabRequest(OpDeleteLab, f.lab)); err == nil {
		t.Fatal("uncertain tunnel was abandoned")
	}

	f.tunnels.cleanupErr = nil

	if _, err := f.execute(existingLabRequest(OpDeleteLab, f.lab)); err != nil {
		t.Fatal(err)
	}
}

func TestDisconnectAfterFailedAttemptStaysFaulted(t *testing.T) {
	f := newTunnelFixture(t)
	f.tunnels.connectErr = errors.New("rolled back")

	if _, err := f.execute(f.connectRequest()); err == nil {
		t.Fatal("failed connect accepted")
	}

	lab, err := f.execute(existingLabRequest(OpDisconnect, f.lab))
	if err != nil || lab.State != LabFaulted || f.labs.tunnelProfile != "" || f.tunnels.cleanups != 1 {
		t.Fatalf("disconnect after a failed attempt: %+v %v", lab, err)
	}

	if _, err := f.execute(existingLabRequest(OpDisconnect, f.lab)); !errors.Is(err, errLabFaulted) {
		t.Fatalf("second disconnect: %v", err)
	}

	if _, err := f.execute(existingLabRequest(OpDeleteLab, f.lab)); err != nil {
		t.Fatal(err)
	}
}

func TestTunnelOperationsNeedTheTunnelBackend(t *testing.T) {
	labs, _, v, mint := newLifecycleFixture(t)

	lab, err := labs.execute(context.Background(), mint(lifecycleProfile), v)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := labs.execute(context.Background(), existingLabRequest(OpDisconnect, lab), v); !errors.Is(err, errLabUnavailable) {
		t.Fatalf("disconnect without tunnels: %v", err)
	}

	signed := Request{Version: Version, Operation: helperauth.OpConnectTunnel, Intent: &helperauth.Intent{
		Operation: helperauth.OpConnectTunnel, ProfileID: lab.ProfileID, Namespace: lab.Namespace, StageID: tunnelTestStage,
	}}
	signed.Capability = mint(lifecycleProfile).Capability

	if _, err := labs.execute(context.Background(), signed, v); !errors.Is(err, errLabUnavailable) {
		t.Fatalf("connect without tunnels: %v", err)
	}
}

func TestTunnelIntentValidation(t *testing.T) {
	ns := "egresslab-lab-0123456789abcdef"

	for name, tt := range map[string]struct {
		op   string
		in   helperauth.Intent
		want bool
	}{
		"connect":            {helperauth.OpConnectTunnel, helperauth.Intent{ProfileID: lifecycleProfile, Namespace: ns, StageID: tunnelTestStage}, true},
		"connect, no stage":  {helperauth.OpConnectTunnel, helperauth.Intent{ProfileID: lifecycleProfile, Namespace: ns}, false},
		"connect, bad stage": {helperauth.OpConnectTunnel, helperauth.Intent{ProfileID: lifecycleProfile, Namespace: ns, StageID: "wgstage_x"}, false},
		"connect, probe":     {helperauth.OpConnectTunnel, helperauth.Intent{ProfileID: lifecycleProfile, Namespace: ns, StageID: tunnelTestStage, ProbeIPv4: "1.1.1.1"}, false},
		"disconnect":         {OpDisconnect, helperauth.Intent{ProfileID: lifecycleProfile, Namespace: ns}, true},
		"disconnect, stage":  {OpDisconnect, helperauth.Intent{ProfileID: lifecycleProfile, Namespace: ns, StageID: tunnelTestStage}, false},
		"verify, stage":      {OpVerifyLab, helperauth.Intent{ProfileID: lifecycleProfile, Namespace: ns, StageID: tunnelTestStage}, false},
		"create, stage":      {helperauth.OpCreateLab, helperauth.Intent{ProfileID: lifecycleProfile, StageID: tunnelTestStage}, false},
		"probe":              {helperauth.OpPermitProbe, helperauth.Intent{ProfileID: lifecycleProfile, Namespace: ns, ProbeIPv4: "1.1.1.1"}, false},
	} {
		tt.in.Operation = tt.op
		if got := validLifecycleIntent(tt.op, &tt.in); got != tt.want {
			t.Errorf("%s: got %t", name, got)
		}
	}
}

func TestValidTunnelResponses(t *testing.T) {
	ns := "egresslab-lab-0123456789abcdef"
	lab := LabInfo{ProfileID: lifecycleProfile, Namespace: ns}
	connect := Request{Operation: helperauth.OpConnectTunnel, Intent: &helperauth.Intent{
		Operation: helperauth.OpConnectTunnel, ProfileID: lifecycleProfile, Namespace: ns, StageID: tunnelTestStage,
	}}
	disconnect := existingLabRequest(OpDisconnect, lab)
	verify := existingLabRequest(OpVerifyLab, lab)

	ok := func(state string) Response {
		return Response{OK: true, Lab: &LabInfo{ProfileID: lifecycleProfile, Namespace: ns, State: state}}
	}

	for name, tt := range map[string]struct {
		req  Request
		resp Response
		want bool
	}{
		"connected":              {connect, ok(LabTunnelConfigured), true},
		"connect reports sealed": {connect, ok(LabSealed), false},
		"verify configured":      {verify, ok(LabTunnelConfigured), true},
		"verify faulted":         {verify, ok(LabFaulted), false},
		"disconnected":           {disconnect, ok(LabSealed), true},
		"disconnect faulted":     {disconnect, ok(LabFaulted), true},
		"disconnect configured":  {disconnect, ok(LabTunnelConfigured), false},
		"disconnect deleted":     {disconnect, ok(LabDeleted), false},
	} {
		if got := validLabResponse(tt.req, tt.resp); got != tt.want {
			t.Errorf("%s: got %t", name, got)
		}
	}

	list := Request{Operation: OpListLabs}
	labs := Response{OK: true, Labs: []LabInfo{{ProfileID: lifecycleProfile, Namespace: ns, State: LabTunnelConfigured}}}

	if !validLabListResponse(list, labs) {
		t.Error("list with a configured tunnel rejected")
	}

	labs.Labs[0].State = LabDeleted
	if validLabListResponse(list, labs) {
		t.Error("list with a deleted lab accepted")
	}
}
