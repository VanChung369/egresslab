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

const lifecycleProfile = "profile_0123456789abcdef"

type fakeLifecycleBackend struct {
	preflights int
	created    int
	sealed     int
	verified   int
	deleted    int

	preflightErr error
	createErr    error
	sealErr      error
	verifyErr    error
	deleteErr    error
}

func (f *fakeLifecycleBackend) Preflight(context.Context) error {
	f.preflights++
	return f.preflightErr
}

func (f *fakeLifecycleBackend) Create(context.Context) (string, error) {
	f.created++

	if f.createErr != nil {
		return "", f.createErr
	}

	return fmt.Sprintf("egresslab-lab-%016x", f.created), nil
}

func (f *fakeLifecycleBackend) Seal(context.Context, string) error {
	f.sealed++
	return f.sealErr
}

func (f *fakeLifecycleBackend) Verify(context.Context, string) error {
	f.verified++
	return f.verifyErr
}

func (f *fakeLifecycleBackend) Delete(context.Context, string) error {
	f.deleted++
	return f.deleteErr
}

func lifecycleSigner(t *testing.T) (*helperauth.Verifier, func(string) Request) {
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

	mint := func(profileID string) Request {
		t.Helper()

		intent := helperauth.Intent{Operation: helperauth.OpCreateLab, ProfileID: profileID}

		claims, err := helperauth.NewClaims(intent, id, time.Now())
		if err != nil {
			t.Fatal(err)
		}

		token, err := helperauth.Mint(private, claims)
		if err != nil {
			t.Fatal(err)
		}

		return Request{Version: Version, Operation: intent.Operation, Intent: &intent, Capability: &token}
	}

	return v, mint
}

func newLifecycleFixture(t *testing.T) (*LabLifecycle, *fakeLifecycleBackend, *helperauth.Verifier, func(string) Request) {
	t.Helper()

	backend := &fakeLifecycleBackend{}
	v, mint := lifecycleSigner(t)

	return NewLabLifecycle(backend), backend, v, mint
}

func existingLabRequest(op string, lab LabInfo) Request {
	return Request{
		Version:   Version,
		Operation: op,
		Intent:    &helperauth.Intent{Operation: op, ProfileID: lab.ProfileID, Namespace: lab.Namespace},
	}
}

func TestLabLifecycleCreateVerifyDelete(t *testing.T) {
	labs, backend, v, mint := newLifecycleFixture(t)
	ctx := context.Background()
	req := mint(lifecycleProfile)

	unsigned := req
	unsigned.Capability = nil

	if _, err := labs.execute(ctx, unsigned, v); !errors.Is(err, errLabAuthorization) {
		t.Fatalf("unsigned creation accepted: %v", err)
	}

	if backend.created != 0 {
		t.Fatal("backend called without authorization")
	}

	lab, err := labs.execute(ctx, req, v)
	if err != nil {
		t.Fatal(err)
	}

	if lab.State != LabSealed || lab.ProfileID != lifecycleProfile || backend.created != 1 || backend.sealed != 1 {
		t.Fatalf("unexpected creation: %+v", lab)
	}

	if _, err := labs.execute(ctx, mint(lifecycleProfile), v); err == nil {
		t.Fatal("duplicate profile accepted")
	}

	foreign := existingLabRequest(OpDeleteLab, lab)
	foreign.Intent.ProfileID = "profile_ffffffffffffffff"

	if _, err := labs.execute(ctx, foreign, v); !errors.Is(err, errLabNotFound) {
		t.Fatalf("foreign deletion accepted: %v", err)
	}

	other := existingLabRequest(OpVerifyLab, lab)
	other.Intent.Namespace = "egresslab-lab-ffffffffffffffff"

	if _, err := labs.execute(ctx, other, v); !errors.Is(err, errLabOwnership) {
		t.Fatalf("other namespace accepted: %v", err)
	}

	verified, err := labs.execute(ctx, existingLabRequest(OpVerifyLab, lab), v)
	if err != nil || verified.State != LabSealed || backend.verified != 1 {
		t.Fatalf("verification failed: %v", err)
	}

	deleted, err := labs.execute(ctx, existingLabRequest(OpDeleteLab, lab), v)
	if err != nil || deleted.State != LabDeleted || labs.labs.count() != 0 {
		t.Fatalf("deletion failed: %v", err)
	}

	// Deletion does not make the original signed capability reusable.
	if _, err := labs.execute(ctx, req, v); !errors.Is(err, errLabAuthorization) {
		t.Fatalf("creation replay accepted: %v", err)
	}

	if backend.created != 1 {
		t.Fatal("replay reached kernel backend")
	}
}

func TestLabLifecycleRejectsMalformedRequests(t *testing.T) {
	labs, backend, v, mint := newLifecycleFixture(t)
	ctx := context.Background()

	lab, err := labs.execute(ctx, mint(lifecycleProfile), v)
	if err != nil {
		t.Fatal(err)
	}

	withNamespace := mint("profile_ffffffffffffffff")
	withNamespace.Intent.Namespace = lab.Namespace

	mismatched := existingLabRequest(OpVerifyLab, lab)
	mismatched.Intent.Operation = OpDeleteLab

	signedVerify := existingLabRequest(OpVerifyLab, lab)
	signedVerify.Capability = mint(lifecycleProfile).Capability

	signedDelete := existingLabRequest(OpDeleteLab, lab)
	signedDelete.Capability = signedVerify.Capability

	for name, tt := range map[string]struct {
		req  Request
		want error
	}{
		"CreateLab naming a namespace":       {withNamespace, errLabInvalid},
		"intent for another operation":       {mismatched, errLabInvalid},
		"missing intent":                     {Request{Version: Version, Operation: OpVerifyLab}, errLabInvalid},
		"VerifyLab carrying a capability":    {signedVerify, errLabAuthorization},
		"DeleteLab carrying a capability":    {signedDelete, errLabAuthorization},
		"ConnectTunnel is not lifecycle":     {Request{Version: Version, Operation: helperauth.OpConnectTunnel}, errLabInvalid},
		"unsupported version":                {Request{Version: 2, Operation: OpVerifyLab, Intent: mismatched.Intent}, errLabInvalid},
		"VerifyLab with a malformed profile": {existingLabRequest(OpVerifyLab, LabInfo{ProfileID: "x", Namespace: lab.Namespace}), errLabInvalid},
	} {
		if _, err := labs.execute(ctx, tt.req, v); !errors.Is(err, tt.want) {
			t.Fatalf("%s: got %v, want %v", name, err, tt.want)
		}
	}

	if backend.created != 1 || backend.verified != 0 || backend.deleted != 0 {
		t.Fatalf("refused requests reached the backend: %+v", backend)
	}
}

func TestLabLifecycleRollsBackSealFailure(t *testing.T) {
	labs, backend, v, mint := newLifecycleFixture(t)
	backend.sealErr = errors.New("nft readback failed")

	if _, err := labs.execute(context.Background(), mint(lifecycleProfile), v); err == nil {
		t.Fatal("seal failure accepted")
	}

	if backend.deleted != 1 || labs.labs.count() != 0 || labs.blockCreation {
		t.Fatal("creation was not rolled back")
	}
}

func TestLabLifecycleRetainsFailedRollback(t *testing.T) {
	labs, backend, v, mint := newLifecycleFixture(t)
	backend.sealErr = errors.New("seal failed")
	backend.deleteErr = errors.New("namespace busy")

	if _, err := labs.execute(context.Background(), mint(lifecycleProfile), v); err == nil {
		t.Fatal("failed rollback accepted")
	}

	lab := labs.labs.peek(lifecycleProfile)
	if lab.State != LabFaulted || !labs.blockCreation {
		t.Fatal("failed resource was forgotten")
	}

	other := mint("profile_ffffffffffffffff")
	if _, err := labs.execute(context.Background(), other, v); err == nil {
		t.Fatal("allocation allowed after failed rollback")
	}

	backend.deleteErr = nil

	if _, err := labs.execute(context.Background(), existingLabRequest(OpDeleteLab, lab), v); err != nil {
		t.Fatal(err)
	}

	if labs.labs.count() != 0 {
		t.Fatal("failed lab not removed")
	}

	// The block is not lifted by cleanup in the same process, and the refused request above did
	// not consume its capability.
	if _, err := labs.execute(context.Background(), other, v); !errors.Is(err, errLabUncertain) {
		t.Fatalf("creation unblocked: %v", err)
	}

	if backend.created != 1 {
		t.Fatal("unsafe second allocation attempted")
	}
}

func TestLabLifecycleFaultsOnVerificationFailure(t *testing.T) {
	labs, backend, v, mint := newLifecycleFixture(t)
	ctx := context.Background()

	lab, err := labs.execute(ctx, mint(lifecycleProfile), v)
	if err != nil {
		t.Fatal(err)
	}

	backend.verifyErr = errors.New("firewall drift")

	if _, err := labs.execute(ctx, existingLabRequest(OpVerifyLab, lab), v); err == nil {
		t.Fatal("firewall drift accepted")
	}

	if labs.labs.peek(lab.ProfileID).State != LabFaulted {
		t.Fatal("lab not marked faulted")
	}

	// A later successful backend check must not silently restore a faulted lab.
	backend.verifyErr = nil

	if _, err := labs.execute(ctx, existingLabRequest(OpVerifyLab, lab), v); err == nil {
		t.Fatal("faulted lab restored automatically")
	}

	if _, err := labs.execute(ctx, existingLabRequest(OpDeleteLab, lab), v); err != nil {
		t.Fatal(err)
	}
}

func TestLabLifecycleFailedDeleteKeepsOwnership(t *testing.T) {
	labs, backend, v, mint := newLifecycleFixture(t)
	ctx := context.Background()

	lab, err := labs.execute(ctx, mint(lifecycleProfile), v)
	if err != nil {
		t.Fatal(err)
	}

	backend.deleteErr = errors.New("namespace has processes")

	if _, err := labs.execute(ctx, existingLabRequest(OpDeleteLab, lab), v); err == nil {
		t.Fatal("failed deletion reported success")
	}

	if got := labs.labs.peek(lab.ProfileID); got.State != LabFaulted || got.Namespace != lab.Namespace {
		t.Fatalf("lab after failed deletion: %+v", got)
	}

	backend.deleteErr = nil

	if _, err := labs.execute(ctx, existingLabRequest(OpDeleteLab, lab), v); err != nil {
		t.Fatal(err)
	}
}

func TestLabLifecycleCapacityAndClose(t *testing.T) {
	labs, backend, v, mint := newLifecycleFixture(t)
	ctx := context.Background()

	for i := 0; i < maxManagedLabs; i++ {
		if _, err := labs.execute(ctx, mint(fmt.Sprintf("profile_%016x", i)), v); err != nil {
			t.Fatal(err)
		}
	}

	if _, err := labs.execute(ctx, mint("profile_ffffffffffffffff"), v); !errors.Is(err, errLabLimit) {
		t.Fatalf("resource limit ignored: %v", err)
	}

	if backend.created != maxManagedLabs {
		t.Fatal("too many namespaces allocated")
	}

	if err := labs.Close(); err != nil {
		t.Fatal(err)
	}

	if labs.labs.count() != 0 || backend.deleted != maxManagedLabs {
		t.Fatal("shutdown cleanup incomplete")
	}

	if _, err := labs.execute(ctx, mint("profile_ffffffffffffffff"), v); !errors.Is(err, errLabUnavailable) {
		t.Fatalf("operation after close: %v", err)
	}
}

func TestLabLifecycleCloseKeepsUndeletableLabs(t *testing.T) {
	labs, backend, v, mint := newLifecycleFixture(t)

	if _, err := labs.execute(context.Background(), mint(lifecycleProfile), v); err != nil {
		t.Fatal(err)
	}

	backend.deleteErr = errors.New("unexpected device")

	if err := labs.Close(); err == nil {
		t.Fatal("failed cleanup not reported")
	}

	if labs.labs.count() != 1 {
		t.Fatal("undeletable lab forgotten")
	}
}

func TestLabLifecycleRejectsConcurrentOperations(t *testing.T) {
	labs, backend, v, mint := newLifecycleFixture(t)
	req := mint(lifecycleProfile)

	labs.mu.Lock()
	_, err := labs.execute(context.Background(), req, v)
	labs.mu.Unlock()

	if !errors.Is(err, errLabBusy) || backend.created != 0 {
		t.Fatalf("busy operation accepted: %v", err)
	}

	// A busy refusal did not consume the nonce.
	if _, err := labs.execute(context.Background(), req, v); err != nil {
		t.Fatal(err)
	}
}

func TestLabLifecycleRejectsUncertainCreation(t *testing.T) {
	labs, backend, v, mint := newLifecycleFixture(t)
	backend.createErr = errors.New("namespace state uncertain")

	if _, err := labs.execute(context.Background(), mint(lifecycleProfile), v); err == nil {
		t.Fatal("uncertain creation accepted")
	}

	backend.createErr = nil

	if _, err := labs.execute(context.Background(), mint(lifecycleProfile), v); err == nil {
		t.Fatal("creation not blocked after uncertain state")
	}

	if backend.created != 1 {
		t.Fatal("unsafe second allocation attempted")
	}
}

func TestValidLabResponse(t *testing.T) {
	const ns = "egresslab-lab-0123456789abcdef"

	create := Request{Version: Version, Operation: helperauth.OpCreateLab,
		Intent: &helperauth.Intent{Operation: helperauth.OpCreateLab, ProfileID: lifecycleProfile}}
	verify := existingLabRequest(OpVerifyLab, LabInfo{ProfileID: lifecycleProfile, Namespace: ns})
	del := existingLabRequest(OpDeleteLab, LabInfo{ProfileID: lifecycleProfile, Namespace: ns})
	ping := Request{Version: Version, Operation: OpPing}

	lab := func(profile, namespace, state string) *LabInfo {
		return &LabInfo{ProfileID: profile, Namespace: namespace, State: state}
	}

	tests := []struct {
		name string
		req  Request
		resp Response
		want bool
	}{
		{"created", create, Response{OK: true, Lab: lab(lifecycleProfile, ns, LabSealed)}, true},
		{"verified", verify, Response{OK: true, Lab: lab(lifecycleProfile, ns, LabSealed)}, true},
		{"deleted", del, Response{OK: true, Lab: lab(lifecycleProfile, ns, LabDeleted)}, true},
		{"refusal without metadata", create, Response{Error: "authorization denied"}, true},
		{"ping without metadata", ping, Response{OK: true}, true},

		{"metadata on ping", ping, Response{OK: true, Lab: lab(lifecycleProfile, ns, LabSealed)}, false},
		{"metadata on a refusal", create, Response{Error: "x", Lab: lab(lifecycleProfile, ns, LabSealed)}, false},
		{"missing metadata", create, Response{OK: true}, false},
		{"other profile", create, Response{OK: true, Lab: lab("profile_ffffffffffffffff", ns, LabSealed)}, false},
		{"invalid namespace", create, Response{OK: true, Lab: lab(lifecycleProfile, "../default", LabSealed)}, false},
		{"created but faulted", create, Response{OK: true, Lab: lab(lifecycleProfile, ns, LabFaulted)}, false},
		{"created but deleted", create, Response{OK: true, Lab: lab(lifecycleProfile, ns, LabDeleted)}, false},
		{"verified other namespace", verify,
			Response{OK: true, Lab: lab(lifecycleProfile, "egresslab-lab-ffffffffffffffff", LabSealed)}, false},
		{"deleted but sealed", del, Response{OK: true, Lab: lab(lifecycleProfile, ns, LabSealed)}, false},
	}

	for _, tt := range tests {
		if got := validLabResponse(tt.req, tt.resp); got != tt.want {
			t.Errorf("%s: got %t, want %t", tt.name, got, tt.want)
		}
	}
}

func TestValidLabListResponse(t *testing.T) {
	list := Request{Version: Version, Operation: OpListLabs}
	lab := func(profile, namespace, state string) LabInfo {
		return LabInfo{ProfileID: profile, Namespace: namespace, State: state}
	}

	const nsA, nsB = "egresslab-lab-000000000000000a", "egresslab-lab-000000000000000b"
	const pB = "profile_000000000000000b"

	full := make([]LabInfo, maxManagedLabs+1)
	for i := range full {
		full[i] = lab(fmt.Sprintf("profile_%016x", i), fmt.Sprintf("egresslab-lab-%016x", i), LabSealed)
	}

	tests := []struct {
		name string
		req  Request
		resp Response
		want bool
	}{
		{"empty", list, Response{OK: true}, true},
		{"sealed and faulted", list, Response{OK: true, Labs: []LabInfo{
			lab(lifecycleProfile, nsA, LabSealed), lab(pB, nsB, LabFaulted)}}, true},
		{"refusal without list", list, Response{Error: "operation not enabled"}, true},

		{"list on a refusal", list, Response{Error: "x", Labs: []LabInfo{lab(lifecycleProfile, nsA, LabSealed)}}, false},
		{"list on Ping", Request{Version: Version, Operation: OpPing},
			Response{OK: true, Labs: []LabInfo{lab(lifecycleProfile, nsA, LabSealed)}}, false},
		{"too many labs", list, Response{OK: true, Labs: full}, false},
		{"deleted state", list, Response{OK: true, Labs: []LabInfo{lab(lifecycleProfile, nsA, LabDeleted)}}, false},
		{"malformed profile", list, Response{OK: true, Labs: []LabInfo{lab("profile_x", nsA, LabSealed)}}, false},
		{"malformed namespace", list, Response{OK: true, Labs: []LabInfo{lab(lifecycleProfile, "../default", LabSealed)}}, false},
		{"duplicate profile", list, Response{OK: true, Labs: []LabInfo{
			lab(lifecycleProfile, nsA, LabSealed), lab(lifecycleProfile, nsB, LabSealed)}}, false},
		{"duplicate namespace", list, Response{OK: true, Labs: []LabInfo{
			lab(lifecycleProfile, nsA, LabSealed), lab(pB, nsA, LabSealed)}}, false},
	}

	for _, tt := range tests {
		if got := validLabListResponse(tt.req, tt.resp); got != tt.want {
			t.Errorf("%s: got %t, want %t", tt.name, got, tt.want)
		}
	}
}

func TestLabLifecyclePreflightGate(t *testing.T) {
	labs, backend, v, mint := newLifecycleFixture(t)
	ctx := context.Background()
	req := mint(lifecycleProfile)

	for _, tt := range []struct {
		err  error
		code string
	}{
		{fmt.Errorf("%w: orphan egresslab-lab-00000000000000a1", ErrLabRecoveryRequired), CodeRecoveryRequired},
		{errors.New("scan failed"), CodeRecoveryRequired},
		{fmt.Errorf("%w: sit0", ErrLabKernelIncompatible), CodeKernelIncompatible},
	} {
		backend.preflightErr = tt.err

		if _, err := labs.execute(ctx, req, v); labCode(err) != tt.code {
			t.Fatalf("%v: got %v (%s), want %s", tt.err, err, labCode(err), tt.code)
		}
	}

	if backend.created != 0 {
		t.Fatal("namespace created despite the gate")
	}

	// The refusals did not consume the capability.
	backend.preflightErr = nil

	if _, err := labs.execute(ctx, req, v); err != nil {
		t.Fatal(err)
	}

	// Verify and delete stay possible whatever the gate says.
	backend.preflightErr = ErrLabRecoveryRequired
	lab := labs.labs.peek(lifecycleProfile)

	if _, err := labs.execute(ctx, existingLabRequest(OpDeleteLab, lab), v); err != nil {
		t.Fatalf("delete blocked by the gate: %v", err)
	}
}

func TestLabCodes(t *testing.T) {
	wrap := func(err error) error { return fmt.Errorf("context: %w", err) }

	tests := map[string]error{
		CodeAuthorizationDenied: wrap(errLabAuthorization),
		CodeLabBusy:             errLabBusy,
		CodeLabNotFound:         errLabNotFound,
		CodeOwnershipMismatch:   errLabOwnership,
		CodeLabExists:           errLabExists,
		CodeLabLimit:            errLabLimit,
		CodeInvalidRequest:      errLabInvalid,
		CodeRuntimeUnavailable:  errLabUnavailable,
		CodeRecoveryRequired:    wrap(ErrLabRecoveryRequired),
		CodeKernelIncompatible:  wrap(ErrLabKernelIncompatible),
		CodeFirewallDrift:       fmt.Errorf("%w: %w", errLabFaulted, ErrLabFirewallDrift),
		CodeLabFaulted:          fmt.Errorf("%w: %w", errLabFaulted, ErrLabTopology),
		// A failed rollback joins the seal error with an uncertain state.
		CodeStateUncertain: errors.Join(fmt.Errorf("%w: seal: %w", errLabUncertain, ErrLabFirewallDrift), errors.New("busy")),
		CodeInternal:       errors.New("seal namespace (rolled back): nft failed"),
	}

	for want, err := range tests {
		if got := labCode(err); got != want {
			t.Errorf("%v: got %s, want %s", err, got, want)
		}

		if !knownCodes[want] || labMessages[want] == "" {
			t.Errorf("%s has no message", want)
		}
	}
}

func TestValidStageResponse(t *testing.T) {
	const stage = "wgstage_0123456789abcdef0123456789abcdef"

	req := Request{Version: Version, Operation: OpStageInfo, Intent: &helperauth.Intent{Operation: OpStageInfo, ProfileID: lifecycleProfile}}
	ping := Request{Version: Version, Operation: OpPing}
	info := func(profile, id string) *StageInfo {
		return &StageInfo{ProfileID: profile, StageID: id, Compatible: true}
	}

	for name, tt := range map[string]struct {
		req  Request
		resp Response
		want bool
	}{
		"stage":              {req, Response{OK: true, Stage: info(lifecycleProfile, stage)}, true},
		"refusal":            {req, Response{Code: CodeStageNotFound, Error: "x"}, true},
		"ping":               {ping, Response{OK: true}, true},
		"stage on ping":      {ping, Response{OK: true, Stage: info(lifecycleProfile, stage)}, false},
		"stage on refusal":   {req, Response{Error: "x", Stage: info(lifecycleProfile, stage)}, false},
		"missing stage":      {req, Response{OK: true}, false},
		"other profile":      {req, Response{OK: true, Stage: info("profile_ffffffffffffffff", stage)}, false},
		"malformed stage ID": {req, Response{OK: true, Stage: info(lifecycleProfile, "wgstage_X")}, false},
	} {
		if got := validStageResponse(tt.req, tt.resp); got != tt.want {
			t.Errorf("%s: got %t, want %t", name, got, tt.want)
		}
	}
}
