package helperipc

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/VanChung369/egresslab/services/network-agent/internal/helperauth"
)

const (
	OpVerifyLab = "VerifyLab"
	OpDeleteLab = "DeleteLab"

	LabSealed  = "sealed"
	LabFaulted = "faulted"
	LabDeleted = "deleted"

	maxManagedLabs = 8

	// A tunnel connect may need its whole operation time plus its own 40 s rollback, so the
	// response deadline exceeds lifecycleTimeout + tunnelCleanupTimeout.
	lifecycleTimeout         = 80 * time.Second
	lifecycleCleanupTimeout  = 12 * time.Second
	tunnelCleanupTimeout     = 40 * time.Second
	lifecycleResponseTimeout = 125 * time.Second
)

var (
	errLabAuthorization = errors.New("lab authorization denied")
	errLabBusy          = errors.New("another lab operation is in progress")
	errLabNotFound      = errors.New("no lab for this profile")
	errLabOwnership     = errors.New("lab ownership mismatch")
	errLabExists        = errors.New("profile already owns a lab")
	errLabLimit         = errors.New("lab limit reached")
	errLabInvalid       = errors.New("invalid lab request")
	errLabUnavailable   = errors.New("lab lifecycle unavailable")
	errLabUncertain     = errors.New("kernel state uncertain")
	errLabFaulted       = errors.New("lab is faulted")
)

// labCode maps a lifecycle error to its wire code. Order matters: a failed rollback joins the
// seal error with an uncertain state, and the uncertain state wins.
func labCode(err error) string {
	switch {
	// An unconfirmed rollback outranks whatever caused it.
	case errors.Is(err, errLabUncertain):
		return CodeStateUncertain
	case errors.Is(err, errLabAuthorization):
		return CodeAuthorizationDenied
	case errors.Is(err, errLabBusy):
		return CodeLabBusy
	case errors.Is(err, errLabNotFound):
		return CodeLabNotFound
	case errors.Is(err, errLabOwnership):
		return CodeOwnershipMismatch
	case errors.Is(err, errLabExists):
		return CodeLabExists
	case errors.Is(err, errLabLimit):
		return CodeLabLimit
	case errors.Is(err, errLabInvalid):
		return CodeInvalidRequest
	case errors.Is(err, ErrStageNotFound):
		return CodeStageNotFound
	case errors.Is(err, errEvidenceUnavailable):
		return CodeEvidenceUnavailable
	case errors.Is(err, errLabUnavailable):
		return CodeRuntimeUnavailable
	case errors.Is(err, ErrLabKernelIncompatible):
		return CodeKernelIncompatible
	case errors.Is(err, ErrLabRecoveryRequired):
		return CodeRecoveryRequired
	case errors.Is(err, ErrLabFirewallDrift):
		return CodeFirewallDrift
	case errors.Is(err, errLabFaulted), errors.Is(err, ErrLabTopology):
		return CodeLabFaulted
	default:
		return CodeInternal
	}
}

var labMessages = map[string]string{
	CodeAuthorizationDenied: "authorization denied",
	CodeLabBusy:             "another lab operation is in progress, or a managed tunnel holds the only tunnel slot",
	CodeLabNotFound:         "no lab for this profile",
	CodeStageNotFound:       "WireGuard stage not found; read stage-info and sign again",
	CodeEvidenceUnavailable: "no matching fresh verified egress evidence",
	CodeOwnershipMismatch:   "lab ownership mismatch",
	CodeLabExists:           "profile already owns a lab",
	CodeLabLimit:            "lab limit reached",
	CodeInvalidRequest:      "invalid lab request",
	CodeRuntimeUnavailable:  "lab lifecycle unavailable",
	CodeKernelIncompatible:  "kernel adds devices to new namespaces; see the helper log",
	CodeRecoveryRequired:    "leftover lab resources; run egresslab-lab-recover",
	CodeStateUncertain:      "kernel state uncertain; check recovery before restarting the helper, which loses egress retirement records",
	CodeFirewallDrift:       "lab firewall drifted; delete the lab",
	CodeLabFaulted:          "lab is faulted; delete the lab",
	CodeInternal:            "lab operation failed",
}

type LabBackend interface {
	// Preflight runs before a capability is consumed. Implementations wrap
	// ErrLabRecoveryRequired or ErrLabKernelIncompatible.
	Preflight(context.Context) error
	Create(context.Context) (string, error)
	Seal(context.Context, string) error
	Verify(context.Context, string) error
	Delete(context.Context, string) error
}

// LabInfo state "sealed" means namespace plus verified firewall only: no tunnel, no egress.
// "tunnel_configured" adds a configured WireGuard link, with no handshake or egress checked.
type LabInfo struct {
	ProfileID string `json:"profile_id"`
	Namespace string `json:"namespace"`
	State     string `json:"state"`
}

// LabLifecycle keeps ownership in memory only; after a crash the labs are orphans for
// egresslab-lab-recover.
type LabLifecycle struct {
	mu sync.Mutex

	backend LabBackend
	labs    map[string]LabInfo // profile ID -> lab

	blockCreation bool // kernel state uncertain; cleared only by a helper restart
	closed        bool

	tunnels       TunnelBackend           // nil unless the managed tunnel is enabled
	probes        ProbeTunnelBackend      // nil unless the single-source probe is enabled
	multiProbes   MultiProbeTunnelBackend // nil unless the multi-source probe is enabled
	tunnelProfile string                  // owner of the one tunnel or unfinished attempt

	generationProbes GenerationProbeTunnelBackend // nil unless the generation-bound (V2) probe is enabled
	verifiedEvidence *verifiedMultiProbeEvidence  // the last checked V2 attempt, if still valid
	localCandidate   *localEgressCandidate        // the evidence one reservation consumed; not a lease
	preparedLease    *preparedEgressLease         // that candidate bound to a durable reservation; not active

	// Kept apart from the expiring authorization above, for this helper epoch.
	candidateRetirements map[string]*candidateRetirementRecord // by candidate reservation nonce
	candidateGeneration  string                                // the tracked tunnel's candidate-bearing generation

	// The backend once named another generation for it: no later cleanup proves its retirement.
	candidateGenerationContradicted bool

	logf func(format string, args ...any) // nil: log.Printf

	// The streams of the prepared lease and their keeper; written under mu, read without it so that
	// a release can cancel them. proxyCount counts admitted and waiting streams.
	proxyPlane atomic.Pointer[proxyPlane]
	proxyCount atomic.Int32
	proxyHalt  atomic.Int32 // releases waiting to preempt the streams
}

func NewLabLifecycle(backend LabBackend) *LabLifecycle {
	return &LabLifecycle{backend: backend, labs: make(map[string]LabInfo)}
}

func isLifecycleOp(op string) bool {
	switch op {
	case helperauth.OpCreateLab, OpVerifyLab, OpDeleteLab, helperauth.OpConnectTunnel, OpDisconnect:
		return true
	default:
		return false
	}
}

func validLifecycleIntent(op string, in *helperauth.Intent) bool {
	if in == nil ||
		in.Operation != op ||
		!helperauth.ValidProfileID(in.ProfileID) ||
		in.ProbeIPv4 != "" ||
		in.TunnelGeneration != "" ||
		in.EvidenceNonce != "" ||
		in.HasLeaseFields() {
		return false
	}

	switch op {
	case helperauth.OpCreateLab:
		return in.Namespace == "" && in.StageID == ""
	case helperauth.OpConnectTunnel:
		return helperauth.ValidLabNamespace(in.Namespace) && helperauth.ValidStageID(in.StageID)
	case OpVerifyLab, OpDeleteLab, OpDisconnect:
		return helperauth.ValidLabNamespace(in.Namespace) && in.StageID == ""
	default:
		return false
	}
}

func (l *LabLifecycle) execute(ctx context.Context, req Request, v *helperauth.Verifier) (LabInfo, error) {
	if l == nil ||
		l.backend == nil ||
		req.Version != Version ||
		!validLifecycleIntent(req.Operation, req.Intent) {
		return LabInfo{}, errLabInvalid
	}

	// Refuse rather than queue: a queued capability may expire.
	if !l.mu.TryLock() {
		return LabInfo{}, errLabBusy
	}
	defer l.mu.Unlock()

	if l.closed || ctx.Err() != nil {
		return LabInfo{}, errLabUnavailable
	}

	intent := *req.Intent

	if req.Operation == helperauth.OpCreateLab {
		// The recovery gate would see the tunnel's own underlay table; until tunnels have their
		// own registry, no lab is created while one exists.
		if l.tunnelProfile != "" {
			return LabInfo{}, errTunnelSlotBusy
		}

		return l.createLocked(ctx, intent, req.Capability, v)
	}

	if req.Operation != helperauth.OpConnectTunnel && req.Capability != nil {
		return LabInfo{}, errLabAuthorization
	}

	lab, exists := l.labs[intent.ProfileID]
	if !exists {
		return LabInfo{}, errLabNotFound
	}

	if lab.Namespace != intent.Namespace {
		return LabInfo{}, errLabOwnership
	}

	switch req.Operation {
	case helperauth.OpConnectTunnel:
		return l.connectTunnelLocked(ctx, lab, intent, req.Capability, v)

	case OpVerifyLab:
		return l.verifyLocked(ctx, lab)

	case OpDisconnect:
		if l.tunnels == nil {
			return LabInfo{}, errLabUnavailable
		}

		return l.disconnectTunnelLocked(ctx, lab)

	case OpDeleteLab:
		return l.deleteLocked(ctx, lab)

	default:
		return LabInfo{}, errLabInvalid
	}
}

func (l *LabLifecycle) createLocked(
	ctx context.Context,
	intent helperauth.Intent,
	capability *helperauth.SignedCapability,
	v *helperauth.Verifier,
) (LabInfo, error) {
	if v == nil || capability == nil {
		return LabInfo{}, errLabAuthorization
	}

	if l.blockCreation {
		return LabInfo{}, errLabUncertain
	}

	if len(l.labs) >= maxManagedLabs {
		return LabInfo{}, errLabLimit
	}

	if _, exists := l.labs[intent.ProfileID]; exists {
		return LabInfo{}, errLabExists
	}

	// Anything the preflight cannot prove clean blocks creation.
	if err := l.backend.Preflight(ctx); err != nil {
		if !errors.Is(err, ErrLabKernelIncompatible) && !errors.Is(err, ErrLabRecoveryRequired) {
			err = fmt.Errorf("%w: %w", ErrLabRecoveryRequired, err)
		}

		return LabInfo{}, err
	}

	if err := v.VerifyAndConsume(*capability, intent); err != nil {
		return LabInfo{}, fmt.Errorf("%w: %w", errLabAuthorization, err)
	}

	name, err := l.backend.Create(ctx)
	if err != nil {
		l.blockCreation = true
		return LabInfo{}, fmt.Errorf("%w: create namespace: %w", errLabUncertain, err)
	}

	if !helperauth.ValidLabNamespace(name) {
		l.blockCreation = true
		return LabInfo{}, fmt.Errorf("%w: backend returned an invalid namespace", errLabUncertain)
	}

	lab := LabInfo{ProfileID: intent.ProfileID, Namespace: name, State: LabFaulted}

	// Tracked before sealing, so a failed rollback is not forgotten.
	l.labs[lab.ProfileID] = lab

	if err := l.backend.Seal(ctx, name); err != nil {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), lifecycleCleanupTimeout)
		cleanupErr := l.backend.Delete(cleanupCtx, name)
		cancel()

		if cleanupErr == nil {
			delete(l.labs, lab.ProfileID)
			return LabInfo{}, fmt.Errorf("seal namespace %s (rolled back): %w", name, err)
		}

		l.blockCreation = true

		return LabInfo{}, errors.Join(fmt.Errorf("%w: seal namespace %s: %w", errLabUncertain, name, err), cleanupErr)
	}

	lab.State = LabSealed
	l.labs[lab.ProfileID] = lab

	return lab, nil
}

// A faulted lab is never restored; only DeleteLab clears it.
func (l *LabLifecycle) verifyLocked(ctx context.Context, lab LabInfo) (LabInfo, error) {
	if lab.State == LabTunnelConfigured {
		return l.verifyTunnelLocked(ctx, lab)
	}

	if lab.State != LabSealed {
		return LabInfo{}, errLabFaulted
	}

	if err := l.backend.Verify(ctx, lab.Namespace); err != nil {
		lab.State = LabFaulted
		l.labs[lab.ProfileID] = lab

		return LabInfo{}, fmt.Errorf("%w: %w", errLabFaulted, err)
	}

	return lab, nil
}

// The tunnel goes first: a namespace is deleted only once the tunnel backend has released it.
func (l *LabLifecycle) deleteLocked(ctx context.Context, lab LabInfo) (LabInfo, error) {
	if err := l.clearTunnelLocked(ctx, lab); err != nil {
		return LabInfo{}, err
	}

	if err := l.backend.Delete(ctx, lab.Namespace); err != nil {
		lab.State = LabFaulted
		l.labs[lab.ProfileID] = lab

		return LabInfo{}, fmt.Errorf("%w: %w", errLabFaulted, err)
	}

	delete(l.labs, lab.ProfileID)
	lab.State = LabDeleted

	return lab, nil
}

// Close must run after the server has stopped. It deletes each lab the same way DeleteLab does,
// tunnel first; labs that cannot be deleted stay for recovery. It can be called again.
func (l *LabLifecycle) Close() error {
	if l == nil {
		return nil
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	l.closed = true
	l.closeProxyStreamsLocked()
	l.verifiedEvidence = nil
	l.localCandidate = nil
	l.preparedLease = nil

	var errs []error

	for _, lab := range l.labs {
		ctx, cancel := context.WithTimeout(context.Background(), lifecycleTimeout)
		_, err := l.deleteLocked(ctx, lab)
		cancel()

		if err != nil {
			errs = append(errs, fmt.Errorf("cleanup %s: %w", lab.Namespace, err))
		}
	}

	return errors.Join(errs...)
}

func validLabResponse(req Request, resp Response) bool {
	if !isLifecycleOp(req.Operation) || !resp.OK {
		return resp.Lab == nil
	}

	if resp.Lab == nil ||
		req.Intent == nil ||
		resp.Lab.ProfileID != req.Intent.ProfileID ||
		!helperauth.ValidLabNamespace(resp.Lab.Namespace) {
		return false
	}

	if req.Operation != helperauth.OpCreateLab && resp.Lab.Namespace != req.Intent.Namespace {
		return false
	}

	switch req.Operation {
	case OpDeleteLab:
		return resp.Lab.State == LabDeleted
	case helperauth.OpConnectTunnel:
		return resp.Lab.State == LabTunnelConfigured
	case OpVerifyLab:
		return resp.Lab.State == LabSealed || resp.Lab.State == LabTunnelConfigured
	case OpDisconnect:
		return resp.Lab.State == LabSealed || resp.Lab.State == LabFaulted
	default:
		return resp.Lab.State == LabSealed
	}
}
