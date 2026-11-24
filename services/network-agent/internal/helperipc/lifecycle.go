package helperipc

import (
	"context"
	"errors"
	"fmt"
	"sync"
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

	lifecycleTimeout         = 40 * time.Second
	lifecycleCleanupTimeout  = 12 * time.Second
	lifecycleResponseTimeout = 55 * time.Second // > lifecycleTimeout + lifecycleCleanupTimeout
)

var (
	errLabAuthorization = errors.New("lab authorization denied")
	errLabBusy          = errors.New("another lab operation is in progress")
	errLabOwnership     = errors.New("lab ownership mismatch")
	errLabUnavailable   = errors.New("lab lifecycle unavailable")
)

type LabBackend interface {
	Create(context.Context) (string, error)
	Seal(context.Context, string) error
	Verify(context.Context, string) error
	Delete(context.Context, string) error
}

// LabInfo state "sealed" means namespace plus verified firewall only: no tunnel, no egress.
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
}

func NewLabLifecycle(backend LabBackend) *LabLifecycle {
	return &LabLifecycle{backend: backend, labs: make(map[string]LabInfo)}
}

func isLifecycleOp(op string) bool {
	switch op {
	case helperauth.OpCreateLab, OpVerifyLab, OpDeleteLab:
		return true
	default:
		return false
	}
}

func validLifecycleIntent(op string, in *helperauth.Intent) bool {
	if in == nil ||
		in.Operation != op ||
		!helperauth.ValidProfileID(in.ProfileID) ||
		in.StageID != "" ||
		in.ProbeIPv4 != "" {
		return false
	}

	switch op {
	case helperauth.OpCreateLab:
		return in.Namespace == ""
	case OpVerifyLab, OpDeleteLab:
		return helperauth.ValidLabNamespace(in.Namespace)
	default:
		return false
	}
}

func (l *LabLifecycle) execute(ctx context.Context, req Request, v *helperauth.Verifier) (LabInfo, error) {
	if l == nil ||
		l.backend == nil ||
		req.Version != Version ||
		!validLifecycleIntent(req.Operation, req.Intent) {
		return LabInfo{}, errLabUnavailable
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

	switch req.Operation {
	case helperauth.OpCreateLab:
		return l.createLocked(ctx, intent, req.Capability, v)

	case OpVerifyLab, OpDeleteLab:
		if req.Capability != nil {
			return LabInfo{}, errLabAuthorization
		}

		lab, exists := l.labs[intent.ProfileID]
		if !exists || lab.Namespace != intent.Namespace {
			return LabInfo{}, errLabOwnership
		}

		if req.Operation == OpVerifyLab {
			return l.verifyLocked(ctx, lab)
		}

		return l.deleteLocked(ctx, lab)

	default:
		return LabInfo{}, errLabUnavailable
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

	if l.blockCreation || len(l.labs) >= maxManagedLabs {
		return LabInfo{}, errLabUnavailable
	}

	if _, exists := l.labs[intent.ProfileID]; exists {
		return LabInfo{}, errors.New("profile already owns a lab")
	}

	if err := v.VerifyAndConsume(*capability, intent); err != nil {
		return LabInfo{}, fmt.Errorf("%w: %w", errLabAuthorization, err)
	}

	name, err := l.backend.Create(ctx)
	if err != nil {
		l.blockCreation = true
		return LabInfo{}, fmt.Errorf("create namespace: %w", err)
	}

	if !helperauth.ValidLabNamespace(name) {
		l.blockCreation = true
		return LabInfo{}, errors.New("backend returned an invalid namespace")
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
		} else {
			l.blockCreation = true
		}

		return LabInfo{}, errors.Join(fmt.Errorf("seal namespace %s: %w", name, err), cleanupErr)
	}

	lab.State = LabSealed
	l.labs[lab.ProfileID] = lab

	return lab, nil
}

// A faulted lab is never restored; only DeleteLab clears it.
func (l *LabLifecycle) verifyLocked(ctx context.Context, lab LabInfo) (LabInfo, error) {
	if lab.State != LabSealed {
		return LabInfo{}, errors.New("lab is faulted; cleanup required")
	}

	if err := l.backend.Verify(ctx, lab.Namespace); err != nil {
		lab.State = LabFaulted
		l.labs[lab.ProfileID] = lab

		return LabInfo{}, err
	}

	return lab, nil
}

func (l *LabLifecycle) deleteLocked(ctx context.Context, lab LabInfo) (LabInfo, error) {
	if err := l.backend.Delete(ctx, lab.Namespace); err != nil {
		lab.State = LabFaulted
		l.labs[lab.ProfileID] = lab

		return LabInfo{}, err
	}

	delete(l.labs, lab.ProfileID)
	lab.State = LabDeleted

	return lab, nil
}

// Close must run after the server has stopped. Labs that cannot be deleted stay for recovery.
func (l *LabLifecycle) Close() error {
	if l == nil {
		return nil
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	l.closed = true

	var errs []error

	for profileID, lab := range l.labs {
		ctx, cancel := context.WithTimeout(context.Background(), lifecycleCleanupTimeout)
		err := l.backend.Delete(ctx, lab.Namespace)
		cancel()

		if err != nil {
			errs = append(errs, fmt.Errorf("cleanup %s: %w", lab.Namespace, err))
			continue
		}

		delete(l.labs, profileID)
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

	if req.Operation == OpDeleteLab {
		return resp.Lab.State == LabDeleted
	}

	return resp.Lab.State == LabSealed
}
