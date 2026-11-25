package helperipc

import (
	"context"

	"github.com/VanChung369/egresslab/services/network-agent/internal/helperauth"
)

// OpMultiProbePolicy reads the multi-source policy of the running helper generation.
const OpMultiProbePolicy = "MultiProbePolicy"

// MultiProbePolicyInfo is public metadata: the policy version and its ident.me pin, bound to the
// helper epoch, runtime ID and public-key fingerprint they apply to. Reading it authorizes nothing.
type MultiProbePolicyInfo struct {
	Policy          string `json:"policy"`
	IdentIPv4       string `json:"ident_ipv4"`
	HelperID        string `json:"helper_id"`
	RuntimeID       string `json:"runtime_id"`
	PublicKeySHA256 string `json:"public_key_sha256"`
}

func (p *MultiProbePolicyInfo) valid() bool {
	if p == nil || (p.Policy != helperauth.OpPermitMultiProbe && p.Policy != helperauth.OpPermitMultiProbeV2) ||
		!helperauth.ValidMultiProbePin(p.IdentIPv4) ||
		!ValidRuntimeID(p.RuntimeID) {
		return false
	}

	identity := HelperInfo{
		AuthorizationConfigured: true,
		HelperID:                p.HelperID,
		RuntimeID:               p.RuntimeID,
		PublicKeySHA256:         p.PublicKeySHA256,
	}

	return identity.valid()
}

func validMultiProbePolicyResponse(req Request, resp Response) bool {
	if req.Operation != OpMultiProbePolicy || !resp.OK {
		return resp.MultiProbePolicy == nil
	}

	return resp.MultiProbePolicy.valid()
}

// readMultiProbePolicy reads the backend's policy without creating a lab, opening a window,
// running a worker or consuming a capability. It does not wait behind a running operation.
func (l *LabLifecycle) readMultiProbePolicy(
	ctx context.Context,
	v *helperauth.Verifier,
	runtimeID string,
) (MultiProbePolicyInfo, error) {
	if l == nil || l.multiProbes == nil || v == nil {
		return MultiProbePolicyInfo{}, errLabUnavailable
	}

	// Shutdown is reported as such, even while another operation still holds the lock.
	if ctx.Err() != nil {
		return MultiProbePolicyInfo{}, errLabUnavailable
	}

	if !l.mu.TryLock() {
		return MultiProbePolicyInfo{}, errLabBusy
	}
	defer l.mu.Unlock()

	if l.closed || ctx.Err() != nil {
		return MultiProbePolicyInfo{}, errLabUnavailable
	}

	if l.blockCreation {
		return MultiProbePolicyInfo{}, errLabUncertain
	}

	// A tunnel whose removal was not confirmed stays tracked on its faulted lab: recovery first.
	if lab, ok := l.labs[l.tunnelProfile]; l.tunnelProfile != "" && (!ok || lab.State == LabFaulted) {
		return MultiProbePolicyInfo{}, errLabUncertain
	}

	return l.multiProbePolicyLocked(v, runtimeID)
}

// multiProbePolicyLocked reports the one operation this lifecycle enables: V2 in a generation
// lifecycle, V1 otherwise. The caller must hold l.mu and have checked the lifecycle state.
func (l *LabLifecycle) multiProbePolicyLocked(v *helperauth.Verifier, runtimeID string) (MultiProbePolicyInfo, error) {
	pin, err := l.multiProbes.MultiProbePolicyPin()
	if err != nil {
		return MultiProbePolicyInfo{}, errLabUnavailable
	}

	helperID, fingerprint := v.Identity()

	policy := helperauth.OpPermitMultiProbe
	if l.generationProbes != nil {
		policy = helperauth.OpPermitMultiProbeV2
	}

	info := MultiProbePolicyInfo{
		Policy:          policy,
		IdentIPv4:       pin.String(),
		HelperID:        helperID,
		RuntimeID:       runtimeID,
		PublicKeySHA256: fingerprint,
	}

	if !info.valid() {
		return MultiProbePolicyInfo{}, errLabUnavailable
	}

	return info, nil
}
