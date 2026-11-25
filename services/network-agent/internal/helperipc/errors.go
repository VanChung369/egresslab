package helperipc

import "errors"

// Error codes carried in Response.Code on every refusal. Clients act on the code; the message is
// for people.
const (
	CodeAuthorizationDenied = "AUTHORIZATION_DENIED"
	CodeRuntimeUnavailable  = "RUNTIME_UNAVAILABLE"
	CodeOperationDisabled   = "OPERATION_DISABLED"
	CodeInvalidRequest      = "INVALID_REQUEST"
	CodeLabBusy             = "LAB_BUSY"
	CodeLabNotFound         = "LAB_NOT_FOUND"
	CodeLabExists           = "LAB_EXISTS"
	CodeLabLimit            = "LAB_LIMIT"
	CodeLabFaulted          = "LAB_FAULTED"
	CodeOwnershipMismatch   = "OWNERSHIP_MISMATCH"
	CodeFirewallDrift       = "FIREWALL_DRIFT"
	CodeRecoveryRequired    = "RECOVERY_REQUIRED"
	CodeKernelIncompatible  = "KERNEL_INCOMPATIBLE"
	CodeStateUncertain      = "STATE_UNCERTAIN"
	CodeStageNotFound       = "STAGE_NOT_FOUND"
	CodeEvidenceUnavailable = "EVIDENCE_UNAVAILABLE"
	CodeInternal            = "INTERNAL"
)

var knownCodes = map[string]bool{
	CodeAuthorizationDenied: true, CodeRuntimeUnavailable: true, CodeOperationDisabled: true,
	CodeInvalidRequest: true, CodeLabBusy: true, CodeLabNotFound: true, CodeLabExists: true,
	CodeLabLimit: true, CodeLabFaulted: true, CodeOwnershipMismatch: true, CodeFirewallDrift: true,
	CodeRecoveryRequired: true, CodeKernelIncompatible: true, CodeStateUncertain: true, CodeStageNotFound: true,
	CodeEvidenceUnavailable: true, CodeInternal: true,
}

// Error is a refusal as the client sees it.
type Error struct {
	Code    string
	Message string
}

func (e *Error) Error() string { return e.Message }

// ErrorCode returns the code of err, or CodeInternal.
func ErrorCode(err error) string {
	var e *Error
	if errors.As(err, &e) && knownCodes[e.Code] {
		return e.Code
	}

	return CodeInternal
}

// Sentinels a LabBackend wraps so the helper can classify kernel failures without parsing text.
var (
	ErrLabRecoveryRequired   = errors.New("leftover lab resources must be recovered first")
	ErrLabKernelIncompatible = errors.New("kernel adds devices to new namespaces")
	ErrLabFirewallDrift      = errors.New("lab firewall drifted")
	ErrLabTopology           = errors.New("lab topology changed")
)
