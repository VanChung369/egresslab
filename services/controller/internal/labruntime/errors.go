package labruntime

import "errors"

// Codes match the helper's (network-agent internal/helperipc/errors.go); RuntimeUntrusted is
// the controller's own.
const (
	CodeAuthorizationDenied = "AUTHORIZATION_DENIED"
	CodeRuntimeUnavailable  = "RUNTIME_UNAVAILABLE"
	CodeRuntimeUntrusted    = "RUNTIME_UNTRUSTED"
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

var helperCodes = map[string]bool{
	CodeAuthorizationDenied: true, CodeRuntimeUnavailable: true, CodeOperationDisabled: true,
	CodeInvalidRequest: true, CodeLabBusy: true, CodeLabNotFound: true, CodeLabExists: true,
	CodeLabLimit: true, CodeLabFaulted: true, CodeOwnershipMismatch: true, CodeFirewallDrift: true,
	CodeRecoveryRequired: true, CodeKernelIncompatible: true, CodeStateUncertain: true, CodeStageNotFound: true,
	CodeEvidenceUnavailable: true, CodeInternal: true,
}

type Error struct {
	Code    string
	Message string
}

func (e *Error) Error() string { return e.Code + ": " + e.Message }

func Errorf(code, message string) error { return &Error{Code: code, Message: message} }

// ErrorCode returns the code of err, or CodeInternal.
func ErrorCode(err error) string {
	var e *Error
	if errors.As(err, &e) {
		return e.Code
	}

	return CodeInternal
}
