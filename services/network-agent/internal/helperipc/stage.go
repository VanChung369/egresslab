package helperipc

import (
	"context"
	"errors"
	"regexp"

	"github.com/VanChung369/egresslab/services/network-agent/internal/helperauth"
)

// OpStageInfo reads which WireGuard stage a profile has in the managed vault: metadata only, never
// the endpoint, keys or config.
const OpStageInfo = "StageInfo"

var (
	ErrStageNotFound = errors.New("WireGuard stage not found")
	stageInfoPattern = regexp.MustCompile(`^wgstage_[0-9a-f]{32}$`)
)

type StageInfo struct {
	ProfileID  string `json:"profile_id"`
	StageID    string `json:"stage_id"`
	Compatible bool   `json:"vpn_lab_compatible"`
}

// StageReader returns ErrStageNotFound when the profile has no stage.
type StageReader func(profileID string) (StageInfo, error)

func validStageIntent(in *helperauth.Intent) bool {
	return in != nil &&
		in.Operation == OpStageInfo &&
		helperauth.ValidProfileID(in.ProfileID) &&
		in.Namespace == "" &&
		in.StageID == "" &&
		in.ProbeIPv4 == "" &&
		in.TunnelGeneration == "" &&
		in.EvidenceNonce == ""
}

func validStageInfo(info *StageInfo, profileID string) bool {
	return info != nil &&
		info.ProfileID == profileID &&
		helperauth.ValidProfileID(info.ProfileID) &&
		stageInfoPattern.MatchString(info.StageID)
}

func validStageResponse(req Request, resp Response) bool {
	if req.Operation != OpStageInfo || !resp.OK {
		return resp.Stage == nil
	}

	return validStageIntent(req.Intent) && validStageInfo(resp.Stage, req.Intent.ProfileID)
}

func ReadStageInfo(ctx context.Context, socketPath, profileID string) (Response, error) {
	if !helperauth.ValidProfileID(profileID) {
		return Response{}, &Error{Code: CodeInvalidRequest, Message: "invalid profile ID"}
	}

	return callRequest(ctx, socketPath, Request{
		Version:   Version,
		Operation: OpStageInfo,
		Intent:    &helperauth.Intent{Operation: OpStageInfo, ProfileID: profileID},
	})
}
