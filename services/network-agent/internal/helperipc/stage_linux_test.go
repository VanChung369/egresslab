//go:build linux

package helperipc

import (
	"context"
	"errors"
	"net"
	"os"
	"testing"

	"github.com/VanChung369/egresslab/services/network-agent/internal/helperauth"
)

func TestStageInfoIPC(t *testing.T) {
	requireUnprivileged(t)

	labs, _, verifier, mint := newLifecycleFixture(t)

	expected := StageInfo{ProfileID: lifecycleProfile, StageID: "wgstage_0123456789abcdef0123456789abcdef", Compatible: true}

	socket := serveWith(t, func(ctx context.Context, listener *net.UnixListener) error {
		return ServeWith(ctx, listener, uint32(os.Getuid()), ServerOptions{
			Labs:     labs,
			Verifier: verifier,
			ReadStage: func(profileID string) (StageInfo, error) {
				switch profileID {
				case expected.ProfileID:
					return expected, nil
				case "profile_eeeeeeeeeeeeeeee":
					return StageInfo{}, errors.New("vault closed")
				case "profile_dddddddddddddddd":
					return StageInfo{ProfileID: lifecycleProfile, StageID: expected.StageID}, nil
				}
				return StageInfo{}, ErrStageNotFound
			},
		})
	})

	ctx := context.Background()

	resp, err := ReadStageInfo(ctx, socket, expected.ProfileID)
	if err != nil || resp.Stage == nil || *resp.Stage != expected || resp.NetworkReady {
		t.Fatalf("unexpected stage info: %+v %v", resp, err)
	}

	if _, err := ReadStageInfo(ctx, socket, "profile_ffffffffffffffff"); ErrorCode(err) != CodeStageNotFound {
		t.Fatalf("missing stage: %v", err)
	}

	for _, profile := range []string{"profile_eeeeeeeeeeeeeeee", "profile_dddddddddddddddd"} {
		if _, err := ReadStageInfo(ctx, socket, profile); ErrorCode(err) != CodeInternal {
			t.Fatalf("%s: vault failure or another profile's stage: %v", profile, err)
		}
	}

	intent := helperauth.Intent{Operation: OpStageInfo, ProfileID: expected.ProfileID}
	withNamespace := intent
	withNamespace.Namespace = "egresslab-lab-0123456789abcdef"

	for name, req := range map[string]Request{
		"namespace":    {Version: Version, Operation: OpStageInfo, Intent: &withNamespace},
		"capability":   {Version: Version, Operation: OpStageInfo, Intent: &intent, Capability: mint(lifecycleProfile).Capability},
		"no intent":    {Version: Version, Operation: OpStageInfo},
		"wrong intent": {Version: Version, Operation: OpStageInfo, Intent: &helperauth.Intent{Operation: OpVerifyLab, ProfileID: lifecycleProfile}},
	} {
		if resp := rawRequest(t, socket, req); resp.OK || resp.Code != CodeInvalidRequest || resp.Stage != nil {
			t.Fatalf("%s accepted: %+v", name, resp)
		}
	}

	// Tunnel operations stay disabled.
	if resp := rawRequest(t, socket, Request{Version: Version, Operation: helperauth.OpConnectTunnel}); resp.OK ||
		resp.Code != CodeOperationDisabled {
		t.Fatal("tunnel operation unexpectedly enabled")
	}
}

func TestStageInfoDisabled(t *testing.T) {
	socket := serveAuthorizedTest(t, nil)

	if _, err := ReadStageInfo(context.Background(), socket, lifecycleProfile); ErrorCode(err) != CodeOperationDisabled {
		t.Fatalf("disabled vault: %v", err)
	}

	if _, err := ReadStageInfo(context.Background(), socket, "profile_x"); ErrorCode(err) != CodeInvalidRequest {
		t.Fatalf("malformed profile reached the socket: %v", err)
	}
}

func TestServeRefusesVaultWithoutLifecycle(t *testing.T) {
	read := func(string) (StageInfo, error) { return StageInfo{}, ErrStageNotFound }
	_, _, verifier, _ := newLifecycleFixture(t)

	for name, opts := range map[string]ServerOptions{
		"no lifecycle": {Verifier: verifier, ReadStage: read},
		"no verifier":  {ReadStage: read},
	} {
		if err := ServeWith(context.Background(), nil, 1000, opts); err == nil ||
			err.Error() != "managed vault requires authorized lab lifecycle" {
			t.Errorf("%s: %v", name, err)
		}
	}
}
