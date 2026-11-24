//go:build linux

package helperipc

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/VanChung369/egresslab/services/network-agent/internal/helperauth"
)

// TestHelperInfoAndEpochBinding simulates two helper generations with two servers that share a
// public key but have different helper IDs. The real restart is covered by the WSL e2e script.
func TestHelperInfoAndEpochBinding(t *testing.T) {
	requireUnprivileged(t)

	ctx := context.Background()

	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	digest := sha256.Sum256(public)
	wantFingerprint := hex.EncodeToString(digest[:])

	newGeneration := func() (string, *HelperInfo) {
		t.Helper()

		id, err := helperauth.NewHelperID()
		if err != nil {
			t.Fatal(err)
		}

		v, err := helperauth.NewVerifier(public, id)
		if err != nil {
			t.Fatal(err)
		}

		socket := serveAuthorizedTest(t, v)

		resp, err := Call(ctx, socket, OpHelperInfo)
		if err != nil ||
			resp.Info == nil ||
			!resp.Info.AuthorizationConfigured ||
			resp.Info.HelperID != id ||
			resp.Info.PublicKeySHA256 != wantFingerprint ||
			resp.NetworkReady {
			t.Fatalf("invalid helper info: %+v %v", resp, err)
		}

		return socket, resp.Info
	}

	firstSocket, firstInfo := newGeneration()
	secondSocket, secondInfo := newGeneration()

	if firstInfo.HelperID == secondInfo.HelperID {
		t.Fatal("helper ID repeated across generations")
	}

	intent := testIntent()

	mint := func(id string) helperauth.SignedCapability {
		t.Helper()

		claims, err := helperauth.NewClaims(intent, id, time.Now())
		if err != nil {
			t.Fatal(err)
		}

		token, err := helperauth.Mint(private, claims)
		if err != nil {
			t.Fatal(err)
		}

		return token
	}

	consumed := mint(firstInfo.HelperID)
	unused := mint(firstInfo.HelperID)

	if _, err := CheckCapability(ctx, firstSocket, intent, consumed); err != nil {
		t.Fatal(err)
	}

	for _, old := range []helperauth.SignedCapability{consumed, unused} {
		if _, err := CheckCapability(ctx, secondSocket, intent, old); err == nil || err.Error() != "authorization denied" {
			t.Fatalf("old epoch accepted: %v", err)
		}
	}

	if _, err := CheckCapability(ctx, secondSocket, intent, mint(secondInfo.HelperID)); err != nil {
		t.Fatal(err)
	}
}

func TestHelperInfoWithoutAuthorization(t *testing.T) {
	socket := serveAuthorizedTest(t, nil)

	resp, err := Call(context.Background(), socket, OpHelperInfo)
	if err != nil ||
		resp.Info == nil ||
		resp.Info.AuthorizationConfigured ||
		resp.Info.HelperID != "" ||
		resp.Info.PublicKeySHA256 != "" {
		t.Fatalf("unexpected helper info: %+v %v", resp, err)
	}
}

// fakeHelper answers every request with reply(request), without any server-side checks, to test
// the client's response validation.
func fakeHelper(t *testing.T, reply func(Request) Response) string {
	t.Helper()

	return serveWith(t, func(ctx context.Context, listener *net.UnixListener) error {
		go func() {
			<-ctx.Done()
			listener.Close()
		}()

		for {
			conn, err := listener.AcceptUnix()
			if err != nil {
				if ctx.Err() != nil {
					return nil
				}
				return err
			}

			var req Request
			if ReadFrame(conn, &req) == nil {
				_ = WriteFrame(conn, reply(req))
			}

			conn.Close()
		}
	})
}

func TestClientValidatesHelperInfo(t *testing.T) {
	ctx := context.Background()
	fingerprint := strings.Repeat("ab", sha256.Size)
	id := "helper_0123456789abcdef0123456789abcdef"

	good := &HelperInfo{AuthorizationConfigured: true, HelperID: id, PublicKeySHA256: fingerprint}

	tests := []struct {
		name    string
		op      string
		ok      bool
		info    *HelperInfo
		wantErr string
	}{
		{"configured", OpHelperInfo, true, good, ""},
		{"unconfigured", OpHelperInfo, true, &HelperInfo{}, ""},
		{"metadata on Ping", OpPing, true, good, "unexpected helper identity metadata"},
		{"metadata on a failed HelperInfo", OpHelperInfo, false, good, "unexpected helper identity metadata"},
		{"missing metadata", OpHelperInfo, true, nil, "invalid helper identity metadata"},
		{"uppercase fingerprint", OpHelperInfo, true,
			&HelperInfo{AuthorizationConfigured: true, HelperID: id, PublicKeySHA256: strings.ToUpper(fingerprint)},
			"invalid helper identity metadata"},
		{"short fingerprint", OpHelperInfo, true,
			&HelperInfo{AuthorizationConfigured: true, HelperID: id, PublicKeySHA256: fingerprint[:62]},
			"invalid helper identity metadata"},
		{"malformed helper ID", OpHelperInfo, true,
			&HelperInfo{AuthorizationConfigured: true, HelperID: "helper_1234", PublicKeySHA256: fingerprint},
			"invalid helper identity metadata"},
		{"ID while unconfigured", OpHelperInfo, true, &HelperInfo{HelperID: id}, "invalid helper identity metadata"},
		{"fingerprint while unconfigured", OpHelperInfo, true,
			&HelperInfo{PublicKeySHA256: fingerprint}, "invalid helper identity metadata"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			socket := fakeHelper(t, func(req Request) Response {
				resp := Response{Version: Version, Operation: req.Operation, OK: tt.ok, Info: tt.info}
				if !tt.ok {
					resp.Error = "refused"
				}
				return resp
			})

			_, err := Call(ctx, socket, tt.op)

			if tt.wantErr == "" && err != nil || tt.wantErr != "" && (err == nil || err.Error() != tt.wantErr) {
				t.Fatalf("got %v, want %q", err, tt.wantErr)
			}
		})
	}

	t.Run("metadata on AuthorizeCheck", func(t *testing.T) {
		socket := fakeHelper(t, func(req Request) Response {
			return Response{Version: Version, Operation: req.Operation, OK: true, Info: good}
		})

		var capability helperauth.SignedCapability
		if _, err := CheckCapability(ctx, socket, testIntent(), capability); err == nil ||
			err.Error() != "unexpected helper identity metadata" {
			t.Fatalf("got %v", err)
		}
	})
}
