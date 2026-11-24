package agent

import (
	"errors"
	"testing"
)

func TestUseVPNStageBinding(t *testing.T) {
	path, _ := writeVaultFixture(t, "198.51.100.7")

	vault := NewWireGuardConfigVault()
	defer vault.Close()

	first, err := vault.StageFile(vaultProfileA, path)
	if err != nil {
		t.Fatal(err)
	}

	calls := 0
	use := func(cfg *ImportedWireGuardConfig) error {
		calls++
		if cfg == nil {
			t.Fatal("missing staged config")
		}
		return nil
	}

	if err := vault.useVPNStage(vaultProfileA, first.StageID, use); err != nil {
		t.Fatal(err)
	}

	if err := vault.useVPNStage(vaultProfileB, first.StageID, use); !errors.Is(err, ErrWGStageNotFound) {
		t.Fatalf("foreign stage accepted: %v", err)
	}

	if err := vault.useVPNStage(vaultProfileA, "wgstage_x", use); !errors.Is(err, ErrWGStageNotFound) {
		t.Fatalf("malformed stage accepted: %v", err)
	}

	// Replacing the config invalidates its old stage ID.
	second, err := vault.StageFile(vaultProfileA, path)
	if err != nil {
		t.Fatal(err)
	}

	if err := vault.useVPNStage(vaultProfileA, first.StageID, use); !errors.Is(err, ErrWGStageNotFound) {
		t.Fatalf("old stage accepted: %v", err)
	}

	if err := vault.useVPNStage(vaultProfileA, second.StageID, use); err != nil {
		t.Fatal(err)
	}

	if err := vault.Revoke(vaultProfileA); err != nil {
		t.Fatal(err)
	}

	if err := vault.useVPNStage(vaultProfileA, second.StageID, use); !errors.Is(err, ErrWGStageNotFound) {
		t.Fatalf("revoked stage accepted: %v", err)
	}

	vault.Close()
	if err := vault.useVPNStage(vaultProfileA, second.StageID, use); !errors.Is(err, ErrWGVaultClosed) {
		t.Fatalf("closed vault: %v", err)
	}

	if calls != 2 {
		t.Fatalf("unexpected config access count: %d", calls)
	}
}

func TestUseVPNStageRejectsUnsupportedConfig(t *testing.T) {
	// The VPN engine needs an IPv4 literal endpoint; hostnames come in Step 27C.
	path, _ := writeVaultFixture(t, "vpn.example.com")

	vault := NewWireGuardConfigVault()
	defer vault.Close()

	stage, err := vault.StageFile(vaultProfileA, path)
	if err != nil {
		t.Fatal(err)
	}

	err = vault.useVPNStage(vaultProfileA, stage.StageID, func(*ImportedWireGuardConfig) error {
		t.Fatal("unsupported config reached the runtime")
		return nil
	})

	if !errors.Is(err, ErrUnsupportedTunnelConfig) {
		t.Fatalf("unexpected compatibility error: %v", err)
	}
}
