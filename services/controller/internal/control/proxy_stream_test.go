//go:build windows || linux || darwin

package control

import (
	"errors"
	"net/netip"
	"testing"
)

func TestMintProxyStream(t *testing.T) {
	f := newReleaseTestFixture(t)
	hold := f.admission.hold
	destination := netip.MustParseAddrPort("93.184.216.34:443")

	capability, err := f.authority.MintProxyStream(hold.ID, destination, f.signer, f.admission.runtime,
		f.admission.helper, f.now)
	if err != nil {
		t.Fatal(err)
	}

	binding, err := NewLabPrepareEgressLeaseIntent(hold.Owner.ProfileID, hold.Owner.Namespace, hold.IdentIPv4,
		hold.Owner.TunnelGeneration, hold.EvidenceNonce, hold.ReservationNonce, hold.Owner.RuntimeID,
		f.authority.Info().ID, hold.ID, hold.IPv4.String())
	if err != nil {
		t.Fatal(err)
	}

	expected, err := NewLabOpenProxyStreamIntent(binding, destination)
	if err != nil || capability.Claims.Intent != expected || capability.Claims.HelperID != hold.Owner.HelperEpoch ||
		!verifyIssuedLabCapability(f.admission.publicKey, capability) {
		t.Fatal("incorrect proxy stream capability")
	}

	for name, bad := range map[string]string{
		"Cloudflare source": "1.1.1.1:443",
		"ident.me pin":      hold.IdentIPv4 + ":443",
		"private":           "192.168.1.1:443",
		"DNS":               "93.184.216.34:53",
		"DNS over TLS":      "93.184.216.34:853",
	} {
		if _, err := f.authority.MintProxyStream(hold.ID, netip.MustParseAddrPort(bad), f.signer, f.admission.runtime,
			f.admission.helper, f.now); !errors.Is(err, ErrReservationReleaseInvalid) {
			t.Fatalf("%s accepted: %v", name, err)
		}
	}

	restarted := f.admission.helper
	restarted.HelperID = "helper_ffffffffffffffffffffffffffffffff"

	if _, err := f.authority.MintProxyStream(hold.ID, destination, f.signer, f.admission.runtime, restarted,
		f.now); !errors.Is(err, ErrReservationReleaseInvalid) {
		t.Fatalf("a later helper epoch received a stream: %v", err)
	}

	if _, err := f.authority.MintProxyStream("reservation_ffffffffffffffffffffffffffffffff", destination, f.signer,
		f.admission.runtime, f.admission.helper, f.now); !errors.Is(err, ErrReservationNotFound) {
		t.Fatalf("unknown reservation accepted: %v", err)
	}

	if _, err := f.release(); err != nil {
		t.Fatal(err)
	}

	if _, err := f.authority.MintProxyStream(hold.ID, destination, f.signer, f.admission.runtime, f.admission.helper,
		f.now); !errors.Is(err, ErrReservationNotFound) {
		t.Fatalf("a released hold received a stream: %v", err)
	}
}
