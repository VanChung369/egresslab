package helperauth

import (
	"bytes"
	"crypto/ed25519"
	"net/netip"
	"testing"
)

const proxyStreamGolden = "OA6DjJ3tdkupojWRhq0tTIwoT8uA-ix9D5Rl1NBIP2iPz6u11mp2lpzxtwnVCdmr0JOl1EZFvPYYSgKHrt5ECg"

func TestOpenProxyStreamSigningMessageGolden(t *testing.T) {
	intent, err := NewOpenProxyStreamIntent(testPrepareLeaseIntent(t), netip.MustParseAddrPort("93.184.216.34:443"))
	if err != nil {
		t.Fatal(err)
	}

	private := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x42}, ed25519.SeedSize))

	token, err := Mint(private, Claims{Version: Version, Intent: intent, HelperID: testHelper,
		Nonce: "00112233445566778899aabbccddeeff", IssuedAt: 1795500000, NotAfter: 1795500030})
	if err != nil {
		t.Fatal(err)
	}

	if token.Signature != proxyStreamGolden {
		t.Fatalf("proxy stream signature mismatch: %s", token.Signature)
	}
}

func TestOpenProxyStreamIntent(t *testing.T) {
	binding := testPrepareLeaseIntent(t)

	valid, err := NewOpenProxyStreamIntent(binding, netip.MustParseAddrPort("93.184.216.34:443"))
	if err != nil || !ValidOpenProxyStreamIntent(valid) || ValidRevokeEgressLeaseIntent(valid) {
		t.Fatalf("valid stream refused: %v", err)
	}

	if destination, ok := valid.ProxyDestination(); !ok || destination.String() != "93.184.216.34:443" {
		t.Fatal("incorrect stream destination")
	}

	for name, destination := range map[string]string{
		"Cloudflare source": "1.1.1.1:443",
		"ident.me pin":      binding.ProbeIPv4 + ":443",
		"private":           "10.0.0.1:443",
		"documentation":     "192.0.2.1:443",
		"loopback":          "127.0.0.1:443",
		"DNS":               "93.184.216.34:53",
		"DNS over TLS":      "93.184.216.34:853",
		"port zero":         "93.184.216.34:0",
		"IPv6":              "[2606:2800:220:1::1]:443",
	} {
		if _, err := NewOpenProxyStreamIntent(binding, netip.MustParseAddrPort(destination)); err == nil {
			t.Fatalf("%s accepted", name)
		}
	}

	revocation, err := NewRevokeEgressLeaseIntent(binding)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := NewOpenProxyStreamIntent(revocation, netip.MustParseAddrPort("93.184.216.34:443")); err == nil {
		t.Fatal("stream bound to a revocation")
	}

	for _, operation := range []string{OpPrepareEgressLease, OpRevokeEgressLease, OpReserveEgressCandidate} {
		other := valid
		other.Operation = operation

		if validateIntent(other) == nil {
			t.Fatalf("%s accepted a destination", operation)
		}
	}

	noncanonical := valid
	noncanonical.DestinationIPv4 = "093.184.216.34"

	if ValidOpenProxyStreamIntent(noncanonical) {
		t.Fatal("noncanonical destination accepted")
	}
}
