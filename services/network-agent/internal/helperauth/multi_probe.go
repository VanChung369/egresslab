package helperauth

import "net/netip"

const (
	MultiProbeCloudflareSource = "cloudflare_trace"
	MultiProbeCloudflareIPv4   = "1.1.1.1"
	MultiProbeIdentSource      = "ident_me"
)

// reservedMultiProbeIPv4 must stay aligned with the network agent's reservedIPv4 (parseCandidateIPv4);
// helperauth does not import the agent, and a test in the agent package compares the two.
var reservedMultiProbeIPv4 = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),
	netip.MustParsePrefix("10.0.0.0/8"),
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("127.0.0.0/8"),
	netip.MustParsePrefix("169.254.0.0/16"),
	netip.MustParsePrefix("172.16.0.0/12"),
	netip.MustParsePrefix("192.0.0.0/24"),
	netip.MustParsePrefix("192.0.2.0/24"),
	netip.MustParsePrefix("192.88.99.0/24"),
	netip.MustParsePrefix("192.168.0.0/16"),
	netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("198.51.100.0/24"),
	netip.MustParsePrefix("203.0.113.0/24"),
	netip.MustParsePrefix("224.0.0.0/4"),
	netip.MustParsePrefix("240.0.0.0/4"),
}

// ValidPublicProbeIPv4 is the public IPv4 policy for probe destinations and observed addresses.
func ValidPublicProbeIPv4(ip netip.Addr) bool {
	if !ip.Is4() || !ip.IsGlobalUnicast() || ip.IsPrivate() {
		return false
	}

	for _, prefix := range reservedMultiProbeIPv4 {
		if prefix.Contains(ip) {
			return false
		}
	}

	return true
}

// ValidMultiProbePin checks the one variable destination of PermitMultiProbeV1: a canonical public
// IPv4 address other than Cloudflare's. It does not establish that ident.me operates it.
func ValidMultiProbePin(raw string) bool {
	ip, err := netip.ParseAddr(raw)

	return err == nil && ValidPublicProbeIPv4(ip) && ip.String() == raw && raw != MultiProbeCloudflareIPv4
}

// NewMultiProbeIntent binds the V1 policy to one profile, namespace and ident.me pin.
func NewMultiProbeIntent(profileID, namespace, identPin string) (Intent, error) {
	intent := Intent{
		Operation: OpPermitMultiProbe,
		ProfileID: profileID,
		Namespace: namespace,
		ProbeIPv4: identPin,
	}

	if err := validateIntent(intent); err != nil {
		return Intent{}, err
	}

	return intent, nil
}
