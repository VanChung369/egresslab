package helperauth

import "net/netip"

// ValidProxyDestination accepts a canonical public IPv4 address other than the probe sources (the
// Cloudflare source and the ident.me pin), and a TCP port other than 0 and the DNS ports.
func ValidProxyDestination(ipv4 string, port uint16, identPin string) bool {
	ip, err := netip.ParseAddr(ipv4)

	return err == nil && ValidPublicProbeIPv4(ip) && ip.String() == ipv4 &&
		ipv4 != MultiProbeCloudflareIPv4 && ipv4 != identPin &&
		port != 0 && port != 53 && port != 853
}

// NewOpenProxyStreamIntent binds one destination to a preparation intent.
func NewOpenProxyStreamIntent(binding Intent, destination netip.AddrPort) (Intent, error) {
	if binding.Operation != OpPrepareEgressLease || !destination.IsValid() {
		return Intent{}, ErrInvalidCapability
	}

	if err := validateIntent(binding); err != nil {
		return Intent{}, err
	}

	binding.Operation = OpOpenProxyStream
	binding.DestinationIPv4 = destination.Addr().String()
	binding.DestinationPort = destination.Port()

	if err := validateIntent(binding); err != nil {
		return Intent{}, err
	}

	return binding, nil
}

func ValidOpenProxyStreamIntent(intent Intent) bool {
	return intent.Operation == OpOpenProxyStream && validateIntent(intent) == nil
}

// ProxyDestination is the stream's destination as an address and port.
func (in Intent) ProxyDestination() (netip.AddrPort, bool) {
	ip, err := netip.ParseAddr(in.DestinationIPv4)
	if err != nil || in.Operation != OpOpenProxyStream {
		return netip.AddrPort{}, false
	}

	return netip.AddrPortFrom(ip, in.DestinationPort), true
}
