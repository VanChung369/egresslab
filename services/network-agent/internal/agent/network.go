package agent

import (
	"fmt"
	"net"
)

type NetworkInterface struct {
	Index        int      `json:"index"`
	Name         string   `json:"name"`
	MTU          int      `json:"mtu"`
	HardwareAddr string   `json:"hardware_addr,omitempty"`
	Flags        []string `json:"flags"`
	Addresses    []string `json:"addresses"`
}

type NetworkInterfacesResponse struct {
	Interfaces []NetworkInterface `json:"interfaces"`
}

type interfaceProvider func() ([]NetworkInterface, error)

func discoverNetworkInterfaces() ([]NetworkInterface, error) {
	systemInterfaces, err := net.Interfaces()

	if err != nil {
		return nil, fmt.Errorf(
			"list network interfaces: %w",
			err,
		)
	}

	result := make([]NetworkInterface, 0, len(systemInterfaces))

	for _, iface := range systemInterfaces {
		addresses, err := iface.Addrs()
		if err != nil {
			return nil, fmt.Errorf(
				"list addresses for interface %q: %w",
				iface.Name,
				err,
			)
		}

		addressList := make([]string, 0, len(addresses))

		for _, address := range addresses {
			addressList = append(
				addressList,
				address.String(),
			)
		}

		result = append(result, NetworkInterface{
			Index:        iface.Index,
			Name:         iface.Name,
			MTU:          iface.MTU,
			HardwareAddr: iface.HardwareAddr.String(),
			Flags:        interfaceFlags(iface.Flags),
			Addresses:    addressList,
		})
	}
	return result, nil
}

func interfaceFlags(flags net.Flags) []string {

	result := make([]string, 0, 6)

	// Always report the administrative state first so clients can rely on
	// "up"/"down" being present, even when other flags are set.
	if flags&net.FlagUp != 0 {
		result = append(result, "up")
	} else {
		result = append(result, "down")
	}

	if flags&net.FlagRunning != 0 {
		result = append(result, "running")
	}

	if flags&net.FlagBroadcast != 0 {
		result = append(result, "broadcast")
	}

	if flags&net.FlagLoopback != 0 {
		result = append(result, "loopback")
	}

	if flags&net.FlagPointToPoint != 0 {
		result = append(result, "point-to-point")
	}

	if flags&net.FlagMulticast != 0 {
		result = append(result, "multicast")
	}

	return result
}
