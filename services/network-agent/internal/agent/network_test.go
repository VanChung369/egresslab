package agent

import (
	"errors"
	"net"
	"reflect"
	"testing"
)

func TestDescribeInterfaces(t *testing.T) {

	systemInterfaces := []net.Interface{
		{
			Index: 1,
			Name:  "lo0",
			MTU:   16384,
			Flags: net.FlagUp | net.FlagLoopback,
		},
		{
			Index:        4,
			Name:         "en0",
			MTU:          1500,
			HardwareAddr: net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x01},
			Flags:        net.FlagUp | net.FlagRunning | net.FlagBroadcast,
		},
	}

	listAddresses := func(iface *net.Interface) ([]net.Addr, error) {

		if iface.Name == "lo0" {
			return []net.Addr{
				&net.IPNet{
					IP:   net.IPv4(127, 0, 0, 1),
					Mask: net.CIDRMask(8, 32),
				},
			}, nil
		}

		return nil, nil
	}

	result := describeInterfaces(systemInterfaces, listAddresses)

	expected := []NetworkInterface{
		{
			Index:     1,
			Name:      "lo0",
			MTU:       16384,
			Flags:     []string{"up", "loopback"},
			Addresses: []string{"127.0.0.1/8"},
		},
		{
			Index:        4,
			Name:         "en0",
			MTU:          1500,
			HardwareAddr: "02:00:00:00:00:01",
			Flags:        []string{"up", "running", "broadcast"},
			Addresses:    []string{},
		},
	}

	if !reflect.DeepEqual(result, expected) {
		t.Errorf(
			"expected %+v, got %+v",
			expected,
			result,
		)
	}
}

// A VPN tunnel can vanish between net.Interfaces() and Addrs(). That one
// interface is dropped; the rest of the listing still comes back.
func TestDescribeInterfacesSkipsFailedInterface(t *testing.T) {

	systemInterfaces := []net.Interface{
		{Index: 1, Name: "lo0", Flags: net.FlagUp | net.FlagLoopback},
		{Index: 20, Name: "utun9", Flags: net.FlagUp | net.FlagPointToPoint},
		{Index: 4, Name: "en0", Flags: net.FlagUp | net.FlagBroadcast},
	}

	listAddresses := func(iface *net.Interface) ([]net.Addr, error) {

		if iface.Name == "utun9" {
			return nil, errors.New("no such network interface")
		}

		return nil, nil
	}

	result := describeInterfaces(systemInterfaces, listAddresses)

	names := make([]string, 0, len(result))

	for _, iface := range result {
		names = append(names, iface.Name)
	}

	if expected := []string{"lo0", "en0"}; !reflect.DeepEqual(names, expected) {
		t.Errorf(
			"expected interfaces %v, got %v",
			expected,
			names,
		)
	}
}

func TestInterfaceFlags(t *testing.T) {

	tests := []struct {
		name     string
		flags    net.Flags
		expected []string
	}{
		{
			name:     "loopback up",
			flags:    net.FlagUp | net.FlagLoopback,
			expected: []string{"up", "loopback"},
		},
		{
			name: "ethernet up and running",
			flags: net.FlagUp | net.FlagRunning |
				net.FlagBroadcast | net.FlagMulticast,
			expected: []string{"up", "running", "broadcast", "multicast"},
		},
		{
			name:     "down with other flags set",
			flags:    net.FlagPointToPoint | net.FlagMulticast,
			expected: []string{"down", "point-to-point", "multicast"},
		},
		{
			name:     "no flags",
			flags:    0,
			expected: []string{"down"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			result := interfaceFlags(tt.flags)

			if !reflect.DeepEqual(result, tt.expected) {
				t.Errorf(
					"expected %v, got %v",
					tt.expected,
					result,
				)
			}
		})
	}
}
