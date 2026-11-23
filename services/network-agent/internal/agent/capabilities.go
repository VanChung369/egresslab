package agent

import (
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
)

const capNetAdminBit = 12

type CapabilityCheck struct {
	Status string `json:"status"`
	Detail string `json:"detail"`
}

type CapabilitiesResponse struct {
	OS           string                     `json:"os"`
	NetworkReady bool                       `json:"network_ready"`
	Checks       map[string]CapabilityCheck `json:"checks"`
}

type capabilityProbe struct {
	OS                string
	LookPath          func(string) (string, error)
	NamespaceHandle   func() (bool, error)
	NetAdminEffective func() (bool, error)
}

type capabilityProvider func() CapabilitiesResponse

func discoverCapabilities() CapabilitiesResponse {
	return detectCapabilities(capabilityProbe{
		OS:                runtime.GOOS,
		LookPath:          exec.LookPath,
		NamespaceHandle:   hasNetworkNamespaceHandle,
		NetAdminEffective: readEffectiveNetAdmin,
	})
}

func detectCapabilities(p capabilityProbe) CapabilitiesResponse {
	keys := []string{
		"iproute2",
		"wireguard_tools",
		"nftables",
		"network_namespace",
		"cap_net_admin_effective",
	}

	result := CapabilitiesResponse{
		OS:           p.OS,
		NetworkReady: false,
		Checks:       make(map[string]CapabilityCheck, len(keys)),
	}

	if p.OS != "linux" {
		for _, key := range keys {
			result.Checks[key] = CapabilityCheck{Status: "unsupported", Detail: "Linux-only inspection"}
		}

		return result
	}

	binaries := map[string]string{
		"iproute2":        "ip",
		"wireguard_tools": "wg",
		"nftables":        "nft",
	}

	for key, executable := range binaries {
		_, err := p.LookPath(executable)

		switch {
		case err == nil:
			result.Checks[key] = CapabilityCheck{Status: "detected", Detail: "Executable found in PATH"}

		case errors.Is(err, exec.ErrNotFound):
			result.Checks[key] = CapabilityCheck{Status: "missing", Detail: "Executable not found in PATH"}

		default:
			result.Checks[key] = CapabilityCheck{Status: "unknown", Detail: "Could not inspect executable"}
		}
	}

	exists, err := p.NamespaceHandle()

	switch {
	case err != nil:
		result.Checks["network_namespace"] = CapabilityCheck{
			Status: "unknown",
			Detail: "Cannot inspect namespace handle",
		}

	case exists:
		result.Checks["network_namespace"] = CapabilityCheck{Status: "detected", Detail: "/proc/self/ns/net exists"}

	default:
		result.Checks["network_namespace"] = CapabilityCheck{Status: "missing", Detail: "/proc/self/ns/net not found"}
	}

	effective, err := p.NetAdminEffective()

	switch {
	case err != nil:
		result.Checks["cap_net_admin_effective"] = CapabilityCheck{Status: "unknown", Detail: "Cannot inspect CapEff"}

	case effective:
		result.Checks["cap_net_admin_effective"] = CapabilityCheck{
			Status: "detected",
			Detail: "CAP_NET_ADMIN bit present in CapEff",
		}

	default:
		result.Checks["cap_net_admin_effective"] = CapabilityCheck{
			Status: "missing",
			Detail: "CAP_NET_ADMIN bit absent from CapEff",
		}
	}

	return result
}

func hasNetworkNamespaceHandle() (bool, error) {
	_, err := os.Lstat("/proc/self/ns/net")
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}

	return err == nil, err
}

func readEffectiveNetAdmin() (bool, error) {
	status, err := os.ReadFile("/proc/self/status")
	if err != nil {
		return false, fmt.Errorf("read process status: %w", err)
	}

	return parseEffectiveNetAdmin(status)
}

func parseEffectiveNetAdmin(data []byte) (bool, error) {
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 || fields[0] != "CapEff:" {
			continue
		}

		if len(fields) != 2 {
			return false, errors.New("malformed CapEff field")
		}

		mask, err := strconv.ParseUint(fields[1], 16, 64)
		if err != nil {
			return false, fmt.Errorf("parse CapEff: %w", err)
		}

		return mask&(uint64(1)<<capNetAdminBit) != 0, nil
	}

	return false, errors.New("CapEff field not found")
}

func handleCapabilities(getCapabilities capabilityProvider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, getCapabilities())
	}
}
