package agent

import (
	"fmt"
	"os"
	"runtime"
)

type SystemInfoResponse struct {
	OS           string `json:"os"`
	Architecture string `json:"architecture"`
	Hostname     string `json:"hostname"`
	GoVersion    string `json:"go_version"`
}

type systemInfoProvider func() (SystemInfoResponse, error)

func discoverSystemInfo() (SystemInfoResponse, error) {

	hostname, err := os.Hostname()

	if err != nil {
		return SystemInfoResponse{}, fmt.Errorf(
			"read hostname: %w",
			err,
		)
	}

	return SystemInfoResponse{
		OS:           runtime.GOOS,
		Architecture: runtime.GOARCH,
		Hostname:     hostname,
		GoVersion:    runtime.Version(),
	}, nil
}
