// Command egresslab-helperctl sends one read-only operation (ping, recover-scan or helper-info) to
// the privileged network helper and prints the response as JSON. Run it as the agent user, not
// with sudo. It cannot send AuthorizeCheck.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"runtime"
	"time"

	"github.com/VanChung369/egresslab/services/network-agent/internal/helperipc"
)

func main() {
	if runtime.GOOS != "linux" || len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage (Linux only): egresslab-helperctl ping|recover-scan|helper-info")
		os.Exit(2)
	}

	var op string

	switch os.Args[1] {
	case "ping":
		op = helperipc.OpPing
	case "recover-scan":
		op = helperipc.OpRecoverScan
	case "helper-info":
		op = helperipc.OpHelperInfo
	default:
		fmt.Fprintln(os.Stderr, "supported operations: ping, recover-scan, helper-info")
		os.Exit(2)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
	defer cancel()

	result, err := helperipc.Call(ctx, helperipc.SocketPath, op)
	if err != nil {
		fmt.Fprintln(os.Stderr, "helper IPC:", err)
		os.Exit(1)
	}

	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")

	if err := encoder.Encode(result); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
