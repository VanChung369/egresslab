// Command egresslab-helperctl is the unprivileged client of the privileged network helper. It
// prints each response as JSON. On failure it exits 1 and still prints a JSON response whose
// "code" says why. A capability is read from stdin only, never from argv.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"runtime"
	"time"

	"github.com/VanChung369/egresslab/services/network-agent/internal/agent"
	"github.com/VanChung369/egresslab/services/network-agent/internal/helperauth"
	"github.com/VanChung369/egresslab/services/network-agent/internal/helperipc"
)

const maxCapabilityBytes = 8192

var readOnlyOperations = map[string]string{
	"ping":               helperipc.OpPing,
	"helper-info":        helperipc.OpHelperInfo,
	"recover-scan":       helperipc.OpRecoverScan,
	"list-labs":          helperipc.OpListLabs,
	"multi-probe-policy": helperipc.OpMultiProbePolicy,
}

func main() {
	if runtime.GOOS != "linux" {
		fail(invalid("helperctl requires Linux"))
	}

	if err := agent.RequireUnprivilegedAgent(); err != nil {
		fail(invalid(err.Error()))
	}

	if err := run(os.Args[1:], os.Stdin, os.Stdout); err != nil {
		fail(err)
	}
}

func invalid(message string) error {
	return &helperipc.Error{Code: helperipc.CodeInvalidRequest, Message: message}
}

func fail(err error) {
	writeFailure(os.Stdout, err)
	fmt.Fprintln(os.Stderr, "helperctl:", err)
	os.Exit(1)
}

func writeFailure(w io.Writer, err error) {
	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")

	_ = encoder.Encode(helperipc.Response{
		Version: helperipc.Version,
		Code:    helperipc.ErrorCode(err),
		Error:   err.Error(),
	})
}

func run(args []string, stdin io.Reader, stdout io.Writer) error {
	if len(args) == 0 {
		return usageError()
	}

	// A probe's worst case (failed probe plus independent cleanups) is longer than other operations.
	timeout := 135 * time.Second
	if args[0] == "probe-egress" || args[0] == "probe-egress-multi" {
		timeout = 200 * time.Second
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	var result helperipc.Response
	var err error

	switch args[0] {
	case "ping", "helper-info", "recover-scan", "list-labs", "multi-probe-policy":
		if len(args) != 1 {
			return usageError()
		}

		result, err = helperipc.Call(ctx, helperipc.SocketPath, readOnlyOperations[args[0]])

	case "create-lab":
		if len(args) != 2 || !helperauth.ValidProfileID(args[1]) {
			return usageError()
		}

		capability, readErr := readCapability(stdin)
		if readErr != nil {
			return readErr
		}

		result, err = helperipc.CreateSealedLab(ctx, helperipc.SocketPath, args[1], capability)

	case "connect-tunnel":
		if len(args) != 4 || !helperauth.ValidProfileID(args[1]) || !helperauth.ValidLabNamespace(args[2]) ||
			!helperauth.ValidStageID(args[3]) {
			return usageError()
		}

		capability, readErr := readCapability(stdin)
		if readErr != nil {
			return readErr
		}

		result, err = helperipc.ConnectTunnel(ctx, helperipc.SocketPath, args[1], args[2], args[3], capability)

	case "probe-egress":
		// No destination, URL or port argument: the helper probes only its fixed endpoint.
		if len(args) != 3 || !helperauth.ValidProfileID(args[1]) || !helperauth.ValidLabNamespace(args[2]) {
			return usageError()
		}

		capability, readErr := readCapability(stdin)
		if readErr != nil {
			return readErr
		}

		result, err = helperipc.ProbeEgress(ctx, helperipc.SocketPath, args[1], args[2], capability)

	case "multi-probe-target":
		if len(args) != 3 || !helperauth.ValidProfileID(args[1]) || !helperauth.ValidLabNamespace(args[2]) {
			return usageError()
		}

		result, err = helperipc.ReadMultiProbeTarget(ctx, helperipc.SocketPath, args[1], args[2])

	case "probe-egress-multi":
		// V2 only: the signed intent names the generation and the pin; neither comes from argv.
		if len(args) != 3 || !helperauth.ValidProfileID(args[1]) || !helperauth.ValidLabNamespace(args[2]) {
			return usageError()
		}

		capability, readErr := readCapability(stdin)
		if readErr != nil {
			return readErr
		}

		result, err = helperipc.ProbeEgressMultiV2(ctx, helperipc.SocketPath, args[1], args[2], capability)

	case "disconnect":
		if len(args) != 3 || !helperauth.ValidProfileID(args[1]) || !helperauth.ValidLabNamespace(args[2]) {
			return usageError()
		}

		result, err = helperipc.DisconnectTunnel(ctx, helperipc.SocketPath, args[1], args[2])

	case "stage-info":
		if len(args) != 2 || !helperauth.ValidProfileID(args[1]) {
			return usageError()
		}

		result, err = helperipc.ReadStageInfo(ctx, helperipc.SocketPath, args[1])

	case "verify-lab", "delete-lab":
		if len(args) != 3 || !helperauth.ValidProfileID(args[1]) || !helperauth.ValidLabNamespace(args[2]) {
			return usageError()
		}

		if args[0] == "verify-lab" {
			result, err = helperipc.VerifySealedLab(ctx, helperipc.SocketPath, args[1], args[2])
		} else {
			result, err = helperipc.DeleteSealedLab(ctx, helperipc.SocketPath, args[1], args[2])
		}

	default:
		return usageError()
	}

	if err != nil {
		return err
	}

	encoder := json.NewEncoder(stdout)
	encoder.SetIndent("", "  ")

	return encoder.Encode(result)
}

func readCapability(r io.Reader) (helperauth.SignedCapability, error) {
	var capability helperauth.SignedCapability

	data, err := io.ReadAll(io.LimitReader(r, maxCapabilityBytes+1))
	if err != nil || len(data) == 0 || len(data) > maxCapabilityBytes {
		return capability, invalid("invalid capability input")
	}

	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()

	if err := decoder.Decode(&capability); err != nil {
		return capability, invalid("invalid capability JSON")
	}

	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return capability, invalid("trailing capability data")
	}

	return capability, nil
}

func usageError() error {
	return invalid("usage: egresslab-helperctl ping|helper-info|recover-scan|list-labs|multi-probe-policy\n" +
		"       egresslab-helperctl create-lab PROFILE_ID < capability.json\n" +
		"       egresslab-helperctl stage-info PROFILE_ID\n" +
		"       egresslab-helperctl verify-lab PROFILE_ID NAMESPACE\n" +
		"       egresslab-helperctl delete-lab PROFILE_ID NAMESPACE\n" +
		"       egresslab-helperctl connect-tunnel PROFILE_ID NAMESPACE STAGE_ID < capability.json\n" +
		"       egresslab-helperctl disconnect PROFILE_ID NAMESPACE\n" +
		"       egresslab-helperctl multi-probe-target PROFILE_ID NAMESPACE\n" +
		"       egresslab-helperctl probe-egress PROFILE_ID NAMESPACE < capability.json\n" +
		"       egresslab-helperctl probe-egress-multi PROFILE_ID NAMESPACE < capability.json")
}
