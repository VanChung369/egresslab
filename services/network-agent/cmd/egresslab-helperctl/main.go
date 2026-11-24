// Command egresslab-helperctl is the unprivileged client of the privileged network helper. It
// prints each response as JSON. A capability is read from stdin only, never from argv.
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
	"ping":         helperipc.OpPing,
	"helper-info":  helperipc.OpHelperInfo,
	"recover-scan": helperipc.OpRecoverScan,
	"list-labs":    helperipc.OpListLabs,
}

func main() {
	if runtime.GOOS != "linux" {
		fail(errors.New("helperctl requires Linux"))
	}

	if err := agent.RequireUnprivilegedAgent(); err != nil {
		fail(err)
	}

	if err := run(os.Args[1:], os.Stdin, os.Stdout); err != nil {
		fail(err)
	}
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, "helperctl:", err)
	os.Exit(1)
}

func run(args []string, stdin io.Reader, stdout io.Writer) error {
	if len(args) == 0 {
		return usageError()
	}

	ctx, cancel := context.WithTimeout(context.Background(), 65*time.Second)
	defer cancel()

	var result helperipc.Response
	var err error

	switch args[0] {
	case "ping", "helper-info", "recover-scan", "list-labs":
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
		return capability, errors.New("invalid capability input")
	}

	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()

	if err := decoder.Decode(&capability); err != nil {
		return capability, errors.New("invalid capability JSON")
	}

	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return capability, errors.New("trailing capability data")
	}

	return capability, nil
}

func usageError() error {
	return errors.New("usage: egresslab-helperctl ping|helper-info|recover-scan|list-labs\n" +
		"       egresslab-helperctl create-lab PROFILE_ID < capability.json\n" +
		"       egresslab-helperctl verify-lab PROFILE_ID NAMESPACE\n" +
		"       egresslab-helperctl delete-lab PROFILE_ID NAMESPACE")
}
