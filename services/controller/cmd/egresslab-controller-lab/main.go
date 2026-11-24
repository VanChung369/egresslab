// Command egresslab-controller-lab signs CreateLab capabilities with the controller key and drives
// the helper's sealed lab lifecycle through the host's Linux runtime (WSL2, Lima or native Linux).
// It is a lab tool: -approve is an operator confirmation, not user authentication.
package main

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/VanChung369/egresslab/services/controller/internal/control"
	"github.com/VanChung369/egresslab/services/controller/internal/keystore"
	"github.com/VanChung369/egresslab/services/controller/internal/labruntime"
)

type deps struct {
	openKeys   func(dataDir string) (keystore.KeyStore, error)
	newRuntime func(kind string, opts labruntime.Options) (labruntime.RuntimeProvider, error)
	now        func() time.Time
	stdout     io.Writer
}

func main() {
	if err := run(os.Args[1:], deps{keystore.Open, labruntime.New, time.Now, os.Stdout}); err != nil {
		fmt.Fprintln(os.Stderr, "controller-lab:", err)
		os.Exit(1)
	}
}

func run(argv []string, d deps) error {
	flags := flag.NewFlagSet("egresslab-controller-lab", flag.ContinueOnError)
	kind := flags.String("runtime", "auto", "network runtime: auto, wsl, lima, native or remote")
	distro := flags.String("wsl-distro", "", "WSL distribution (default: the WSL default distribution)")
	instance := flags.String("lima-instance", "", "Lima instance (default: egresslab)")
	approve := flags.Bool("approve", false, "approve a lab mutation (create-lab, delete-lab)")

	if err := flags.Parse(argv); err != nil {
		return err
	}

	args := flags.Args()
	if len(args) == 0 {
		return usageError()
	}

	dataDir, err := dataDirectory()
	if err != nil {
		return err
	}

	if args[0] == "init-key" || args[0] == "public-key" {
		if len(args) != 1 {
			return usageError()
		}

		return printPublicKey(d, dataDir, args[0] == "init-key")
	}

	if (args[0] == "create-lab" || args[0] == "delete-lab") && !*approve {
		return fmt.Errorf("%s requires -approve", args[0])
	}

	if err := checkArgs(args); err != nil {
		return err
	}

	provider, err := d.newRuntime(*kind, labruntime.Options{WSLDistro: *distro, LimaInstance: *instance})
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	transport := provider.Transport()
	var result any

	switch args[0] {
	case "runtime-status":
		status, err := provider.Status(ctx)
		if err != nil {
			return err
		}

		report := struct {
			labruntime.Status
			Capabilities *labruntime.Capabilities `json:"capabilities,omitempty"`
		}{Status: status}

		if status.Reachable {
			caps, err := provider.Capabilities(ctx)
			if err != nil {
				return err
			}
			report.Capabilities = &caps
		}

		result = report

	case "helper-info":
		result, err = transport.HelperInfo(ctx)

	case "list-labs":
		var labs []control.LabInfo
		labs, err = transport.ListLabs(ctx)
		result = struct {
			Labs []control.LabInfo `json:"labs"`
		}{append([]control.LabInfo{}, labs...)}

	case "create-lab":
		result, err = createLab(ctx, d, dataDir, transport, args[1])

	case "verify-lab":
		result, err = transport.VerifyLab(ctx, args[1], args[2])

	case "delete-lab":
		result, err = transport.DeleteLab(ctx, args[1], args[2])
	}

	if err != nil {
		return err
	}

	encoder := json.NewEncoder(d.stdout)
	encoder.SetIndent("", "  ")

	return encoder.Encode(result)
}

func checkArgs(args []string) error {
	switch args[0] {
	case "runtime-status", "helper-info", "list-labs":
		if len(args) == 1 {
			return nil
		}
	case "create-lab":
		if len(args) == 2 && control.ValidProfileID(args[1]) {
			return nil
		}
	case "verify-lab", "delete-lab":
		if len(args) == 3 && control.ValidProfileID(args[1]) && control.ValidLabNamespace(args[2]) {
			return nil
		}
	}

	return usageError()
}

func printPublicKey(d deps, dataDir string, initialize bool) error {
	keys, err := d.openKeys(dataDir)
	if err != nil {
		return err
	}

	if initialize {
		if err := keys.Initialize(); err != nil {
			return err
		}
	}

	public, err := keys.PublicKey()
	if err != nil {
		return err
	}

	_, err = fmt.Fprintln(d.stdout, hex.EncodeToString(public))

	return err
}

// createLab fetches the current helper epoch right before signing and never retries.
func createLab(ctx context.Context, d deps, dataDir string, transport labruntime.HelperTransport, profileID string) (control.LabInfo, error) {
	profile, err := loadProfile(dataDir, profileID)
	if err != nil {
		return control.LabInfo{}, err
	}

	keys, err := d.openKeys(dataDir)
	if err != nil {
		return control.LabInfo{}, err
	}

	info, err := transport.HelperInfo(ctx)
	if err != nil {
		return control.LabInfo{}, err
	}

	capability, err := control.MintCreateLab(keys, profile, info, d.now())
	if err != nil {
		return control.LabInfo{}, err
	}

	lab, err := transport.CreateLab(ctx, profile.ID, capability)
	if err != nil {
		return control.LabInfo{}, fmt.Errorf("CreateLab result uncertain; run list-labs before retrying: %w", err)
	}

	return lab, nil
}

func dataDirectory() (string, error) {
	root := os.Getenv("EGRESSLAB_DATA_DIR")
	if root == "" {
		config, err := os.UserConfigDir()
		if err != nil {
			return "", err
		}

		root = filepath.Join(config, "EgressLab")
	}

	return filepath.Abs(root)
}

func loadProfile(dataDir, id string) (control.RoutingProfile, error) {
	store, err := control.NewStore(filepath.Join(dataDir, "state.json"))
	if err != nil {
		return control.RoutingProfile{}, err
	}

	for _, profile := range store.Profiles() {
		if profile.ID == id {
			return profile, nil
		}
	}

	return control.RoutingProfile{}, errors.New("profile not found in controller state")
}

func usageError() error {
	return errors.New("usage: egresslab-controller-lab [-runtime auto|wsl|lima|native] [-wsl-distro NAME] [-lima-instance NAME] [-approve] COMMAND\n" +
		"  init-key | public-key | runtime-status | helper-info | list-labs\n" +
		"  create-lab PROFILE_ID | verify-lab PROFILE_ID NAMESPACE | delete-lab PROFILE_ID NAMESPACE")
}
