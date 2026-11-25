//go:build linux

package main

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/VanChung369/egresslab/services/network-agent/internal/agent"
	"github.com/VanChung369/egresslab/services/network-agent/internal/helperipc"
)

const (
	machineIDPath    = "/etc/machine-id"
	runtimeIDContext = "egresslab-runtime-id-v1"
)

// runtimeIDFrom derives an application-specific ID from machine-id, as machine-id(5) asks, so the
// raw machine-id is never disclosed. It is stable across helper restarts and distinct per Linux
// installation; images cloned from one installation share it.
func runtimeIDFrom(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()

	data, err := io.ReadAll(io.LimitReader(file, 64))
	if err != nil {
		return "", err
	}

	text := strings.TrimSpace(string(data))

	key, err := hex.DecodeString(text)
	if err != nil || len(key) != 16 || hex.EncodeToString(key) != text {
		return "", fmt.Errorf("%s does not hold a 128-bit machine ID", path)
	}

	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(runtimeIDContext))

	return "runtime_" + hex.EncodeToString(mac.Sum(nil)[:16]), nil
}

// labBackend maps the agent's kernel errors onto the helper's sentinels, so refusals carry codes
// without matching message text.
type labBackend struct{ *agent.SealedLabBackend }

func (b labBackend) Preflight(ctx context.Context) error {
	return classifyLabError(b.SealedLabBackend.Preflight(ctx))
}

func (b labBackend) Seal(ctx context.Context, name string) error {
	return classifyLabError(b.SealedLabBackend.Seal(ctx, name))
}

func (b labBackend) Verify(ctx context.Context, name string) error {
	return classifyLabError(b.SealedLabBackend.Verify(ctx, name))
}

func (b labBackend) Delete(ctx context.Context, name string) error {
	return classifyLabError(b.SealedLabBackend.Delete(ctx, name))
}

func classifyLabError(err error) error {
	var sentinel error

	switch {
	case err == nil:
		return nil
	case errors.Is(err, agent.ErrKernelIncompatible):
		sentinel = helperipc.ErrLabKernelIncompatible
	case errors.Is(err, agent.ErrRecoveryRequired):
		sentinel = helperipc.ErrLabRecoveryRequired
	case errors.Is(err, agent.ErrFirewallDrift):
		sentinel = helperipc.ErrLabFirewallDrift
	case errors.Is(err, agent.ErrLabNotLoopbackOnly):
		sentinel = helperipc.ErrLabTopology
	default:
		return err
	}

	return fmt.Errorf("%w: %w", sentinel, err)
}

// tunnelBackend reports a stage the vault refused as helperipc.ErrStageNotFound. The vault refuses
// before anything runs, so the lifecycle can leave the lab sealed. Other errors are not
// classified: after a failed connect the lab is faulted whatever the cause.
type tunnelBackend struct{ *agent.ManagedTunnelBackend }

// MultiProbePolicyPin is promoted from the embedded backend.
var (
	_ helperipc.ProbeTunnelBackend           = tunnelBackend{}
	_ helperipc.MultiProbeTunnelBackend      = tunnelBackend{}
	_ helperipc.GenerationProbeTunnelBackend = tunnelBackend{}
)

// ProbeConfigured adapts the backend's observation, so helperipc does not depend on the agent package.
func (b tunnelBackend) ProbeConfigured(ctx context.Context, namespace string) (helperipc.ProbeObservation, error) {
	result, err := b.ManagedTunnelBackend.ProbeConfigured(ctx, namespace)
	if err != nil {
		return helperipc.ProbeObservation{}, err
	}

	if result.NetworkReady {
		return helperipc.ProbeObservation{}, errors.New("diagnostic probe cannot activate networking")
	}

	return helperipc.ProbeObservation{
		IPv4:        result.IPv4,
		ObservedAt:  result.ObservedAt,
		HandshakeAt: result.HandshakeAt,
		Source:      result.Source,
	}, nil
}

// ProbeConfiguredMulti adapts the backend's multi-source observation the same way, without the
// tunnel generation (V1 evidence carries none).
func (b tunnelBackend) ProbeConfiguredMulti(
	ctx context.Context,
	namespace string,
) (helperipc.MultiProbeObservation, error) {
	result, err := b.ManagedTunnelBackend.ProbeConfiguredMulti(ctx, namespace)
	if err != nil {
		return helperipc.MultiProbeObservation{}, err
	}

	return adaptMultiProbeObservation(result, false)
}

// ProbeConfiguredMultiForGeneration reports the generation the agent actually probed, never the
// one the request named.
func (b tunnelBackend) ProbeConfiguredMultiForGeneration(
	ctx context.Context,
	namespace, generation string,
) (helperipc.MultiProbeObservation, error) {
	result, err := b.ManagedTunnelBackend.ProbeConfiguredMultiForGeneration(ctx, namespace, generation)
	if err != nil {
		return helperipc.MultiProbeObservation{}, err
	}

	return adaptMultiProbeObservation(result, true)
}

func adaptMultiProbeObservation(
	result agent.ManagedMultiProbeObservation,
	withGeneration bool,
) (helperipc.MultiProbeObservation, error) {
	if result.NetworkReady {
		return helperipc.MultiProbeObservation{}, errors.New("diagnostic probe cannot activate networking")
	}

	sources := make([]helperipc.MultiProbeSourceObservation, 0, len(result.Sources))
	for _, source := range result.Sources {
		sources = append(sources, helperipc.MultiProbeSourceObservation{
			Source:          source.Source,
			DestinationIPv4: source.DestinationIPv4,
			IPv4:            source.IPv4,
			ObservedAt:      source.ObservedAt,
		})
	}

	observation := helperipc.MultiProbeObservation{
		IPv4:        result.IPv4,
		StartedAt:   result.StartedAt,
		FinishedAt:  result.FinishedAt,
		ObservedAt:  result.ObservedAt,
		HandshakeAt: result.HandshakeAt,
		Sources:     sources,
	}

	if withGeneration {
		observation.TunnelGeneration = result.TunnelGeneration
	}

	return observation, nil
}

func (b tunnelBackend) ConnectStage(ctx context.Context, profileID, namespace, stageID string) error {
	err := b.ManagedTunnelBackend.ConnectStage(ctx, profileID, namespace, stageID)
	if errors.Is(err, agent.ErrWGStageNotFound) {
		return fmt.Errorf("%w: %w", helperipc.ErrStageNotFound, err)
	}

	return err
}
