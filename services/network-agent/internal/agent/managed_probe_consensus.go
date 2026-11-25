package agent

import (
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"time"
)

const (
	minManagedProbeSources = 2
	maxManagedProbeSources = 8

	// The helper's operation context; the budget for several sources is revisited in Step 29C.3.
	maxManagedVerificationSpan = 80 * time.Second
)

var (
	ErrManagedProbeSourcePolicy       = errors.New("invalid managed probe source policy")
	ErrManagedProbeEvidenceIncomplete = errors.New("incomplete managed probe evidence")
	ErrManagedProbeIPMismatch         = errors.New("managed probe sources disagree on public IPv4")

	managedProbeNamePattern = regexp.MustCompile(`^[a-z][a-z0-9_]{0,31}$`)
)

// managedProbeSourceSpec is trusted local policy; an untrusted caller must never supply it. A
// distinct operator name is a declaration, not proof of independence: no code checks who runs a
// source, which is reviewed by hand when a destination is provisioned (docs/DEV-LINUX-VM.md).
type managedProbeSourceSpec struct {
	id          string
	operator    string
	destination netip.Addr
}

// managedProbeSample is one observation made during the current verification attempt.
type managedProbeSample struct {
	sourceID   string
	ipv4       netip.Addr
	observedAt time.Time
}

// managedProbeConsensus is diagnostic evidence only. It authorizes neither an egress lease nor
// application traffic, and says nothing about the address after the verification interval.
type managedProbeConsensus struct {
	ipv4       netip.Addr
	observedAt time.Time
	sourceIDs  []string
}

// validateManagedProbeSources requires 2 to 8 sources, each with its own ID, operator and public
// IPv4 destination.
func validateManagedProbeSources(sources []managedProbeSourceSpec) error {
	if len(sources) < minManagedProbeSources || len(sources) > maxManagedProbeSources {
		return fmt.Errorf("%w: between %d and %d sources required", ErrManagedProbeSourcePolicy,
			minManagedProbeSources, maxManagedProbeSources)
	}

	ids := make(map[string]bool, len(sources))
	operators := make(map[string]bool, len(sources))
	destinations := make(map[netip.Addr]bool, len(sources))

	for _, source := range sources {
		if !managedProbeNamePattern.MatchString(source.id) || !managedProbeNamePattern.MatchString(source.operator) {
			return fmt.Errorf("%w: invalid source or operator name", ErrManagedProbeSourcePolicy)
		}

		if _, err := parseCandidateIPv4(source.destination.String()); err != nil {
			return fmt.Errorf("%w: invalid destination", ErrManagedProbeSourcePolicy)
		}

		switch {
		case ids[source.id]:
			return fmt.Errorf("%w: duplicate source", ErrManagedProbeSourcePolicy)
		case operators[source.operator]:
			return fmt.Errorf("%w: duplicate operator", ErrManagedProbeSourcePolicy)
		case destinations[source.destination]:
			return fmt.Errorf("%w: duplicate destination", ErrManagedProbeSourcePolicy)
		}

		ids[source.id] = true
		operators[source.operator] = true
		destinations[source.destination] = true
	}

	return nil
}

// verifyManagedProbeConsensus requires exactly one observation from every required source, each
// a valid public IPv4 address observed inside [startedAt, finishedAt], and all of them the same
// address. There is no majority vote and no fallback to fewer sources. The evidence carries the
// earliest observation time, so its freshness is that of its oldest part.
func verifyManagedProbeConsensus(
	sources []managedProbeSourceSpec,
	samples []managedProbeSample,
	startedAt, finishedAt time.Time,
) (managedProbeConsensus, error) {
	if err := validateManagedProbeSources(sources); err != nil {
		return managedProbeConsensus{}, err
	}

	if startedAt.IsZero() || finishedAt.IsZero() || finishedAt.Before(startedAt) ||
		finishedAt.Sub(startedAt) > maxManagedVerificationSpan {
		return managedProbeConsensus{}, fmt.Errorf("%w: invalid verification interval", ErrInvalidObservation)
	}

	if len(samples) != len(sources) {
		return managedProbeConsensus{}, ErrManagedProbeEvidenceIncomplete
	}

	required := make(map[string]bool, len(sources))
	for _, source := range sources {
		required[source.id] = true
	}

	seen := make(map[string]bool, len(samples))

	var agreed netip.Addr
	var earliest time.Time

	for _, sample := range samples {
		if !required[sample.sourceID] {
			return managedProbeConsensus{}, fmt.Errorf("%w: unknown source", ErrInvalidObservation)
		}

		if seen[sample.sourceID] {
			return managedProbeConsensus{}, fmt.Errorf("%w: duplicate observation", ErrInvalidObservation)
		}

		seen[sample.sourceID] = true

		ip, err := parseCandidateIPv4(sample.ipv4.String())
		if err != nil {
			return managedProbeConsensus{}, err
		}

		if sample.observedAt.IsZero() || sample.observedAt.Before(startedAt) || sample.observedAt.After(finishedAt) {
			return managedProbeConsensus{}, fmt.Errorf("%w: observation outside the verification interval",
				ErrInvalidObservation)
		}

		if !agreed.IsValid() {
			agreed = ip
		} else if ip != agreed {
			return managedProbeConsensus{}, ErrManagedProbeIPMismatch
		}

		if earliest.IsZero() || sample.observedAt.Before(earliest) {
			earliest = sample.observedAt
		}
	}

	sourceIDs := make([]string, 0, len(sources))
	for _, source := range sources {
		sourceIDs = append(sourceIDs, source.id)
	}

	return managedProbeConsensus{ipv4: agreed, observedAt: earliest.UTC(), sourceIDs: sourceIDs}, nil
}
