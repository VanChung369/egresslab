package agent

import (
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"testing"
	"time"
)

// A synthetic policy: these are not production echo endpoints, and nothing here touches the network.
func testManagedConsensusSources() []managedProbeSourceSpec {
	return []managedProbeSourceSpec{
		{id: "source_a", operator: "operator_a", destination: netip.MustParseAddr("1.1.1.1")},
		{id: "source_b", operator: "operator_b", destination: netip.MustParseAddr("9.9.9.9")},
	}
}

type (
	specList   = []managedProbeSourceSpec
	sampleList = []managedProbeSample
)

func requireNoConsensus(t *testing.T, result managedProbeConsensus) {
	t.Helper()

	if result.ipv4.IsValid() || !result.observedAt.IsZero() || len(result.sourceIDs) != 0 {
		t.Fatalf("failed consensus returned evidence: %+v", result)
	}
}

func TestManagedProbeSourcePolicy(t *testing.T) {
	if err := validateManagedProbeSources(testManagedConsensusSources()); err != nil {
		t.Fatal(err)
	}

	// The upper bounds themselves are accepted: 8 sources, 32-character names.
	full := testManagedConsensusSources()
	full[1].operator = "o" + strings.Repeat("x", 31)

	for i := 0; len(full) < maxManagedProbeSources; i++ {
		full = append(full, managedProbeSourceSpec{
			id:          fmt.Sprintf("extra_%d", i),
			operator:    fmt.Sprintf("extra_operator_%d", i),
			destination: netip.AddrFrom4([4]byte{8, 8, 8, byte(i + 1)}),
		})
	}

	if err := validateManagedProbeSources(full); err != nil || len(full) != maxManagedProbeSources {
		t.Fatalf("maximum policy refused: %v", err)
	}

	tests := map[string]func(specList) specList{
		"no source":           func(s specList) specList { return nil },
		"single source":       func(s specList) specList { return s[:1] },
		"duplicate source ID": func(s specList) specList { s[1].id = s[0].id; return s },
		"duplicate operator":  func(s specList) specList { s[1].operator = s[0].operator; return s },
		"duplicate destination": func(s specList) specList {
			s[1].destination = s[0].destination
			return s
		},
		"private destination": func(s specList) specList {
			s[1].destination = netip.MustParseAddr("10.0.0.1")
			return s
		},
		"IPv4-mapped destination": func(s specList) specList {
			s[1].destination = netip.MustParseAddr("::ffff:9.9.9.9")
			return s
		},
		"missing destination": func(s specList) specList { s[1].destination = netip.Addr{}; return s },
		"empty operator":      func(s specList) specList { s[1].operator = ""; return s },
		"empty source ID":     func(s specList) specList { s[1].id = ""; return s },
		"upper-case ID":       func(s specList) specList { s[1].id = "Source_B"; return s },
		"padded operator":     func(s specList) specList { s[1].operator = " operator_b"; return s },
		"inner space":         func(s specList) specList { s[1].id = "source b"; return s },
		"name too long": func(s specList) specList {
			s[1].operator = "o" + strings.Repeat("x", 32)
			return s
		},
		"too many sources": func(s specList) specList {
			for i := 0; len(s) <= maxManagedProbeSources; i++ {
				s = append(s, managedProbeSourceSpec{
					id:          fmt.Sprintf("extra_%d", i),
					operator:    fmt.Sprintf("extra_operator_%d", i),
					destination: netip.AddrFrom4([4]byte{8, 8, 8, byte(i + 1)}),
				})
			}
			return s
		},
	}

	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			err := validateManagedProbeSources(mutate(testManagedConsensusSources()))
			if !errors.Is(err, ErrManagedProbeSourcePolicy) {
				t.Fatalf("invalid policy accepted: %v", err)
			}
		})
	}
}

func TestManagedProbeConsensusSuccess(t *testing.T) {
	start := time.Unix(1795500000, 0).UTC()
	finish := start.Add(12 * time.Second)
	ip := netip.MustParseAddr("8.8.4.4")

	// Out of order on purpose: the result follows the policy order and the earliest observation.
	samples := []managedProbeSample{
		{sourceID: "source_b", ipv4: ip, observedAt: start.Add(9 * time.Second)},
		{sourceID: "source_a", ipv4: ip, observedAt: start.Add(3 * time.Second)},
	}

	result, err := verifyManagedProbeConsensus(testManagedConsensusSources(), samples, start, finish)
	if err != nil {
		t.Fatal(err)
	}

	if result.ipv4 != ip || !result.observedAt.Equal(start.Add(3*time.Second)) ||
		!slices.Equal(result.sourceIDs, []string{"source_a", "source_b"}) {
		t.Fatalf("unexpected consensus: %+v", result)
	}

	// Observations exactly at the interval bounds count as inside it.
	samples[0].observedAt, samples[1].observedAt = start, finish
	if _, err := verifyManagedProbeConsensus(testManagedConsensusSources(), samples, start, finish); err != nil {
		t.Fatalf("boundary observations refused: %v", err)
	}
}

func TestManagedProbeConsensusRefusals(t *testing.T) {
	start := time.Unix(1795500000, 0).UTC()
	finish := start.Add(12 * time.Second)
	ip := netip.MustParseAddr("8.8.4.4")

	base := []managedProbeSample{
		{sourceID: "source_a", ipv4: ip, observedAt: start.Add(3 * time.Second)},
		{sourceID: "source_b", ipv4: ip, observedAt: start.Add(9 * time.Second)},
	}

	setIP := func(raw string) func(sampleList) sampleList {
		return func(s sampleList) sampleList {
			s[1].ipv4 = netip.Addr{}
			if raw != "" {
				s[1].ipv4 = netip.MustParseAddr(raw)
			}
			return s
		}
	}

	setTime := func(at time.Time) func(sampleList) sampleList {
		return func(s sampleList) sampleList { s[1].observedAt = at; return s }
	}

	tests := []struct {
		name   string
		want   error
		mutate func(sampleList) sampleList
	}{
		{"missing source", ErrManagedProbeEvidenceIncomplete, func(s sampleList) sampleList { return s[:1] }},
		{"extra sample", ErrManagedProbeEvidenceIncomplete, func(s sampleList) sampleList { return append(s, s[0]) }},
		{"no samples", ErrManagedProbeEvidenceIncomplete, func(sampleList) sampleList { return nil }},
		{"duplicate observation", ErrInvalidObservation, func(s sampleList) sampleList {
			s[1].sourceID = s[0].sourceID
			return s
		}},
		{"unknown source", ErrInvalidObservation, func(s sampleList) sampleList {
			s[1].sourceID = "unknown"
			return s
		}},
		{"IP mismatch", ErrManagedProbeIPMismatch, setIP("8.8.8.8")},
		{"private IP", ErrInvalidObservation, setIP("192.168.1.1")},
		{"CGNAT IP", ErrInvalidObservation, setIP("100.64.0.1")},
		{"loopback IP", ErrInvalidObservation, setIP("127.0.0.1")},
		{"documentation IP", ErrInvalidObservation, setIP("192.0.2.1")},
		{"IPv6", ErrInvalidObservation, setIP("2001:4860::1")},
		{"IPv4-mapped IPv6", ErrInvalidObservation, setIP("::ffff:8.8.4.4")},
		{"invalid IP", ErrInvalidObservation, setIP("")},
		{"before the interval", ErrInvalidObservation, setTime(start.Add(-time.Second))},
		{"after the interval", ErrInvalidObservation, setTime(finish.Add(time.Second))},
		{"zero timestamp", ErrInvalidObservation, setTime(time.Time{})},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			samples := tt.mutate(slices.Clone(base))

			result, err := verifyManagedProbeConsensus(testManagedConsensusSources(), samples, start, finish)
			if !errors.Is(err, tt.want) {
				t.Fatalf("expected %v, got %v", tt.want, err)
			}

			requireNoConsensus(t, result)
		})
	}

	// An invalid policy is refused before any evidence is read.
	sources := testManagedConsensusSources()[:1]
	result, err := verifyManagedProbeConsensus(sources, base[:1], start, finish)
	if !errors.Is(err, ErrManagedProbeSourcePolicy) {
		t.Fatalf("single-source fallback accepted: %v", err)
	}

	requireNoConsensus(t, result)
}

func TestManagedProbeConsensusInvalidInterval(t *testing.T) {
	start := time.Unix(1795500000, 0).UTC()

	for name, interval := range map[string][2]time.Time{
		"exceeded verification span": {start, start.Add(maxManagedVerificationSpan + time.Second)},
		"reversed interval":          {start, start.Add(-time.Second)},
		"missing start":              {{}, start},
		"missing finish":             {start, {}},
	} {
		t.Run(name, func(t *testing.T) {
			result, err := verifyManagedProbeConsensus(testManagedConsensusSources(), nil, interval[0], interval[1])
			if !errors.Is(err, ErrInvalidObservation) {
				t.Fatalf("invalid interval accepted: %v", err)
			}

			requireNoConsensus(t, result)
		})
	}

	// The full span itself is allowed.
	ip := netip.MustParseAddr("8.8.4.4")
	finish := start.Add(maxManagedVerificationSpan)
	samples := []managedProbeSample{
		{sourceID: "source_a", ipv4: ip, observedAt: start},
		{sourceID: "source_b", ipv4: ip, observedAt: finish},
	}

	if _, err := verifyManagedProbeConsensus(testManagedConsensusSources(), samples, start, finish); err != nil {
		t.Fatalf("maximum span refused: %v", err)
	}
}

func TestManagedProbeConsensusThreeSources(t *testing.T) {
	sources := append(testManagedConsensusSources(),
		managedProbeSourceSpec{id: "source_c", operator: "operator_c", destination: netip.MustParseAddr("8.8.8.8")})

	start := time.Unix(1795500000, 0).UTC()
	finish := start.Add(12 * time.Second)
	ip := netip.MustParseAddr("8.8.4.4")

	samples := []managedProbeSample{
		{sourceID: "source_a", ipv4: ip, observedAt: start.Add(time.Second)},
		{sourceID: "source_b", ipv4: ip, observedAt: start.Add(2 * time.Second)},
		{sourceID: "source_c", ipv4: ip, observedAt: start.Add(3 * time.Second)},
	}

	result, err := verifyManagedProbeConsensus(sources, samples, start, finish)
	if err != nil || result.ipv4 != ip || len(result.sourceIDs) != 3 {
		t.Fatalf("consensus failed: %+v %v", result, err)
	}

	// Two agreeing sources out of three are not enough, whichever one disagrees.
	for i := range samples {
		disagreeing := slices.Clone(samples)
		disagreeing[i].ipv4 = netip.MustParseAddr("8.8.8.8")

		result, err := verifyManagedProbeConsensus(sources, disagreeing, start, finish)
		if !errors.Is(err, ErrManagedProbeIPMismatch) {
			t.Fatalf("majority vote accepted with source %d disagreeing: %v", i, err)
		}

		requireNoConsensus(t, result)
	}

	// Two of three present is incomplete, not a quorum.
	result, err = verifyManagedProbeConsensus(sources, samples[:2], start, finish)
	if !errors.Is(err, ErrManagedProbeEvidenceIncomplete) {
		t.Fatalf("partial evidence accepted: %v", err)
	}

	requireNoConsensus(t, result)
}
