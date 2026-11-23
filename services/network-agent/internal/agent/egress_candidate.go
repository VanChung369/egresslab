package agent

import (
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"strings"
	"sync"
	"time"
)

var (
	ErrInvalidObservation = errors.New("invalid egress observation")
	ErrEgressIPCollision  = errors.New("egress IP already reserved by another profile")

	profileIDPattern = regexp.MustCompile(`^profile_[0-9a-f]{16}$`)

	reservedIPv4 = []netip.Prefix{
		netip.MustParsePrefix("0.0.0.0/8"),
		netip.MustParsePrefix("10.0.0.0/8"),
		netip.MustParsePrefix("100.64.0.0/10"),
		netip.MustParsePrefix("127.0.0.0/8"),
		netip.MustParsePrefix("169.254.0.0/16"),
		netip.MustParsePrefix("172.16.0.0/12"),
		netip.MustParsePrefix("192.0.0.0/24"),
		netip.MustParsePrefix("192.0.2.0/24"),
		netip.MustParsePrefix("192.88.99.0/24"),
		netip.MustParsePrefix("192.168.0.0/16"),
		netip.MustParsePrefix("198.18.0.0/15"),
		netip.MustParsePrefix("198.51.100.0/24"),
		netip.MustParsePrefix("203.0.113.0/24"),
		netip.MustParsePrefix("224.0.0.0/4"),
		netip.MustParsePrefix("240.0.0.0/4"),
	}
)

type EgressObservation struct {
	ProfileID  string
	ObservedIP string
	ObservedAt time.Time
}

type EgressCandidateStatus struct {
	ProfileID    string     `json:"profile_id"`
	Status       string     `json:"status"`
	CandidateIP  string     `json:"candidate_ip,omitempty"`
	ExpiresAt    *time.Time `json:"expires_at,omitempty"`
	NetworkReady bool       `json:"network_ready"`
}

type candidateRecord struct {
	ip      netip.Addr
	expires time.Time
}

// EgressCandidateRegistry is an in-memory uniqueness precheck, never proof that traffic left through a VPN.
type EgressCandidateRegistry struct {
	mu        sync.Mutex
	ttl       time.Duration
	now       func() time.Time
	byProfile map[string]candidateRecord
	byIP      map[netip.Addr]string
}

func NewEgressCandidateRegistry(ttl time.Duration) (*EgressCandidateRegistry, error) {
	if ttl <= 0 || ttl > time.Minute {
		return nil, errors.New("candidate TTL must be positive and at most one minute")
	}

	return &EgressCandidateRegistry{
		ttl:       ttl,
		now:       time.Now,
		byProfile: make(map[string]candidateRecord),
		byIP:      make(map[netip.Addr]string),
	}, nil
}

func parseCandidateIPv4(raw string) (netip.Addr, error) {
	if raw == "" || raw != strings.TrimSpace(raw) {
		return netip.Addr{}, fmt.Errorf("%w: IP must be a single address", ErrInvalidObservation)
	}

	ip, err := netip.ParseAddr(raw)
	if err != nil || !ip.Is4() || !ip.IsGlobalUnicast() {
		return netip.Addr{}, fmt.Errorf("%w: IPv4 address required", ErrInvalidObservation)
	}

	for _, prefix := range reservedIPv4 {
		if prefix.Contains(ip) {
			return netip.Addr{}, fmt.Errorf("%w: reserved or non-public IPv4 address", ErrInvalidObservation)
		}
	}

	return ip, nil
}

func (r *EgressCandidateRegistry) Evaluate(obs EgressObservation) (EgressCandidateStatus, error) {
	result := EgressCandidateStatus{ProfileID: obs.ProfileID, Status: "rejected"}

	if !profileIDPattern.MatchString(obs.ProfileID) {
		return result, fmt.Errorf("%w: invalid profile ID", ErrInvalidObservation)
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	now := r.now()
	r.pruneLocked(now)
	r.releaseLocked(obs.ProfileID)

	ip, err := parseCandidateIPv4(obs.ObservedIP)
	if err != nil {
		return result, err
	}

	if obs.ObservedAt.IsZero() || obs.ObservedAt.After(now) || !now.Before(obs.ObservedAt.Add(r.ttl)) {
		return result, fmt.Errorf("%w: observation is stale or future-dated", ErrInvalidObservation)
	}

	if owner, exists := r.byIP[ip]; exists && owner != obs.ProfileID {
		result.Status = "collision"
		return result, ErrEgressIPCollision
	}

	expires := obs.ObservedAt.Add(r.ttl)
	r.byProfile[obs.ProfileID] = candidateRecord{ip: ip, expires: expires}
	r.byIP[ip] = obs.ProfileID

	result.Status = "candidate"
	result.CandidateIP = ip.String()
	result.ExpiresAt = &expires

	return result, nil
}

func (r *EgressCandidateRegistry) Snapshot(profileID string) EgressCandidateStatus {
	result := EgressCandidateStatus{ProfileID: profileID, Status: "absent"}

	r.mu.Lock()
	defer r.mu.Unlock()

	r.pruneLocked(r.now())

	if record, exists := r.byProfile[profileID]; exists {
		expires := record.expires
		result.Status = "candidate"
		result.CandidateIP = record.ip.String()
		result.ExpiresAt = &expires
	}

	return result
}

func (r *EgressCandidateRegistry) Release(profileID string) {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.releaseLocked(profileID)
}

func (r *EgressCandidateRegistry) releaseLocked(profileID string) {
	if old, exists := r.byProfile[profileID]; exists {
		delete(r.byIP, old.ip)
		delete(r.byProfile, profileID)
	}
}

func (r *EgressCandidateRegistry) pruneLocked(now time.Time) {
	for profileID, record := range r.byProfile {
		if !now.Before(record.expires) {
			r.releaseLocked(profileID)
		}
	}
}
