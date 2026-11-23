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
	ErrEgressIPChanged    = errors.New("observed egress IP differs from the IP pinned to the active profile")
	ErrNoEgressCandidate  = errors.New("profile has no current egress candidate")

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

// Status values: "rejected", "collision", "candidate", "absent", "active" (lease pinned and, after
// Evaluate, the observation matched it) and "ip_changed" (observation differs from the pinned IP).
type EgressCandidateStatus struct {
	ProfileID    string     `json:"profile_id"`
	Status       string     `json:"status"`
	CandidateIP  string     `json:"candidate_ip,omitempty"`
	PinnedIP     string     `json:"pinned_ip,omitempty"`
	ExpiresAt    *time.Time `json:"expires_at,omitempty"`
	NetworkReady bool       `json:"network_ready"`
}

type candidateRecord struct {
	ip      netip.Addr
	expires time.Time
}

// EgressCandidateRegistry is a uniqueness precheck, never proof that traffic left through a VPN.
//
// Candidates are short-lived (TTL) and in memory. Active leases pin one IP to one profile until
// Deactivate; they block every other profile from that IP and make any different observation for
// the pinned profile fail with ErrEgressIPChanged. With a lease file, leases survive restarts.
type EgressCandidateRegistry struct {
	mu        sync.Mutex
	ttl       time.Duration
	now       func() time.Time
	byProfile map[string]candidateRecord
	byIP      map[netip.Addr]string
	leases    map[string]egressLease
	leasedBy  map[netip.Addr]string
	leaseFile string
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
		leases:    make(map[string]egressLease),
		leasedBy:  make(map[netip.Addr]string),
	}, nil
}

// OpenEgressCandidateRegistry is NewEgressCandidateRegistry with active leases persisted to
// leaseFile (created 0600 on first write). Existing leases are loaded and fully re-validated.
func OpenEgressCandidateRegistry(ttl time.Duration, leaseFile string) (*EgressCandidateRegistry, error) {
	if leaseFile == "" {
		return nil, errors.New("lease file path is required")
	}

	r, err := NewEgressCandidateRegistry(ttl)
	if err != nil {
		return nil, err
	}

	leases, err := loadEgressLeases(leaseFile)
	if err != nil {
		return nil, err
	}

	for profileID, lease := range leases {
		r.leases[profileID] = lease
		r.leasedBy[lease.ip] = profileID
	}

	r.leaseFile = leaseFile

	return r, nil
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

	// Sticky IP: an active profile may only ever be observed on its pinned IP.
	lease, active := r.leases[obs.ProfileID]
	if active {
		result.PinnedIP = lease.ip.String()

		if ip != lease.ip {
			result.Status = "ip_changed"
			result.CandidateIP = ip.String()
			return result, fmt.Errorf("%w: pinned %s, observed %s", ErrEgressIPChanged, lease.ip, ip)
		}
	}

	if owner, exists := r.leasedBy[ip]; exists && owner != obs.ProfileID {
		result.Status = "collision"
		return result, ErrEgressIPCollision
	}

	if owner, exists := r.byIP[ip]; exists && owner != obs.ProfileID {
		result.Status = "collision"
		return result, ErrEgressIPCollision
	}

	expires := obs.ObservedAt.Add(r.ttl)
	r.byProfile[obs.ProfileID] = candidateRecord{ip: ip, expires: expires}
	r.byIP[ip] = obs.ProfileID

	result.Status = "candidate"
	if active {
		result.Status = "active"
	}

	result.CandidateIP = ip.String()
	result.ExpiresAt = &expires

	return result, nil
}

// Activate pins the profile's current candidate IP as its active lease. It is idempotent for the
// same IP and fails with ErrEgressIPChanged if the profile is already pinned to a different IP.
func (r *EgressCandidateRegistry) Activate(profileID string) (EgressCandidateStatus, error) {
	result := EgressCandidateStatus{ProfileID: profileID, Status: "rejected"}

	if !profileIDPattern.MatchString(profileID) {
		return result, fmt.Errorf("%w: invalid profile ID", ErrInvalidObservation)
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	r.pruneLocked(r.now())

	record, ok := r.byProfile[profileID]
	if !ok {
		return result, ErrNoEgressCandidate
	}

	if lease, active := r.leases[profileID]; active {
		result.PinnedIP = lease.ip.String()

		if lease.ip != record.ip {
			result.Status = "ip_changed"
			return result, fmt.Errorf("%w: pinned %s, candidate %s", ErrEgressIPChanged, lease.ip, record.ip)
		}

		return r.activeStatusLocked(profileID), nil
	}

	if owner, exists := r.leasedBy[record.ip]; exists && owner != profileID {
		result.Status = "collision"
		return result, ErrEgressIPCollision
	}

	r.leases[profileID] = egressLease{ip: record.ip, pinnedAt: r.now().UTC()}
	r.leasedBy[record.ip] = profileID

	if err := r.persistLocked(); err != nil {
		delete(r.leases, profileID)
		delete(r.leasedBy, record.ip)

		return result, fmt.Errorf("persist active lease: %w", err)
	}

	return r.activeStatusLocked(profileID), nil
}

// Deactivate removes the profile's active lease, freeing its IP for other profiles.
func (r *EgressCandidateRegistry) Deactivate(profileID string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	lease, ok := r.leases[profileID]
	if !ok {
		return nil
	}

	delete(r.leases, profileID)
	delete(r.leasedBy, lease.ip)

	if err := r.persistLocked(); err != nil {
		r.leases[profileID] = lease
		r.leasedBy[lease.ip] = profileID

		return fmt.Errorf("persist lease removal: %w", err)
	}

	return nil
}

func (r *EgressCandidateRegistry) Snapshot(profileID string) EgressCandidateStatus {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.pruneLocked(r.now())

	if _, active := r.leases[profileID]; active {
		return r.activeStatusLocked(profileID)
	}

	result := EgressCandidateStatus{ProfileID: profileID, Status: "absent"}

	if record, exists := r.byProfile[profileID]; exists {
		expires := record.expires
		result.Status = "candidate"
		result.CandidateIP = record.ip.String()
		result.ExpiresAt = &expires
	}

	return result
}

func (r *EgressCandidateRegistry) activeStatusLocked(profileID string) EgressCandidateStatus {
	lease := r.leases[profileID]
	result := EgressCandidateStatus{ProfileID: profileID, Status: "active", PinnedIP: lease.ip.String()}

	if record, exists := r.byProfile[profileID]; exists {
		expires := record.expires
		result.CandidateIP = record.ip.String()
		result.ExpiresAt = &expires
	}

	return result
}

func (r *EgressCandidateRegistry) persistLocked() error {
	if r.leaseFile == "" {
		return nil
	}

	return saveEgressLeases(r.leaseFile, r.leases)
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
