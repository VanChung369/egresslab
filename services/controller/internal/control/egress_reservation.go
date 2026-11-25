package control

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"net/netip"
	"sort"
	"sync"
	"time"
)

const maxEgressReservations = 1024

var (
	ErrReservationIPCollision = errors.New("public IPv4 already reserved")
	ErrReservationOwnerHeld   = errors.New("tunnel generation already holds a reservation")
	ErrReservationProfileHeld = errors.New("profile already holds a reservation")
	ErrReservationLimit       = errors.New("egress reservation registry limit reached")
	ErrReservationUnavailable = errors.New("egress reservation registry unavailable")
)

// LeaseOwner is one managed tunnel's lifetime, not merely the routing profile: a reconnect, a
// helper restart or a move to another runtime is another owner.
type LeaseOwner struct {
	ProfileID        string `json:"profile_id"`
	RuntimeID        string `json:"runtime_id"`
	HelperEpoch      string `json:"helper_epoch"`
	Namespace        string `json:"namespace"`
	TunnelGeneration string `json:"tunnel_generation"`
}

func (o LeaseOwner) Valid() bool {
	return ValidProfileID(o.ProfileID) &&
		ValidRuntimeID(o.RuntimeID) &&
		labHelperIDPattern.MatchString(o.HelperEpoch) &&
		ValidLabNamespace(o.Namespace) &&
		ValidLabTunnelGeneration(o.TunnelGeneration)
}

// EgressReservation is an exclusive hold on one public IPv4 address. It is not an active lease and
// authorizes no application networking. Its ID is neither a secret nor a capability.
type EgressReservation struct {
	ID    string     `json:"id"`
	Owner LeaseOwner `json:"owner"`
	IPv4  netip.Addr `json:"ipv4"`

	IdentIPv4       string `json:"ident_ipv4"`
	PublicKeySHA256 string `json:"public_key_sha256"`

	EvidenceNonce    string `json:"evidence_nonce"`
	ReservationNonce string `json:"reservation_nonce"`

	ObservedAt         time.Time `json:"observed_at"`
	CandidateExpiresAt time.Time `json:"candidate_expires_at"`
	ReservedAt         time.Time `json:"reserved_at"`
	EligibleUntil      time.Time `json:"eligible_until"`
}

// FreshAt reports the controller's local eligibility deadline only; it does not establish that the
// helper still holds the candidate or a healthy tunnel. Expiry ends eligibility, not the hold.
func (r EgressReservation) FreshAt(now time.Time) bool {
	return r.ID != "" && stableReservationClock(r.ReservedAt, now) && now.Before(r.EligibleUntil)
}

func newEgressReservationID() (string, error) {
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", err
	}

	return "reservation_" + hex.EncodeToString(raw[:]), nil
}

// egressReservationRegistry is the in-process core of the future shared reservation authority
// (Step 31C makes it shared between processes and durable). One instance must serve every
// runtime; it is never created per runtime or per request. All four indexes change together under
// mu:
//
//	byOwner[owner].IPv4 == ip, byIP[ip] == owner, byProfile[owner.ProfileID] == owner,
//	byID[reservation.ID] == owner
//
// There is deliberately no expiry, eviction, replacement or release yet: an address is released
// only once a later lifecycle confirms its owner can no longer use it.
type egressReservationRegistry struct {
	mu sync.Mutex

	now   func() time.Time
	limit int

	byOwner   map[LeaseOwner]EgressReservation
	byIP      map[netip.Addr]LeaseOwner
	byProfile map[string]LeaseOwner
	byID      map[string]LeaseOwner
}

func newEgressReservationRegistry() *egressReservationRegistry {
	return &egressReservationRegistry{
		now:       time.Now,
		limit:     maxEgressReservations,
		byOwner:   make(map[LeaseOwner]EgressReservation),
		byIP:      make(map[netip.Addr]LeaseOwner),
		byProfile: make(map[string]LeaseOwner),
		byID:      make(map[string]LeaseOwner),
	}
}

// reserve validates the admission, checks every index and publishes the hold in one critical
// section. A refusal never replaces an existing reservation or changes an index. Nothing in it
// touches the network, the disk or a runtime.
func (r *egressReservationRegistry) reserve(admission candidateAdmission) (EgressReservation, error) {
	if r == nil {
		return EgressReservation{}, ErrReservationUnavailable
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	if r.now == nil || r.limit <= 0 || r.byOwner == nil || r.byIP == nil || r.byProfile == nil || r.byID == nil {
		return EgressReservation{}, ErrReservationUnavailable
	}

	// Indexes that disagree on the count mean a broken registry: refuse everything.
	count := len(r.byOwner)
	if len(r.byIP) != count || len(r.byProfile) != count || len(r.byID) != count {
		return EgressReservation{}, ErrReservationUnavailable
	}

	now := r.now()

	candidate, err := validateCandidateAdmission(admission, now)
	if err != nil {
		return EgressReservation{}, err
	}

	owner, ip := candidate.owner, candidate.receipt.IPv4

	// The same owner never replaces its hold, even with a newer receipt.
	if _, exists := r.byOwner[owner]; exists {
		return EgressReservation{}, ErrReservationOwnerHeld
	}

	// A reconnect or a move to another runtime does not get a second hold for the profile.
	if _, exists := r.byProfile[owner.ProfileID]; exists {
		return EgressReservation{}, ErrReservationProfileHeld
	}

	if _, exists := r.byIP[ip]; exists {
		return EgressReservation{}, ErrReservationIPCollision
	}

	// Never evict a hold to make room.
	if count >= r.limit {
		return EgressReservation{}, ErrReservationLimit
	}

	id, err := newEgressReservationID()
	if err != nil {
		return EgressReservation{}, errors.Join(ErrReservationUnavailable, err)
	}

	if _, exists := r.byID[id]; exists {
		return EgressReservation{}, ErrReservationUnavailable
	}

	// Freshness again at the commit point.
	commitAt := r.now()
	if !stableReservationClock(now, commitAt) {
		return EgressReservation{}, ErrReservationUnavailable
	}

	if !commitAt.Before(candidate.eligibleUntil) {
		return EgressReservation{}, ErrReservationCandidateExpired
	}

	receipt := candidate.receipt

	reservation := EgressReservation{
		ID:                 id,
		Owner:              owner,
		IPv4:               ip,
		IdentIPv4:          receipt.IdentIPv4,
		PublicKeySHA256:    receipt.PublicKeySHA256,
		EvidenceNonce:      receipt.EvidenceNonce,
		ReservationNonce:   receipt.ReservationNonce,
		ObservedAt:         receipt.ObservedAt,
		CandidateExpiresAt: receipt.ExpiresAt,
		ReservedAt:         commitAt,
		EligibleUntil:      candidate.eligibleUntil,
	}

	r.byOwner[owner] = reservation
	r.byIP[ip] = owner
	r.byProfile[owner.ProfileID] = owner
	r.byID[id] = owner

	return reservation, nil
}

// The lookups and the snapshot return copies, never the maps or pointers into them.

func (r *egressReservationRegistry) lookupByOwner(owner LeaseOwner) (EgressReservation, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()

	reservation, exists := r.byOwner[owner]

	return reservation, exists
}

func (r *egressReservationRegistry) lookupByIP(ip netip.Addr) (EgressReservation, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()

	owner, exists := r.byIP[ip]
	if !exists {
		return EgressReservation{}, false
	}

	reservation, exists := r.byOwner[owner]

	return reservation, exists
}

func (r *egressReservationRegistry) lookupByID(id string) (EgressReservation, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()

	owner, exists := r.byID[id]
	if !exists {
		return EgressReservation{}, false
	}

	reservation, exists := r.byOwner[owner]

	return reservation, exists
}

// snapshot lists every hold, expired ones included (expiry is not release), ordered by ID.
func (r *egressReservationRegistry) snapshot() []EgressReservation {
	r.mu.Lock()
	defer r.mu.Unlock()

	items := make([]EgressReservation, 0, len(r.byOwner))
	for _, reservation := range r.byOwner {
		items = append(items, reservation)
	}

	sort.Slice(items, func(i, j int) bool { return items[i].ID < items[j].ID })

	return items
}
