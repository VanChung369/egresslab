package agent

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"sort"
	"time"
)

const (
	egressLeaseFileVersion = 1
	maxEgressLeaseBytes    = 1 << 20
)

type egressLease struct {
	ip       netip.Addr
	pinnedAt time.Time
}

type egressLeaseFile struct {
	Version int                `json:"version"`
	Leases  []egressLeaseEntry `json:"leases"`
}

type egressLeaseEntry struct {
	ProfileID string    `json:"profile_id"`
	IP        string    `json:"ip"`
	PinnedAt  time.Time `json:"pinned_at"`
}

// loadEgressLeases reads and re-validates a lease file. A missing file means no leases.
func loadEgressLeases(path string) (map[string]egressLease, error) {
	leases := make(map[string]egressLease)

	data, err := readPrivateFile(path, maxEgressLeaseBytes)
	if errors.Is(err, os.ErrNotExist) {
		return leases, nil
	}

	if err != nil {
		return nil, fmt.Errorf("read lease file: %w", err)
	}

	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()

	var file egressLeaseFile
	if err := decoder.Decode(&file); err != nil {
		return nil, fmt.Errorf("parse lease file: %w", err)
	}

	var extra json.RawMessage
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return nil, errors.New("parse lease file: trailing data")
	}

	if file.Version != egressLeaseFileVersion {
		return nil, fmt.Errorf("unsupported lease file version %d", file.Version)
	}

	owners := make(map[netip.Addr]string)

	for i, entry := range file.Leases {
		if !profileIDPattern.MatchString(entry.ProfileID) {
			return nil, fmt.Errorf("lease %d: invalid profile ID", i)
		}

		ip, err := parseCandidateIPv4(entry.IP)
		if err != nil {
			return nil, fmt.Errorf("lease %d: %w", i, err)
		}

		if entry.PinnedAt.IsZero() {
			return nil, fmt.Errorf("lease %d: missing pinned_at", i)
		}

		if _, dup := leases[entry.ProfileID]; dup {
			return nil, fmt.Errorf("lease %d: profile leased twice", i)
		}

		if owner, dup := owners[ip]; dup {
			return nil, fmt.Errorf("lease %d: %s already leased to %s", i, ip, owner)
		}

		owners[ip] = entry.ProfileID
		leases[entry.ProfileID] = egressLease{ip: ip, pinnedAt: entry.PinnedAt}
	}

	return leases, nil
}

func saveEgressLeases(path string, leases map[string]egressLease) error {
	file := egressLeaseFile{Version: egressLeaseFileVersion, Leases: []egressLeaseEntry{}}

	for profileID, lease := range leases {
		file.Leases = append(file.Leases, egressLeaseEntry{
			ProfileID: profileID,
			IP:        lease.ip.String(),
			PinnedAt:  lease.pinnedAt,
		})
	}

	sort.Slice(file.Leases, func(i, j int) bool { return file.Leases[i].ProfileID < file.Leases[j].ProfileID })

	data, err := json.MarshalIndent(file, "", "  ")
	if err != nil {
		return err
	}

	return writePrivateFile(path, append(data, '\n'))
}
