package control

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
	"unicode/utf8"
)

var (
	ErrNotFound   = errors.New("resource not found")
	ErrConflict   = errors.New("resource conflict")
	ErrValidation = errors.New("invalid resource")
)

// This is configuration state, not a claim that network resources are active.
type RoutingProfile struct {
	ID                 string    `json:"id"`
	Name               string    `json:"name"`
	TunnelID           string    `json:"tunnel_id,omitempty"`
	Status             string    `json:"status"`
	UniqueIPRequired   bool      `json:"unique_ip_required"`
	KillSwitchRequired bool      `json:"kill_switch_required"`
	CreatedAt          time.Time `json:"created_at"`
}

type ProxyEndpoint struct {
	ID         string    `json:"id"`
	Name       string    `json:"name"`
	Protocol   string    `json:"protocol"`
	ListenHost string    `json:"listen_host"`
	Port       int       `json:"port"`
	ProfileID  string    `json:"profile_id"`
	Status     string    `json:"status"`
	CreatedAt  time.Time `json:"created_at"`
}

type snapshot struct {
	Version   int              `json:"version"`
	Profiles  []RoutingProfile `json:"profiles"`
	Endpoints []ProxyEndpoint  `json:"endpoints"`
}

type Store struct {
	mu       sync.RWMutex
	path     string
	profiles []RoutingProfile
	proxies  []ProxyEndpoint
}

func NewStore(path string) (*Store, error) {
	s := &Store{path: path, profiles: []RoutingProfile{}, proxies: []ProxyEndpoint{}}
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return s, nil
	}
	if err != nil {
		return nil, err
	}
	var state snapshot
	if err := json.Unmarshal(data, &state); err != nil {
		return nil, fmt.Errorf("read state: %w", err)
	}
	if state.Version != 1 {
		return nil, fmt.Errorf("unsupported state version %d", state.Version)
	}
	if state.Profiles != nil {
		s.profiles = state.Profiles
	}
	if state.Endpoints != nil {
		s.proxies = state.Endpoints
	}
	return s, nil
}

func newID(prefix string) string {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic("crypto/rand failed: " + err.Error())
	}
	return prefix + "_" + hex.EncodeToString(b[:])
}

func validateName(name string) (string, error) {
	name = strings.TrimSpace(name)
	if utf8.RuneCountInString(name) < 2 || utf8.RuneCountInString(name) > 64 {
		return "", fmt.Errorf("%w: name must be 2-64 characters", ErrValidation)
	}
	return name, nil
}

func (s *Store) Profiles() []RoutingProfile {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return append([]RoutingProfile{}, s.profiles...)
}

func (s *Store) Endpoints() []ProxyEndpoint {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return append([]ProxyEndpoint{}, s.proxies...)
}

func (s *Store) CreateProfile(name string) (RoutingProfile, error) {
	name, err := validateName(name)
	if err != nil {
		return RoutingProfile{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, p := range s.profiles {
		if strings.EqualFold(p.Name, name) {
			return RoutingProfile{}, fmt.Errorf("%w: profile name already exists", ErrConflict)
		}
	}
	profile := RoutingProfile{
		ID: newID("profile"), Name: name, Status: "unconfigured",
		UniqueIPRequired: true, KillSwitchRequired: true, CreatedAt: time.Now().UTC(),
	}
	s.profiles = append(s.profiles, profile)
	if err := s.saveLocked(); err != nil {
		s.profiles = s.profiles[:len(s.profiles)-1]
		return RoutingProfile{}, err
	}
	return profile, nil
}

func (s *Store) CreateEndpoint(name, protocol, profileID string, port int) (ProxyEndpoint, error) {
	name, err := validateName(name)
	if err != nil {
		return ProxyEndpoint{}, err
	}
	if protocol != "socks5" && protocol != "http-connect" {
		return ProxyEndpoint{}, fmt.Errorf("%w: protocol must be socks5 or http-connect", ErrValidation)
	}
	if port < 1024 || port > 65535 {
		return ProxyEndpoint{}, fmt.Errorf("%w: port must be 1024-65535", ErrValidation)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	found := false
	for _, p := range s.profiles {
		if p.ID == profileID {
			found = true
			break
		}
	}
	if !found {
		return ProxyEndpoint{}, fmt.Errorf("%w: select a valid routing profile", ErrValidation)
	}
	for _, p := range s.proxies {
		if p.Port == port {
			return ProxyEndpoint{}, fmt.Errorf("%w: local port already assigned", ErrConflict)
		}
		if strings.EqualFold(p.Name, name) {
			return ProxyEndpoint{}, fmt.Errorf("%w: endpoint name already exists", ErrConflict)
		}
	}
	endpoint := ProxyEndpoint{
		ID: newID("proxy"), Name: name, Protocol: protocol,
		ListenHost: "127.0.0.1", Port: port, ProfileID: profileID,
		Status: "draft", CreatedAt: time.Now().UTC(),
	}
	s.proxies = append(s.proxies, endpoint)
	if err := s.saveLocked(); err != nil {
		s.proxies = s.proxies[:len(s.proxies)-1]
		return ProxyEndpoint{}, err
	}
	return endpoint, nil
}

func (s *Store) DeleteEndpoint(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i, endpoint := range s.proxies {
		if endpoint.ID == id {
			s.proxies = append(s.proxies[:i], s.proxies[i+1:]...)
			if err := s.saveLocked(); err != nil {
				s.proxies = append(s.proxies[:i], append([]ProxyEndpoint{endpoint}, s.proxies[i:]...)...)
				return err
			}
			return nil
		}
	}
	return ErrNotFound
}

func (s *Store) DeleteProfile(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, endpoint := range s.proxies {
		if endpoint.ProfileID == id {
			return fmt.Errorf("%w: profile has attached proxy endpoints", ErrConflict)
		}
	}
	for i, profile := range s.profiles {
		if profile.ID == id {
			s.profiles = append(s.profiles[:i], s.profiles[i+1:]...)
			if err := s.saveLocked(); err != nil {
				s.profiles = append(s.profiles[:i], append([]RoutingProfile{profile}, s.profiles[i:]...)...)
				return err
			}
			return nil
		}
	}
	return ErrNotFound
}

func (s *Store) saveLocked() error {
	if err := os.MkdirAll(filepath.Dir(s.path), 0700); err != nil {
		return err
	}
	contents, err := json.MarshalIndent(snapshot{Version: 1, Profiles: s.profiles, Endpoints: s.proxies}, "", "  ")
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(s.path), ".egresslab-*.tmp")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if err = tmp.Chmod(0600); err != nil {
		tmp.Close()
		return err
	}
	if _, err = tmp.Write(contents); err != nil {
		tmp.Close()
		return err
	}
	if err = tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err = tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), s.path)
}
