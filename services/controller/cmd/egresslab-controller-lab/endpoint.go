package main

import (
	"context"
	"errors"
	"path/filepath"
	"strconv"

	"github.com/VanChung369/egresslab/services/controller/internal/control"
	"github.com/VanChung369/egresslab/services/controller/internal/labruntime"
)

// endpointRoute is what the stored endpoint, the profile's runtime binding and the trusted runtime
// say, without the reservation journal.
type endpointRoute struct {
	EndpointID      string
	Port            int
	ProfileID       string
	RuntimeID       string
	Namespace       string
	HelperEpoch     string
	Provider        string
	Target          string
	PublicKeySHA256 string
}

// endpointPlan is a route resolved to the profile's current durable hold. It authorizes nothing by
// itself.
type endpointPlan struct {
	endpointRoute
	ReservationID string
	Owner         control.LeaseOwner
	IPv4          string
}

func readEndpointRoute(dataDir, endpointID string) (endpointRoute, error) {
	if !control.ValidEndpointID(endpointID) {
		return endpointRoute{}, control.ErrValidation
	}

	store, err := control.NewStore(filepath.Join(dataDir, "state.json"))
	if err != nil {
		return endpointRoute{}, err
	}

	var endpoint control.ProxyEndpoint

	for _, item := range store.Endpoints() {
		if item.ID == endpointID {
			endpoint = item
			break
		}
	}

	if endpoint.ID == "" {
		return endpointRoute{}, control.ErrNotFound
	}

	if endpoint.Protocol != "socks5" || endpoint.ListenHost != "127.0.0.1" || !validSocksPort(strconv.Itoa(endpoint.Port)) {
		return endpointRoute{}, errors.New("unsupported proxy endpoint: only SOCKS5 on 127.0.0.1 is served")
	}

	state, err := control.LoadRuntimeState(dataDir)
	if err != nil {
		return endpointRoute{}, err
	}

	binding, exists := state.Binding(endpoint.ProfileID)
	if !exists {
		return endpointRoute{}, errors.New("profile has no runtime binding")
	}

	for _, rt := range state.Runtimes {
		if rt.ID == binding.RuntimeID {
			return endpointRoute{
				EndpointID:      endpoint.ID,
				Port:            endpoint.Port,
				ProfileID:       endpoint.ProfileID,
				RuntimeID:       binding.RuntimeID,
				Namespace:       binding.Namespace,
				HelperEpoch:     binding.HelperEpoch,
				Provider:        rt.Provider,
				Target:          rt.Target,
				PublicKeySHA256: rt.PublicKeySHA256,
			}, nil
		}
	}

	return endpointRoute{}, labruntime.Errorf(labruntime.CodeRuntimeUntrusted, "runtime not trusted")
}

// readEndpointPlan resolves the route and the profile's hold; both must agree.
func readEndpointPlan(dataDir, endpointID string, authority *control.ReservationAuthority) (endpointPlan, error) {
	route, err := readEndpointRoute(dataDir, endpointID)
	if err != nil {
		return endpointPlan{}, err
	}

	if route.PublicKeySHA256 != authority.Info().PublicKeySHA256 {
		return endpointPlan{}, errors.New("runtime key mismatch")
	}

	holds, err := authority.List()
	if err != nil {
		return endpointPlan{}, err
	}

	for _, hold := range holds {
		if hold.Owner.ProfileID != route.ProfileID {
			continue
		}

		if hold.Owner.RuntimeID != route.RuntimeID || hold.Owner.Namespace != route.Namespace ||
			hold.Owner.HelperEpoch != route.HelperEpoch || hold.PublicKeySHA256 != route.PublicKeySHA256 {
			return endpointPlan{}, errors.New("reservation and runtime binding disagree")
		}

		return endpointPlan{endpointRoute: route, ReservationID: hold.ID, Owner: hold.Owner, IPv4: hold.IPv4.String()}, nil
	}

	return endpointPlan{}, control.ErrReservationNotFound
}

// serveEndpoint serves a stored endpoint on its own runtime, pinned to the hold and generation
// approved at start: a later hold for the profile needs a new, approved start.
func (s *session) serveEndpoint(endpointID string) error {
	authority, keys, err := s.openReservationAuthority()
	if err != nil {
		return err
	}

	plan, err := readEndpointPlan(s.dataDir, endpointID, authority)
	if err != nil {
		return reservationCommandError(err)
	}

	var options labruntime.Options

	switch plan.Provider {
	case "lima":
		options.LimaInstance = plan.Target
	case "wsl":
		options.WSLDistro = plan.Target
	case "native":
	default:
		return errors.New("unsupported runtime provider")
	}

	if s.provider, err = s.d.newRuntime(plan.Provider, options); err != nil {
		return err
	}

	if s.provider.Kind() != plan.Provider || s.provider.Target() != plan.Target {
		return errors.New("selected runtime does not match the endpoint")
	}

	ctx, cancel := context.WithTimeout(context.Background(), proxySetupTimeout)
	info, err := s.provider.Transport().HelperInfo(ctx)
	cancel()

	if err != nil {
		return err
	}

	if !info.Valid() || !info.AuthorizationConfigured || info.RuntimeID != plan.Owner.RuntimeID ||
		info.HelperID != plan.Owner.HelperEpoch || info.PublicKeySHA256 != plan.PublicKeySHA256 {
		return labruntime.Errorf(labruntime.CodeRuntimeUntrusted, "the helper that prepared the reservation is required")
	}

	// The hold itself is looked up again when each stream is minted, just before this check; a hold
	// never changes owner.
	guard := func() error {
		current, err := readEndpointRoute(s.dataDir, endpointID)
		if err != nil {
			return err
		}

		if current != plan.endpointRoute {
			return errors.New("endpoint binding changed; restart it with a new approval")
		}

		return nil
	}

	return s.serveSocksWithAuthority(plan.ReservationID, strconv.Itoa(plan.Port), authority, keys, guard)
}
