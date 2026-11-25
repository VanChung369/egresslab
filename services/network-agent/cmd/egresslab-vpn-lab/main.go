package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"net/netip"
	"os"
	"time"

	"github.com/VanChung369/egresslab/services/network-agent/internal/agent"
	"github.com/VanChung369/egresslab/services/network-agent/internal/labcli"
)

const (
	probeAttempts   = 3
	probeRetryDelay = 2 * time.Second
	watchInterval   = 2 * time.Second

	// Upper bound of one egress probe: the HTTP client gives up after 10s, the probe
	// subprocess is killed after 15s.
	leakProbeWait = 15 * time.Second
)

func main() {
	if len(os.Args) == 3 && os.Args[1] == "internal-probe" {
		os.Exit(probe(os.Args[2]))
	}

	file := flag.String("file", "", "path to a WireGuard .conf file (chmod 600)")
	probeURL := flag.String("probe-url", agent.DefaultEgressProbeURL, "HTTPS URL on an IPv4 literal returning an ip= line")
	flag.Parse()

	if *file == "" || flag.NArg() != 0 {
		fmt.Fprintln(os.Stderr, "usage: sudo egresslab-vpn-lab -file /path/to/config.conf [-probe-url URL]")
		os.Exit(2)
	}

	if err := run(*file, *probeURL); err != nil {
		log.Fatal(err)
	}
}

func probe(url string) int {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	body, err := agent.FetchEgressTrace(ctx, url)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}

	_, _ = os.Stdout.Write(body)

	return 0
}

func run(file, probeURL string) (resultErr error) {
	target, err := agent.ParseEgressProbeURL(probeURL)
	if err != nil {
		return err
	}

	cfg, err := agent.LoadWireGuardConfig(file)
	if err != nil {
		return fmt.Errorf("import rejected: %w", err)
	}

	// Fail before any namespace or tunnel exists if the lab cannot use this config.
	if err := agent.CheckVPNLabCompatibility(cfg); err != nil {
		return fmt.Errorf("config is valid but not usable by the VPN egress lab: %w", err)
	}

	self, err := os.Executable()
	if err != nil {
		return err
	}

	manager, err := agent.NewNetNSLabManager()
	if err != nil {
		return err
	}

	firewall, err := agent.NewLabFirewall(manager)
	if err != nil {
		return err
	}

	lab, err := agent.NewVPNEgressLab(manager, firewall, self)
	if err != nil {
		return err
	}

	registry, err := agent.NewEgressCandidateRegistry(30 * time.Second)
	if err != nil {
		return err
	}

	profileID, err := labProfileID()
	if err != nil {
		return err
	}

	session := labcli.Start(manager)
	defer session.Close(&resultErr)

	// The baseline is required: without it the lab cannot show that the tunnel changes egress.
	// It gets the same retries as the tunnel probe, so one transient failure does not end the run.
	var direct netip.Addr
	directErr := session.Step("direct probe", func(ctx context.Context) error {
		var err error
		direct, err = probeWithRetry(session, "Direct probe", func() (netip.Addr, error) {
			return lab.Probe(ctx, "", target)
		})
		return err
	})

	if errors.Is(directErr, labcli.ErrInterrupted) {
		return directErr
	}

	if directErr != nil {
		return fmt.Errorf(
			"cannot establish the host's direct egress baseline after %d attempts "+
				"(the host must reach %s directly): %w",
			probeAttempts, target.URL, directErr,
		)
	}

	ns, err := session.CreateNamespace()
	if err != nil {
		return fmt.Errorf("create lab namespace: %w", err)
	}

	// Removes wg0 first, then the host-side underlay table (retried after namespace deletion).
	session.OnCleanup("tunnel and underlay policy for "+ns, func(ctx context.Context) error {
		return lab.Disconnect(ctx, ns)
	})

	steps := []struct {
		title string
		run   func(context.Context) error
	}{
		{"seal namespace", func(ctx context.Context) error { return firewall.Seal(ctx, ns) }},
		{"bring up tunnel (underlay policy first)", func(ctx context.Context) error { return lab.Connect(ctx, ns, cfg) }},
		{"verify underlay policy and fwmark", func(ctx context.Context) error { return lab.VerifyUnderlay(ctx, ns) }},
		{"allow probe through tunnel", func(ctx context.Context) error {
			return firewall.PermitEgressProbe(ctx, ns, target.IP)
		}},
		{"verify lab firewall readback", func(ctx context.Context) error { return firewall.Verify(ctx, ns) }},
	}

	for _, step := range steps {
		if err := session.Step(step.title, step.run); err != nil {
			return err
		}
	}

	// ProbeVerified reads back the namespace firewall, the underlay table and wg0's fwmark before
	// and after each request. A network error is retried; an isolation failure is not, and its
	// IP is never used for a candidate.
	var observed netip.Addr
	if err := session.Step("probe through tunnel (isolation verified before and after)", func(ctx context.Context) error {
		var err error
		observed, err = probeWithRetry(session, "Tunnel probe", func() (netip.Addr, error) {
			return lab.ProbeVerified(ctx, ns, target)
		})
		return err
	}); err != nil {
		if errors.Is(err, labcli.ErrInterrupted) {
			return err
		}

		isolationFailed := errors.Is(err, agent.ErrVPNIsolationNotVerified)

		if !isolationFailed {
			if handshake, hsErr := lab.LatestHandshake(context.Background(), ns); hsErr == nil && handshake.IsZero() {
				err = fmt.Errorf("%w (the tunnel never completed a handshake)", err)
			}
		}

		fmt.Printf("Namespace: %s\n", ns)

		if isolationFailed {
			fmt.Printf("Isolation verification failed; the probe result is not trusted: %v\n", err)
			fmt.Println("Quarantining the tunnel now. Do not activate this route.")

			// Never wait for input while an unsafe tunnel may still be up.
			return quarantineAfter(lab, ns, fmt.Errorf("isolation verification failed: %w", err))
		}

		fmt.Printf("Probe through tunnel failed: %v\n", err)
		fmt.Println("No egress candidate was recorded. Inspect the namespace, then press Enter or Ctrl+C to clean up.")
		session.WaitForEnter()

		return err
	}

	handshake, err := lab.LatestHandshake(context.Background(), ns)
	if err != nil {
		return err
	}

	// The successful probe already proves a live session (the namespace has only lo and wg0), so
	// an odd handshake timestamp, usually a WSL clock jump, is reported but does not end the run.
	if err := agent.ValidateVPNLabHandshake(time.Now(), handshake); err != nil {
		fmt.Printf("Warning: %v\n", err)
	}

	if observed == direct {
		return fmt.Errorf(
			"observed egress IP %s equals the host's direct egress IP: traffic may not be using "+
				"the tunnel, or the host itself already exits through the same VPN or provider "+
				"(disconnect any VPN on the host, for example on Windows, and run the lab again)",
			observed,
		)
	}

	if _, err := registry.Evaluate(agent.EgressObservation{
		ProfileID:  profileID,
		ObservedIP: observed.String(),
		ObservedAt: time.Now(),
	}); err != nil {
		return fmt.Errorf("egress candidate rejected: %w", err)
	}

	// Pin the observed IP (in memory for this lab): any later observation must match it.
	status, err := registry.Activate(profileID)
	if err != nil {
		return fmt.Errorf("pin egress IP: %w", err)
	}

	candidate, _ := json.Marshal(status)

	fmt.Printf("Namespace: %s (only lo and wg0; IPv4 default route via wg0; IPv6 and DNS port 53 explicitly dropped)\n", ns)
	fmt.Println("Underlay: encrypted UDP from wg0 is marked and may only reach the configured endpoint (host-side nft table)")
	fmt.Printf("Tunnel handshake: %s ago\n", time.Since(handshake).Round(time.Second))
	fmt.Printf("Observed egress IPv4: %s (via %s)\n", observed, target.URL)
	fmt.Printf("Differs from the host's direct egress IP (%s): yes\n", direct)
	fmt.Printf("Candidate: %s\n", candidate)
	fmt.Printf("Check: sudo ip netns exec %s wg show wg0 latest-handshakes\n", ns)
	fmt.Println(labcli.StopCommandsHint)
	fmt.Println("Press Enter to simulate tunnel loss (peer removed), or Ctrl+C to clean up.")
	fmt.Printf("While waiting, the namespace firewall, underlay and fwmark are re-verified every %s.\n", watchInterval)

	// A polling lab diagnostic, not a production safety service: changes between two checks
	// are not caught, and the watchdog only runs while this process runs.
	entered, err := waitForEnterWatched(session, lab, ns)
	if err != nil {
		return err
	}

	if !entered {
		return nil
	}

	fmt.Println("Removing the tunnel peer (simulated tunnel loss)...")

	if err := session.Step("remove tunnel peer", func(ctx context.Context) error {
		return lab.DropPeer(ctx, ns, cfg)
	}); err != nil {
		return err
	}

	registry.Release(profileID)
	if err := registry.Deactivate(profileID); err != nil {
		return err
	}

	// Without a peer, wg0 drops every packet, so the probe can only end by timing out. It is not
	// cancelled by Ctrl+C: its result is the point of the test and must always be reported.
	fmt.Printf("Probing %s with no tunnel peer; this must fail. Waiting up to %s (Ctrl+C waits too)...\n",
		target.URL, leakProbeWait)

	var leaked netip.Addr
	var leakErr error
	probed := false

	probeErr := session.Step("probe after tunnel loss", func(ctx context.Context) error {
		probed = true
		leaked, leakErr = lab.Probe(ctx, ns, target)
		return leakErr
	})

	// A completed probe that succeeded is a leak, even if the user interrupted meanwhile.
	if probed && leakErr == nil {
		return fmt.Errorf("LEAK: probe reached %s after the tunnel peer was removed (egress %s)", target.URL, leaked)
	}

	if probed {
		fmt.Println("Probe after tunnel loss: failed as expected (no fallback route).")
	}

	if errors.Is(probeErr, labcli.ErrInterrupted) {
		return probeErr
	}
	fmt.Printf("Candidate after tunnel loss: %s\n", registry.Snapshot(profileID).Status)
	fmt.Println("Press Enter or Ctrl+C to clean up.")

	session.WaitForEnter()

	return nil
}

// quarantineAfter removes the tunnel right away after an isolation failure and returns cause,
// joined with any quarantine error (in which case isolation must not be assumed restored).
func quarantineAfter(lab *agent.VPNEgressLab, ns string, cause error) error {
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()

	if err := lab.Quarantine(ctx, ns); err != nil {
		return errors.Join(cause, fmt.Errorf("emergency quarantine: %w", err))
	}

	return fmt.Errorf("VPN tunnel quarantined: %w", cause)
}

// waitForEnterWatched waits for Enter (true) or Ctrl+C (false) while the isolation watchdog
// runs. A watchdog failure (it has already quarantined the tunnel) is returned as an error,
// including one that races with Enter, so it is never silently dropped.
func waitForEnterWatched(session *labcli.Session, lab *agent.VPNEgressLab, ns string) (bool, error) {
	watchCtx, stopWatch := context.WithCancel(context.Background())
	defer stopWatch()

	faults := lab.WatchIsolation(watchCtx, ns, watchInterval)

	entered := make(chan bool, 1)
	go func() { entered <- session.WaitForEnter() }()

	select {
	case ok := <-entered:
		stopWatch()

		// Wait for the watchdog to finish, so it never runs alongside the next lab step.
		if watchErr, failed := <-faults; failed && watchErr != nil {
			return false, fmt.Errorf("VPN isolation watchdog: %w", watchErr)
		}

		return ok, nil

	case watchErr, failed := <-faults:
		if !failed {
			return false, errors.New("VPN isolation watchdog stopped unexpectedly")
		}

		fmt.Printf("Isolation watchdog: %v\n", watchErr)

		return false, fmt.Errorf("VPN isolation watchdog stopped the tunnel: %w", watchErr)
	}
}

// probeWithRetry runs probe up to probeAttempts times. It checks for Ctrl+C before every attempt
// and during the back-off, so an interrupt waits for at most the probe in flight. Isolation
// failures (ErrVPNIsolationNotVerified) are returned at once: retrying cannot make them safe.
func probeWithRetry(
	session *labcli.Session,
	label string,
	probe func() (netip.Addr, error),
) (netip.Addr, error) {
	var lastErr error

	for attempt := 1; attempt <= probeAttempts; attempt++ {
		if err := session.Err(); err != nil {
			return netip.Addr{}, err
		}

		ip, err := probe()
		if err == nil {
			return ip, nil
		}

		if errors.Is(err, agent.ErrVPNIsolationNotVerified) {
			return netip.Addr{}, err
		}

		lastErr = err

		if attempt < probeAttempts {
			fmt.Printf("%s attempt %d failed (%v); retrying.\n", label, attempt, err)

			if err := session.Pause(probeRetryDelay); err != nil {
				return netip.Addr{}, err
			}
		}
	}

	return netip.Addr{}, lastErr
}

func labProfileID() (string, error) {
	var data [8]byte
	if _, err := rand.Read(data[:]); err != nil {
		return "", err
	}

	return "profile_" + hex.EncodeToString(data[:]), nil
}
