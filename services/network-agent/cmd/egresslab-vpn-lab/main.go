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

	var direct netip.Addr
	directErr := session.Step("direct probe", func(ctx context.Context) error {
		ip, err := lab.Probe(ctx, "", target)
		direct = ip
		return err
	})

	if errors.Is(directErr, labcli.ErrInterrupted) {
		return directErr
	}

	ns, err := session.CreateNamespace()
	if err != nil {
		return fmt.Errorf("create lab namespace: %w", err)
	}

	steps := []struct {
		title string
		run   func(context.Context) error
	}{
		{"seal namespace", func(ctx context.Context) error { return firewall.Seal(ctx, ns) }},
		{"bring up tunnel", func(ctx context.Context) error { return lab.Connect(ctx, ns, cfg) }},
		{"allow probe through tunnel", func(ctx context.Context) error {
			return firewall.PermitEgressProbe(ctx, ns, target.IP)
		}},
	}

	for _, step := range steps {
		if err := session.Step(step.title, step.run); err != nil {
			return err
		}
	}

	var observed netip.Addr
	if err := session.Step("probe through tunnel", func(ctx context.Context) error {
		ip, err := lab.Probe(ctx, ns, target)
		observed = ip
		return err
	}); err != nil {
		if handshake, hsErr := lab.LatestHandshake(context.Background(), ns); hsErr == nil && handshake.IsZero() {
			return fmt.Errorf("%w (the tunnel never completed a handshake)", err)
		}
		return err
	}

	handshake, err := lab.LatestHandshake(context.Background(), ns)
	if err != nil {
		return err
	}

	if directErr == nil && observed == direct {
		return errors.New("observed egress IP equals the VM's direct egress IP; traffic is not using the VPN")
	}

	status, err := registry.Evaluate(agent.EgressObservation{
		ProfileID:  profileID,
		ObservedIP: observed.String(),
		ObservedAt: time.Now(),
	})
	if err != nil {
		return fmt.Errorf("egress candidate rejected: %w", err)
	}

	differs := "unknown (direct probe failed)"
	if directErr == nil {
		differs = "yes"
	}

	candidate, _ := json.Marshal(status)

	fmt.Printf("Namespace: %s (only lo and wg0; IPv4 default route via wg0; IPv6 not configured)\n", ns)
	fmt.Printf("Tunnel handshake: %s ago\n", time.Since(handshake).Round(time.Second))
	fmt.Printf("Observed egress IPv4: %s (via %s)\n", observed, target.URL)
	fmt.Printf("Differs from the VM's direct egress IP: %s\n", differs)
	fmt.Printf("Candidate: %s\n", candidate)
	fmt.Printf("Check: sudo ip netns exec %s wg show wg0 latest-handshakes\n", ns)
	fmt.Println(labcli.StopCommandsHint)
	fmt.Println("Press Enter to simulate tunnel loss (peer removed), or Ctrl+C to clean up.")

	if !session.WaitForEnter() {
		return nil
	}

	if err := session.Step("remove tunnel peer", func(ctx context.Context) error {
		return lab.DropPeer(ctx, ns, cfg)
	}); err != nil {
		return err
	}

	registry.Release(profileID)

	var leaked netip.Addr
	probeErr := session.Step("probe after tunnel loss", func(ctx context.Context) error {
		ip, err := lab.Probe(ctx, ns, target)
		leaked = ip
		return err
	})

	switch {
	case errors.Is(probeErr, labcli.ErrInterrupted):
		return probeErr

	case probeErr == nil:
		return fmt.Errorf("LEAK: probe reached %s after the tunnel peer was removed (egress %s)", target.URL, leaked)
	}

	fmt.Println("Probe after tunnel loss: failed as expected (no fallback route).")
	fmt.Printf("Candidate after tunnel loss: %s\n", registry.Snapshot(profileID).Status)
	fmt.Println("Press Enter or Ctrl+C to clean up.")

	session.WaitForEnter()

	return nil
}

func labProfileID() (string, error) {
	var data [8]byte
	if _, err := rand.Read(data[:]); err != nil {
		return "", err
	}

	return "profile_" + hex.EncodeToString(data[:]), nil
}
