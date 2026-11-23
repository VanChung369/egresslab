// Command egresslab-lab-recover reports lab namespaces, ownership markers and host-side underlay
// tables left behind by a crashed or killed lab session. It only reports by default; -delete
// removes orphan namespaces whose owner is provably gone and whose links are safe (only lo and
// the lab veth ends), plus stale markers. Underlay tables are never removed automatically.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/VanChung369/egresslab/services/network-agent/internal/agent"
)

func main() {
	remove := flag.Bool("delete", false,
		"remove verified orphan namespaces and stale markers; preserve underlay tables")
	flag.Parse()

	if flag.NArg() != 0 {
		fmt.Fprintln(os.Stderr, "usage: sudo egresslab-lab-recover [-delete]")
		os.Exit(2)
	}

	if err := run(*remove); err != nil {
		log.Fatal(err)
	}
}

func run(remove bool) error {
	manager, err := agent.NewNetNSLabManager()
	if err != nil {
		return err
	}

	recovery, err := agent.NewLabRecovery(manager)
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	items, err := recovery.Scan(ctx)
	if err != nil {
		return err
	}

	if len(items) == 0 {
		fmt.Println("No EgressLab lab resources found.")
		return nil
	}

	printItems(items)

	if !remove {
		fmt.Println("\nNothing was changed.")
		fmt.Println("Re-run with -delete to remove proven orphan namespaces and stale markers.")
		fmt.Println("WireGuard interfaces, unknown links, unreadable resources and root underlay tables are preserved.")
		printUnderlayHint(items)

		return nil
	}

	removed, cleanErr := recovery.Clean(ctx)

	fmt.Println("\nRemoved:")
	if len(removed) == 0 {
		fmt.Println("  nothing")
	} else {
		printItems(removed)
	}

	if cleanErr != nil {
		fmt.Println("\nNot removed (kept on purpose):")
		for _, line := range strings.Split(cleanErr.Error(), "\n") {
			fmt.Println("  " + line)
		}
	}

	// Show the real state after cleanup, including the underlay tables kept on purpose.
	remaining, scanErr := recovery.Scan(ctx)
	if scanErr != nil {
		return errors.Join(cleanErr, fmt.Errorf("scan resources after cleanup: %w", scanErr))
	}

	fmt.Println("\nRemaining resources:")
	if len(remaining) == 0 {
		fmt.Println("  none")
	} else {
		printItems(remaining)
	}

	printUnderlayHint(remaining)

	return cleanErr
}

// printUnderlayHint explains how to remove an orphan underlay table by hand, only after the
// tunnel is proven gone. Recovery never removes these tables itself.
func printUnderlayHint(items []agent.LabRecoveryItem) {
	var orphans []string
	for _, item := range items {
		if item.Kind == "underlay_table" && item.State == agent.LabStateOrphanTable {
			orphans = append(orphans, item.Name)
		}
	}

	if len(orphans) == 0 {
		return
	}

	fmt.Println("\nRoot underlay tables are not deleted automatically: a namespace without its name can")
	fmt.Println("still hold a WireGuard interface whose encrypted socket that table confines.")
	fmt.Println("Remove one by hand only after confirming no WireGuard interface with its fwmark remains:")
	fmt.Println("  sudo nft list table inet <table>      # note the 'meta mark' value")
	fmt.Println("  sudo sh -c 'for n in $(ip netns list | cut -d\" \" -f1); do ip netns exec $n wg show all fwmark; done;")
	fmt.Println("    for p in /proc/[0-9]*; do nsenter -t ${p#/proc/} -n wg show all fwmark; done 2>/dev/null' | sort -u")
	fmt.Println("  sudo nft delete table inet <table>    # only if that mark is not listed")
}

func printItems(items []agent.LabRecoveryItem) {
	w := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(w, "KIND\tNAME\tSTATE\tDETAIL")

	for _, item := range items {
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", item.Kind, item.Name, item.State, item.Detail)
	}

	_ = w.Flush()
}
