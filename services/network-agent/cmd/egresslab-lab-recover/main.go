// Command egresslab-lab-recover reports lab namespaces, ownership markers and VM-side underlay
// tables left behind by a crashed or killed lab session. It only reports by default; -delete
// removes resources whose owner process is provably gone.
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"text/tabwriter"
	"time"

	"github.com/VanChung369/egresslab/services/network-agent/internal/agent"
)

func main() {
	remove := flag.Bool("delete", false, "remove orphans (owner gone), stale markers and unused underlay tables")
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
		fmt.Println("\nNothing was changed. Re-run with -delete to remove orphan, stale_marker and orphan_underlay entries.")
		fmt.Println("unmarked and unreadable entries are never removed automatically; inspect them by hand.")
		return nil
	}

	removed, cleanErr := recovery.Clean(ctx)

	fmt.Println("\nRemoved:")
	if len(removed) == 0 {
		fmt.Println("  nothing")
	} else {
		printItems(removed)
	}

	return cleanErr
}

func printItems(items []agent.LabRecoveryItem) {
	w := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(w, "KIND\tNAME\tSTATE\tDETAIL")

	for _, item := range items {
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", item.Kind, item.Name, item.State, item.Detail)
	}

	_ = w.Flush()
}
