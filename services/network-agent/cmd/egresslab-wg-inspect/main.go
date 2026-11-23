package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/VanChung369/egresslab/services/network-agent/internal/agent"
)

func main() {
	file := flag.String("file", "", "path to a locally owned WireGuard .conf file")
	flag.Parse()

	if *file == "" || flag.NArg() != 0 {
		fmt.Fprintln(os.Stderr, "usage: egresslab-wg-inspect -file /path/to/config.conf")
		os.Exit(2)
	}

	conf, err := agent.LoadWireGuardConfig(*file)
	if err != nil {
		fmt.Fprintln(os.Stderr, "import rejected:", err)
		os.Exit(1)
	}

	if err := json.NewEncoder(os.Stdout).Encode(conf.Summary()); err != nil {
		fmt.Fprintln(os.Stderr, "could not print safe summary")
		os.Exit(1)
	}
}
