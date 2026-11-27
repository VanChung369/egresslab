package main

import (
	"errors"
	"flag"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/VanChung369/egresslab/services/controller/internal/control"
)

func main() {
	address := flag.String("listen", "127.0.0.1:8787", "Loopback HTTP control API address")
	desktop := flag.Bool("desktop", false, "Serve private desktop IPC over stdin/stdout")
	flag.Parse()

	host, _, err := net.SplitHostPort(*address)
	if err != nil || (host != "127.0.0.1" && host != "localhost" && host != "::1") {
		log.Fatal("control API must listen on loopback only")
	}

	root := os.Getenv("EGRESSLAB_DATA_DIR")
	if root == "" {
		config, err := os.UserConfigDir()
		if err != nil {
			log.Fatal(err)
		}

		root = filepath.Join(config, "EgressLab")
	}

	storeLock, err := control.LockControllerStore(root)
	if errors.Is(err, control.ErrControllerRunning) {
		// The desktop supervisor reads this exit status to say why the controller stopped.
		log.Print("Controller store unavailable: ", err)
		os.Exit(control.ExitControllerRunning)
	}

	if err != nil {
		log.Fatal("Controller store unavailable: ", err)
	}
	defer storeLock.Close()

	store, err := control.NewStore(filepath.Join(root, "state.json"))
	if err != nil {
		log.Fatal(err)
	}

	var agent *control.AgentClient
	if token := os.Getenv("EGRESSLAB_AGENT_TOKEN"); token != "" {
		agent, err = control.NewAgentClient(token)
		if err != nil {
			log.Fatal("agent client configuration: ", err)
		}
	}

	api := &control.API{
		Store:   store,
		Started: time.Now(),
		Agent:   agent,
	}

	if *desktop {
		if err := control.ServeDesktopIPC(os.Stdin, os.Stdout, api.Handler()); err != nil {
			log.Fatal("Desktop IPC: ", err)
		}

		return
	}

	server := &http.Server{
		Addr:              *address,
		Handler:           api.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	log.Printf("EgressLab controller %s listening at http://%s", control.Version, *address)
	log.Printf("Mode: control-plane-only (no live VPN or proxy routing)")
	log.Fatal(server.ListenAndServe())
}
