package main

import (
	"log"
	"net/http"
	"os"
	"time"

	"github.com/VanChung369/egresslab/services/network-agent/internal/agent"
)

func main() {
	// The HTTP API is read-only; refuse to serve it with root or networking capabilities.
	if err := agent.RequireUnprivilegedAgent(); err != nil {
		log.Fatal(err)
	}

	token := os.Getenv("EGRESSLAB_AGENT_TOKEN")
	handler, err := agent.NewAuthenticatedHTTPHandler(token)
	if err != nil {
		log.Fatal("network agent configuration: ", err)
	}

	server := &http.Server{
		Addr:              "127.0.0.1:8788",
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
	}

	log.Println("EgressLab Network Agent listening on 127.0.0.1:8788")

	log.Fatal(server.ListenAndServe())
}
