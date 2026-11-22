package main

import (
	"log"
	"net/http"
	"time"

	"github.com/VanChung369/egresslab/services/network-agent/internal/agent"
)

func main() {

	handler := agent.NewHTTPHandler()

	server := &http.Server{
		Addr:              "127.0.0.1:8788",
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
	}

	log.Println("EgressLab Network Agent listening on 127.0.0.1:8788")

	log.Fatal(server.ListenAndServe())
}
