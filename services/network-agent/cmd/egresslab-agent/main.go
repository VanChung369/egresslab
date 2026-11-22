package main

import (
	"encoding/json"
	"log"
	"net/http"
	"time"
)

type HealthResponse struct {
	Status       string `json:"status"`
	Mode         string `json:"mode"`
	NetworkReady bool   `json:"network_ready"`
}

func main() {

	mux := http.NewServeMux()

	mux.HandleFunc("GET /health", func(w http.ResponseWriter, r *http.Request) {

		w.Header().Set(
			"Content-Type", "application/json",
		)

		response := HealthResponse{
			Status:       "running",
			Mode:         "read-only",
			NetworkReady: false,
		}

		if err := json.NewEncoder(w).Encode(response); err != nil {
			log.Printf("encode health response: %v", err)
		}

	})

	server := &http.Server{
		Addr:              "127.0.0.1:8788",
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}

	log.Println("EgressLab Network Agent listening on 127.0.0.1:8788")

	log.Fatal(server.ListenAndServe())
}
