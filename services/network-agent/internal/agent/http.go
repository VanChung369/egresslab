package agent

import (
	"encoding/json"
	"log"
	"net/http"
)

type HealthResponse struct {
	Status       string `json:"status"`
	Mode         string `json:"mode"`
	NetworkReady bool   `json:"network_ready"`
}

func NewHTTPHandler() http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("GET /health", handleHealth)

	return mux
}

func handleHealth(w http.ResponseWriter, r *http.Request) {

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
}
