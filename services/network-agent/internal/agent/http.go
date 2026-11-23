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

type ErrorResponse struct {
	Error string `json:"error"`
}

func NewHTTPHandler() http.Handler {
	return newHTTPHandler(discoverNetworkInterfaces)
}

func newHTTPHandler(
	listInterfaces interfaceProvider,
) http.Handler {

	if listInterfaces == nil {
		listInterfaces = discoverNetworkInterfaces
	}

	mux := http.NewServeMux()

	mux.HandleFunc("GET /health", handleHealth)

	mux.HandleFunc("GET /system/info", handleSystemInfo)

	mux.HandleFunc(
		"GET /network/interfaces",
		handleNetworkInterfaces(listInterfaces),
	)

	return mux
}

func handleHealth(w http.ResponseWriter, r *http.Request) {

	response := HealthResponse{
		Status:       "running",
		Mode:         "read-only",
		NetworkReady: false,
	}

	writeJSON(w, http.StatusOK, response)
}

func handleSystemInfo(w http.ResponseWriter, r *http.Request) {

	info, err := discoverSystemInfo()
	if err != nil {
		log.Printf("discover system info: %v", err)

		writeJSON(
			w,
			http.StatusInternalServerError,
			ErrorResponse{
				Error: "failed to discover system information",
			},
		)
		return
	}

	writeJSON(w, http.StatusOK, info)
}

func handleNetworkInterfaces(
	listInterfaces interfaceProvider,
) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {

		interfaces, err := listInterfaces()
		if err != nil {
			log.Printf("discover network interfaces: %v", err)

			writeJSON(
				w,
				http.StatusInternalServerError,
				ErrorResponse{
					Error: "failed to discover network interfaces",
				},
			)
			return
		}

		if interfaces == nil {
			interfaces = []NetworkInterface{}
		}

		response := NetworkInterfacesResponse{
			Interfaces: interfaces,
		}

		writeJSON(w, http.StatusOK, response)
	}
}

func writeJSON(
	w http.ResponseWriter,
	status int,
	value any,
) {

	w.Header().Set(
		"Content-Type",
		"application/json; charset=utf-8",
	)

	w.WriteHeader(status)

	if err := json.NewEncoder(w).Encode(value); err != nil {
		log.Printf("write JSON response: %v", err)
	}
}
