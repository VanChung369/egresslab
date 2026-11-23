package agent

import (
	"encoding/json"
	"log"
	"net"
	"net/http"
	"strings"
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
	return newHTTPHandler(
		discoverNetworkInterfaces,
		discoverSystemInfo,
	)
}

func newHTTPHandler(
	listInterfaces interfaceProvider,
	systemInfo systemInfoProvider,
) http.Handler {

	if listInterfaces == nil {
		listInterfaces = discoverNetworkInterfaces
	}

	if systemInfo == nil {
		systemInfo = discoverSystemInfo
	}

	mux := http.NewServeMux()

	mux.HandleFunc("GET /health", handleHealth)

	mux.HandleFunc(
		"GET /system/info",
		handleSystemInfo(systemInfo),
	)

	mux.HandleFunc(
		"GET /network/interfaces",
		handleNetworkInterfaces(listInterfaces),
	)

	return protectLoopback(mux)
}

// protectLoopback only lets local, non-browser clients through.
//
// Binding to 127.0.0.1 is not enough on its own: with DNS rebinding, a web
// page on an attacker domain can resolve that domain to 127.0.0.1 and read
// responses as same-origin. The browser still sends the attacker's hostname
// in the Host header, so requiring a loopback Host blocks that. The agent
// has no browser clients, so any request carrying an Origin header is
// rejected too.
func protectLoopback(next http.Handler) http.Handler {

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		if !isLoopbackHost(r.Host) {
			log.Printf("rejected request with host %q", r.Host)

			writeJSON(
				w,
				http.StatusForbidden,
				ErrorResponse{Error: "host not allowed"},
			)
			return
		}

		if origin := r.Header.Get("Origin"); origin != "" {
			log.Printf("rejected browser request from origin %q", origin)

			writeJSON(
				w,
				http.StatusForbidden,
				ErrorResponse{Error: "browser requests are not allowed"},
			)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// isLoopbackHost reports whether a Host header value ("host" or
// "host:port") names localhost or a loopback IP address.
func isLoopbackHost(hostport string) bool {

	host, _, err := net.SplitHostPort(hostport)
	if err != nil {
		host = hostport
	}

	host = strings.TrimSuffix(strings.TrimPrefix(host, "["), "]")

	if strings.EqualFold(host, "localhost") {
		return true
	}

	ip := net.ParseIP(host)

	return ip != nil && ip.IsLoopback()
}

func handleHealth(w http.ResponseWriter, r *http.Request) {

	response := HealthResponse{
		Status:       "running",
		Mode:         "read-only",
		NetworkReady: false,
	}

	writeJSON(w, http.StatusOK, response)
}

func handleSystemInfo(
	systemInfo systemInfoProvider,
) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {

		info, err := systemInfo()
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
