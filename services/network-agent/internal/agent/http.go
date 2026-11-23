package agent

import (
	"encoding/json"
	"errors"
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
	Error APIError `json:"error"`
}

type APIError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

func NewHTTPHandler() http.Handler {
	return newHTTPHandler(discoverNetworkInterfaces, discoverSystemInfo, discoverLinuxLinks, discoverNamedNamespaces)
}

func newHTTPHandler(
	listInterfaces interfaceProvider,
	systemInfo systemInfoProvider,
	listLinks linkProvider,
	listNamespaces namespaceProvider,
) http.Handler {
	if listInterfaces == nil {
		listInterfaces = discoverNetworkInterfaces
	}

	if systemInfo == nil {
		systemInfo = discoverSystemInfo
	}

	if listLinks == nil {
		listLinks = discoverLinuxLinks
	}

	if listNamespaces == nil {
		listNamespaces = discoverNamedNamespaces
	}

	mux := http.NewServeMux()

	mux.HandleFunc("GET /health", handleHealth)
	mux.HandleFunc("GET /system/info", handleSystemInfo(systemInfo))
	mux.HandleFunc("GET /network/interfaces", handleNetworkInterfaces(listInterfaces))
	mux.HandleFunc("GET /network/links", handleLinks(listLinks))
	mux.HandleFunc("GET /capabilities", handleCapabilities(discoverCapabilities))
	mux.HandleFunc("GET /network/namespaces", handleNamespaces(listNamespaces))

	return protectLoopback(mux)
}

func protectLoopback(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !isLoopbackHost(r.Host) {
			log.Printf("rejected request with host %q", r.Host)
			writeError(w, http.StatusForbidden, "HOST_BLOCKED", "Host not allowed")
			return
		}

		if origin := r.Header.Get("Origin"); origin != "" {
			log.Printf("rejected browser request from origin %q", origin)
			writeError(w, http.StatusForbidden, "ORIGIN_BLOCKED", "Browser requests are not allowed")
			return
		}

		next.ServeHTTP(w, r)
	})
}

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

func handleSystemInfo(systemInfo systemInfoProvider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		info, err := systemInfo()
		if err != nil {
			log.Printf("discover system info: %v", err)
			writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to discover system information")
			return
		}

		writeJSON(w, http.StatusOK, info)
	}
}

func handleNetworkInterfaces(listInterfaces interfaceProvider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		interfaces, err := listInterfaces()
		if err != nil {
			log.Printf("discover network interfaces: %v", err)
			writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to discover network interfaces")
			return
		}

		if interfaces == nil {
			interfaces = []NetworkInterface{}
		}

		response := NetworkInterfacesResponse{Interfaces: interfaces}

		writeJSON(w, http.StatusOK, response)
	}
}

func handleLinks(listLinks linkProvider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		links, err := listLinks(r.Context())
		if err != nil {
			status := http.StatusServiceUnavailable
			code := "LINKS_UNAVAILABLE"
			message := "Failed to read Linux link information"

			if errors.Is(err, ErrLinuxRequired) {
				status = http.StatusNotImplemented
				code = "LINUX_REQUIRED"
				message = "Link classification requires Linux"
			}

			log.Printf("discover Linux links: %v", err)

			writeError(w, status, code, message)
			return
		}

		if links == nil {
			links = []ClassifiedLink{}
		}

		writeJSON(w, http.StatusOK, ClassifiedLinksResponse{Links: links})
	}
}

func writeError(w http.ResponseWriter, status int, code string, message string) {
	writeJSON(w, status, ErrorResponse{
		Error: APIError{
			Code:    code,
			Message: message,
		},
	})
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")

	w.WriteHeader(status)

	if err := json.NewEncoder(w).Encode(value); err != nil {
		log.Printf("write JSON response: %v", err)
	}
}
