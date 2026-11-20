package control

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"runtime"
	"strings"
	"time"
)

const Version = "0.1.0"

type API struct {
	Store   *Store
	Started time.Time
}

type apiError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

func respond(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	if value != nil {
		_ = json.NewEncoder(w).Encode(value)
	}
}

func fail(w http.ResponseWriter, status int, code, message string) {
	respond(w, status, map[string]any{"error": apiError{Code: code, Message: message}})
}

func requestJSON(r *http.Request, into any) error {
	if !strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") {
		return fmt.Errorf("Content-Type must be application/json")
	}
	reader := json.NewDecoder(http.MaxBytesReader(nil, r.Body, 32768))
	reader.DisallowUnknownFields()
	if err := reader.Decode(into); err != nil {
		return err
	}
	var extra any
	if err := reader.Decode(&extra); errors.Is(err, io.EOF) {
		return nil
	}
	return fmt.Errorf("request body must contain exactly one JSON object")
}

func errorFor(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, ErrValidation):
		fail(w, http.StatusBadRequest, "VALIDATION_ERROR", err.Error())
	case errors.Is(err, ErrConflict):
		fail(w, http.StatusConflict, "CONFLICT", err.Error())
	case errors.Is(err, ErrNotFound):
		fail(w, http.StatusNotFound, "NOT_FOUND", err.Error())
	default:
		fail(w, http.StatusInternalServerError, "INTERNAL_ERROR", "Could not save the requested change")
	}
}

func (a *API) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/v1/health", func(w http.ResponseWriter, r *http.Request) {
		respond(w, 200, map[string]any{
			"status": "ready", "version": Version, "platform": runtime.GOOS,
			"uptime_seconds": int(time.Since(a.Started).Seconds()),
			"mode":           "control-plane-only",
			"capabilities": map[string]bool{
				"proxy_runtime": false, "vpn_runtime": false,
				"routing_enforcement": false, "egress_verification": false,
			},
		})
	})
	mux.HandleFunc("GET /api/v1/overview", func(w http.ResponseWriter, r *http.Request) {
		respond(w, 200, map[string]any{
			"profiles": len(a.Store.Profiles()), "proxy_endpoints": len(a.Store.Endpoints()),
			"active_proxies": 0, "connected_vpns": 0, "verified_exit_ips": 0,
			"network_enforcement_ready": false,
		})
	})
	mux.HandleFunc("GET /api/v1/profiles", func(w http.ResponseWriter, r *http.Request) {
		respond(w, 200, map[string]any{"items": a.Store.Profiles()})
	})
	mux.HandleFunc("POST /api/v1/profiles", func(w http.ResponseWriter, r *http.Request) {
		var input struct {
			Name string `json:"name"`
		}
		if err := requestJSON(r, &input); err != nil {
			fail(w, 400, "BAD_JSON", err.Error())
			return
		}
		item, err := a.Store.CreateProfile(input.Name)
		if err != nil {
			errorFor(w, err)
			return
		}
		respond(w, 201, item)
	})
	mux.HandleFunc("DELETE /api/v1/profiles/{id}", func(w http.ResponseWriter, r *http.Request) {
		if err := a.Store.DeleteProfile(r.PathValue("id")); err != nil {
			errorFor(w, err)
			return
		}
		w.WriteHeader(204)
	})
	mux.HandleFunc("GET /api/v1/endpoints", func(w http.ResponseWriter, r *http.Request) {
		respond(w, 200, map[string]any{"items": a.Store.Endpoints()})
	})
	mux.HandleFunc("POST /api/v1/endpoints", func(w http.ResponseWriter, r *http.Request) {
		var input struct {
			Name      string `json:"name"`
			Protocol  string `json:"protocol"`
			ProfileID string `json:"profile_id"`
			Port      int    `json:"port"`
		}
		if err := requestJSON(r, &input); err != nil {
			fail(w, 400, "BAD_JSON", err.Error())
			return
		}
		item, err := a.Store.CreateEndpoint(input.Name, input.Protocol, input.ProfileID, input.Port)
		if err != nil {
			errorFor(w, err)
			return
		}
		respond(w, 201, item)
	})
	mux.HandleFunc("DELETE /api/v1/endpoints/{id}", func(w http.ResponseWriter, r *http.Request) {
		if err := a.Store.DeleteEndpoint(r.PathValue("id")); err != nil {
			errorFor(w, err)
			return
		}
		w.WriteHeader(204)
	})
	mux.HandleFunc("POST /api/v1/endpoints/{id}/start", func(w http.ResponseWriter, r *http.Request) {
		fail(w, 409, "ROUTE_NOT_VERIFIED", "Proxy activation is disabled until VPN isolation, egress IP verification, and the kill-switch are enforced")
	})
	mux.HandleFunc("GET /api/v1/tunnels", func(w http.ResponseWriter, r *http.Request) {
		respond(w, 200, map[string]any{"items": []any{}})
	})
	mux.HandleFunc("GET /api/v1/agents", func(w http.ResponseWriter, r *http.Request) {
		respond(w, 200, map[string]any{"items": []any{}})
	})
	return protectBrowserAccess(mux)
}

func protectBrowserAccess(next http.Handler) http.Handler {
	// Development allowlist only. Replace with authenticated IPC before privileged control.
	allowed := map[string]bool{
		"http://127.0.0.1:5173": true, "http://localhost:5173": true,
		"tauri://localhost": true, "http://tauri.localhost": true,
		"https://tauri.localhost": true,
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		if origin != "" {
			if !allowed[origin] {
				fail(w, 403, "ORIGIN_BLOCKED", "Browser origin not allowed")
				return
			}
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Vary", "Origin")
			w.Header().Set("Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS")
			w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
		}
		w.Header().Set("X-Content-Type-Options", "nosniff")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}
