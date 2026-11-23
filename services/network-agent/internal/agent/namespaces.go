package agent

import (
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"runtime"
)

type NamedNamespace struct {
	Name string `json:"name"`
}

type NamedNamespacesResponse struct {
	Scope      string           `json:"scope"`
	Namespaces []NamedNamespace `json:"namespaces"`
}

type namespaceProvider func() ([]NamedNamespace, error)

func discoverNamedNamespaces() ([]NamedNamespace, error) {
	if runtime.GOOS != "linux" {
		return nil, ErrLinuxRequired
	}

	return listNamedNamespaces("/run/netns")
}

func listNamedNamespaces(root string) ([]NamedNamespace, error) {
	entries, err := os.ReadDir(root)
	if errors.Is(err, os.ErrNotExist) {
		return []NamedNamespace{}, nil
	}

	if err != nil {
		return nil, fmt.Errorf("read named namespace directory: %w", err)
	}

	namespaces := make([]NamedNamespace, 0, len(entries))

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		namespaces = append(namespaces, NamedNamespace{Name: entry.Name()})
	}

	return namespaces, nil
}

func handleNamespaces(listNamespaces namespaceProvider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		namespaces, err := listNamespaces()
		if err != nil {
			status := http.StatusServiceUnavailable
			code := "NAMESPACES_UNAVAILABLE"
			message := "Failed to list named network namespaces"

			if errors.Is(err, ErrLinuxRequired) {
				status = http.StatusNotImplemented
				code = "LINUX_REQUIRED"
				message = "Namespace discovery requires Linux"
			}

			log.Printf("discover named namespaces: %v", err)

			writeError(w, status, code, message)
			return
		}

		if namespaces == nil {
			namespaces = []NamedNamespace{}
		}

		writeJSON(w, http.StatusOK, NamedNamespacesResponse{Scope: "named", Namespaces: namespaces})
	}
}
