package control

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"
)

func TestCreateAndPersist(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")

	store, err := NewStore(path)
	if err != nil {
		t.Fatal(err)
	}

	p, err := store.CreateProfile("Japan Lab")
	if err != nil {
		t.Fatal(err)
	}

	if !p.UniqueIPRequired || !p.KillSwitchRequired || p.Status != "unconfigured" {
		t.Fatal("profile must be fail-closed", p)
	}

	e, err := store.CreateEndpoint("QA Proxy", "socks5", p.ID, 1080)
	if err != nil {
		t.Fatal(err)
	}

	if e.Status != "draft" || e.ListenHost != "127.0.0.1" {
		t.Fatal("unverified endpoint must remain inactive and bound to localhost", e)
	}

	if _, err = store.CreateEndpoint("Second", "socks5", p.ID, 1080); err == nil {
		t.Fatal("duplicate port allowed")
	}

	if err = store.DeleteProfile(p.ID); err == nil {
		t.Fatal("in-use profile deleted")
	}

	reloaded, err := NewStore(path)
	if err != nil {
		t.Fatal(err)
	}

	if len(reloaded.Profiles()) != 1 || len(reloaded.Endpoints()) != 1 {
		t.Fatal("persistence failed")
	}

	if err = reloaded.DeleteEndpoint(e.ID); err != nil {
		t.Fatal(err)
	}

	if err = reloaded.DeleteProfile(p.ID); err != nil {
		t.Fatal(err)
	}
}

func TestAPI(t *testing.T) {
	store, err := NewStore(filepath.Join(t.TempDir(), "state.json"))
	if err != nil {
		t.Fatal(err)
	}

	ts := httptest.NewServer((&API{Store: store, Started: time.Now()}).Handler())
	defer ts.Close()

	resp, err := ts.Client().Get(ts.URL + "/api/v1/health")
	if err != nil {
		t.Fatal(err)
	}

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("health: %d", resp.StatusCode)
	}

	resp.Body.Close()

	payload, _ := json.Marshal(map[string]string{"name": "Research Route"})

	resp, err = ts.Client().Post(ts.URL+"/api/v1/profiles", "application/json", bytes.NewReader(payload))
	if err != nil {
		t.Fatal(err)
	}

	if resp.StatusCode != 201 {
		t.Fatalf("create profile: %d", resp.StatusCode)
	}

	var profile RoutingProfile
	if err := json.NewDecoder(resp.Body).Decode(&profile); err != nil {
		t.Fatal(err)
	}

	resp.Body.Close()

	endpointRequest, _ := json.Marshal(map[string]any{
		"name":       "Safe Proxy",
		"protocol":   "socks5",
		"port":       1080,
		"profile_id": profile.ID,
	})

	resp, err = ts.Client().Post(ts.URL+"/api/v1/endpoints", "application/json", bytes.NewReader(endpointRequest))
	if err != nil {
		t.Fatal(err)
	}

	if resp.StatusCode != 201 {
		t.Fatalf("create endpoint: %d", resp.StatusCode)
	}

	var endpoint ProxyEndpoint
	if err := json.NewDecoder(resp.Body).Decode(&endpoint); err != nil {
		t.Fatal(err)
	}

	resp.Body.Close()

	resp, err = ts.Client().Post(
		ts.URL+"/api/v1/endpoints/"+endpoint.ID+"/start",
		"application/json",
		bytes.NewReader([]byte("{}")),
	)
	if err != nil {
		t.Fatal(err)
	}

	if resp.StatusCode != http.StatusConflict {
		t.Fatalf("unverified route activated: %d", resp.StatusCode)
	}

	resp.Body.Close()

	req, _ := http.NewRequest("POST", ts.URL+"/api/v1/profiles", bytes.NewReader(payload))
	req.Header.Set("Origin", "https://untrusted.test")
	req.Header.Set("Content-Type", "application/json")

	resp, err = ts.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}

	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("untrusted browser origin accepted: %d", resp.StatusCode)
	}

	resp.Body.Close()
}

// DNS rebinding: an attacker page resolves its own domain to 127.0.0.1, so its
// same-origin GETs arrive with no Origin header but with the attacker's Host.
func TestRejectsNonLoopbackHost(t *testing.T) {
	store, err := NewStore(filepath.Join(t.TempDir(), "state.json"))
	if err != nil {
		t.Fatal(err)
	}

	ts := httptest.NewServer((&API{Store: store, Started: time.Now()}).Handler())
	defer ts.Close()

	hosts := []string{
		"attacker.example:8787",
		"attacker.example",
		"127.0.0.1.attacker.example:8787",
	}

	for _, host := range hosts {
		req, _ := http.NewRequest("GET", ts.URL+"/api/v1/profiles", nil)
		req.Host = host

		resp, err := ts.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}

		resp.Body.Close()

		if resp.StatusCode != http.StatusForbidden {
			t.Fatalf("host %q accepted: %d", host, resp.StatusCode)
		}
	}
}

func TestIsLoopbackHost(t *testing.T) {
	allowed := []string{
		"127.0.0.1:8787",
		"localhost:8787",
		"LocalHost",
		"[::1]:8787",
	}

	for _, host := range allowed {
		if !isLoopbackHost(host) {
			t.Errorf("loopback host %q rejected", host)
		}
	}

	blocked := []string{
		"",
		"attacker.example",
		"localhost.attacker.example:8787",
		"192.168.1.10:8787",
		"[::2]:8787",
	}

	for _, host := range blocked {
		if isLoopbackHost(host) {
			t.Errorf("non-loopback host %q accepted", host)
		}
	}
}
