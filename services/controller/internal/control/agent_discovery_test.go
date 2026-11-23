package control

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"
)

func discoveryAgent(t *testing.T, routes map[string]string) *AgentClient {
	t.Helper()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.Header.Get("Authorization") != "Bearer "+testAgentToken() {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		body, ok := routes[r.URL.Path]
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			return
		}

		if strings.HasPrefix(body, "!") {
			w.WriteHeader(http.StatusNotImplemented)
			body = body[1:]
		}

		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(server.Close)

	client, err := newAgentClient(server.URL, testAgentToken())
	if err != nil {
		t.Fatal(err)
	}

	return client
}

func fullDiscoveryRoutes() map[string]string {
	return map[string]string{
		"/health": healthyAgentBody,
		"/capabilities": `{"os": "linux", "network_ready": false, "checks": {
		  "iproute2": {"status": "detected", "detail": "Executable found in PATH"},
		  "wireguard_tools": {"status": "missing", "detail": "Executable not found in PATH"},
		  "Bad Key!": {"status": "detected"}}}`,
		"/network/links": `{"links": [
		  {"index": 1, "name": "lo", "kind": "loopback", "category": "loopback", "operational_state": "unknown"},
		  {"index": 4, "name": "wg-office", "kind": "wireguard", "category": "vpn-interface", "operational_state": "up"},
		  {"index": 5, "name": "<script>", "kind": "wireguard", "category": "vpn-interface", "operational_state": "up"}]}`,
		"/network/namespaces": `{"scope": "named", "namespaces": [
		  {"name": "egresslab-lab-00000000000000aa"}, {"name": "docker-1"}, {"name": "egresslab-lab-bad"}]}`,
	}
}

func TestAgentDiscoveryIsSanitized(t *testing.T) {
	status := discoveryAgent(t, fullDiscoveryRoutes()).Snapshot(context.Background())

	if status.Status != "online" || status.Discovery == nil {
		t.Fatalf("unexpected status: %+v", status)
	}

	d := status.Discovery

	if d.OS != "linux" || len(d.Errors) != 0 {
		t.Fatalf("unexpected discovery header: %+v", d)
	}

	want := map[string]AgentCheck{"iproute2": {Status: "detected"}, "wireguard_tools": {Status: "missing"}}
	if !reflect.DeepEqual(d.Capabilities, want) {
		t.Fatalf("unexpected capabilities: %+v", d.Capabilities)
	}

	if len(d.Links) != 2 || d.Links[1].Name != "wg-office" {
		t.Fatalf("unsafe link names were not dropped: %+v", d.Links)
	}

	if !reflect.DeepEqual(d.LabNamespaces, []string{"egresslab-lab-00000000000000aa"}) || d.OtherNamespaces != 2 {
		t.Fatalf("unexpected namespaces: %+v %d", d.LabNamespaces, d.OtherNamespaces)
	}

	tunnels := discoveredTunnels(status)
	if len(tunnels) != 1 || tunnels[0].Name != "wg-office" || tunnels[0].Managed || tunnels[0].Source != "agent-discovery" {
		t.Fatalf("unexpected tunnels: %+v", tunnels)
	}
}

func TestAgentDiscoverySectionsFailIndependently(t *testing.T) {
	routes := fullDiscoveryRoutes()
	routes["/network/links"] = `!{"error": {"code": "LINUX_REQUIRED", "message": "Link classification requires Linux"}}`
	routes["/network/namespaces"] = `not json`

	d := discoveryAgent(t, routes).Snapshot(context.Background()).Discovery

	if d == nil || len(d.Capabilities) == 0 {
		t.Fatal("capabilities lost because another section failed")
	}

	wantErrors := []string{"links: LINUX_REQUIRED", "namespaces: invalid response"}
	if !reflect.DeepEqual(d.Errors, wantErrors) {
		t.Fatalf("unexpected errors: %v", d.Errors)
	}
}

func TestTunnelsAPIListsDiscoveredWireGuardOnly(t *testing.T) {
	api := &API{Store: newTestStore(t), Started: time.Now(), Agent: discoveryAgent(t, fullDiscoveryRoutes())}

	request := httptest.NewRequest(http.MethodGet, "/api/v1/tunnels", nil)
	request.Host = "127.0.0.1:8787"

	recorder := httptest.NewRecorder()
	api.Handler().ServeHTTP(recorder, request)

	var body struct {
		Items []DiscoveredTunnel `json:"items"`
	}

	if err := json.Unmarshal(recorder.Body.Bytes(), &body); err != nil || recorder.Code != http.StatusOK {
		t.Fatalf("unexpected response %d %s", recorder.Code, recorder.Body.String())
	}

	if len(body.Items) != 1 || body.Items[0].Name != "wg-office" || body.Items[0].Managed {
		t.Fatalf("unexpected tunnels: %+v", body.Items)
	}

	if strings.Contains(recorder.Body.String(), testAgentToken()) {
		t.Fatal("agent token leaked")
	}

	withoutAgent := &API{Store: newTestStore(t), Started: time.Now()}
	recorder = httptest.NewRecorder()
	withoutAgent.Handler().ServeHTTP(recorder, request)

	if strings.TrimSpace(recorder.Body.String()) != `{"items":[]}` {
		t.Fatalf("unexpected response without agent: %s", recorder.Body.String())
	}
}
