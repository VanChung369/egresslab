package control

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func desktopTestAPI(t *testing.T) *API {
	t.Helper()

	store, err := NewStore(filepath.Join(t.TempDir(), "state.json"))
	if err != nil {
		t.Fatal(err)
	}

	return &API{Store: store, Started: time.Now()}
}

func desktopReplies(t *testing.T, output []byte, want int) []DesktopResponse {
	t.Helper()

	// The desktop reader is line-framed: exactly one line per reply.
	lines := strings.Split(strings.TrimSuffix(string(output), "\n"), "\n")
	if len(lines) != want {
		t.Fatalf("got %d reply lines, want %d", len(lines), want)
	}

	replies := make([]DesktopResponse, 0, want)

	for _, line := range lines {
		var reply DesktopResponse
		if err := json.Unmarshal([]byte(line), &reply); err != nil || reply.Version != desktopIPCVersion {
			t.Fatalf("invalid reply %q: %v", line, err)
		}

		replies = append(replies, reply)
	}

	return replies
}

func TestDesktopIPC(t *testing.T) {
	api := desktopTestAPI(t)

	input := strings.NewReader(
		`{"version":1,"method":"POST","path":"/profiles","body":{"name":"Desktop Test"}}` + "\n" +
			`{"version":1,"method":"GET","path":"/profiles","body":null}` + "\n" +
			`{"version":1,"method":"POST","path":"/endpoints/example/start","body":null}` + "\n",
	)

	var output bytes.Buffer

	if err := ServeDesktopIPC(input, &output, api.Handler()); err != nil {
		t.Fatal(err)
	}

	for i, want := range []int{201, 200, 403} {
		if reply := desktopReplies(t, output.Bytes(), 3)[i]; reply.Status != want {
			t.Fatalf("reply %d: got status %d, want %d", i, reply.Status, want)
		}
	}

	if len(api.Store.Profiles()) != 1 {
		t.Fatal("profile was not persisted")
	}
}

func TestDesktopIPCDelete(t *testing.T) {
	api := desktopTestAPI(t)

	profile, err := api.Store.CreateProfile("Desktop Delete")
	if err != nil {
		t.Fatal(err)
	}

	input := strings.NewReader(`{"version":1,"method":"DELETE","path":"/profiles/` + profile.ID + `","body":null}` + "\n")

	var output bytes.Buffer

	if err := ServeDesktopIPC(input, &output, api.Handler()); err != nil {
		t.Fatal(err)
	}

	reply := desktopReplies(t, output.Bytes(), 1)[0]
	if reply.Status != 204 || string(reply.Body) != "null" || len(api.Store.Profiles()) != 0 {
		t.Fatalf("delete through IPC: %d %s", reply.Status, reply.Body)
	}
}

func TestDesktopIPCDeniedRoutes(t *testing.T) {
	api := desktopTestAPI(t)

	profile, err := api.Store.CreateProfile("Kept")
	if err != nil {
		t.Fatal(err)
	}

	for _, route := range [][2]string{
		{"POST", "/endpoints/proxy_0123456789abcdef/start"},
		{"get", "/profiles"},
		{"GET", "/profiles?all=1"},
		{"GET", "/api/v1/profiles"},
		{"GET", ""},
		{"PUT", "/profiles"},
		{"PATCH", "/profiles/" + profile.ID},
		{"DELETE", "/profiles/profile_xyz"},
		{"DELETE", "/profiles/../endpoints"},
		{"DELETE", "/profiles/" + profile.ID + "/"},
		{"DELETE", "/endpoints/" + profile.ID},
		{"POST", "/profiles/"},
		{"GET /profiles HTTP/1.1\r\n", "/profiles"},
		{"GET", "/profiles?offset=0&limit=2"},
		{"GET", "/profiles?limit=02&offset=0"},
		{"GET", "/profiles?limit=2&offset=0&all=1"},
		{"GET", "/profiles?limit=2&offset=0#x"},
		{"GET", "/agents?limit=2&offset=0"},
		{"DELETE", "/profiles?limit=2&offset=0"},
	} {
		line, _ := json.Marshal(DesktopRequest{Version: 1, Method: route[0], Path: route[1], Body: json.RawMessage("null")})

		var output bytes.Buffer

		if err := ServeDesktopIPC(bytes.NewReader(append(line, '\n')), &output, api.Handler()); err != nil {
			t.Fatalf("%q %q: %v", route[0], route[1], err)
		}

		reply := desktopReplies(t, output.Bytes(), 1)[0]

		var body struct {
			Error apiError `json:"error"`
		}

		if reply.Status != 403 || json.Unmarshal(reply.Body, &body) != nil || body.Error.Code != "IPC_OPERATION_DENIED" {
			t.Fatalf("%q %q was not denied: %d %s", route[0], route[1], reply.Status, reply.Body)
		}
	}

	if len(api.Store.Profiles()) != 1 {
		t.Fatal("a denied request changed the store")
	}
}

// A request the controller cannot trust ends the session with no reply; the parent sees EOF.
func TestDesktopIPCEndsOnMalformedRequest(t *testing.T) {
	api := desktopTestAPI(t)

	for name, line := range map[string]string{
		"not JSON":      `GET /profiles`,
		"unknown field": `{"version":1,"method":"GET","path":"/profiles","body":null,"admin":true}`,
		"trailing data": `{"version":1,"method":"GET","path":"/profiles","body":null} {}`,
		"wrong version": `{"version":2,"method":"GET","path":"/profiles","body":null}`,
		"oversized":     `{"version":1,"method":"POST","path":"/profiles","body":{"name":"` + strings.Repeat("x", maxDesktopRequest) + `"}}`,
	} {
		input := strings.NewReader(line + "\n" + `{"version":1,"method":"GET","path":"/profiles","body":null}` + "\n")

		var output bytes.Buffer

		if err := ServeDesktopIPC(input, &output, api.Handler()); err == nil || output.Len() != 0 {
			t.Fatalf("%s: accepted (%v), %d bytes of output", name, err, output.Len())
		}
	}

	if len(api.Store.Profiles()) != 0 {
		t.Fatal("a malformed request changed the store")
	}
}

func TestControllerWriterLock(t *testing.T) {
	root := t.TempDir()

	first, err := LockControllerStore(root)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()

	second, err := LockControllerStore(root)
	if err == nil {
		second.Close()
		t.Fatal("second writer was accepted")
	}

	if !errors.Is(err, ErrControllerRunning) {
		t.Fatalf("second writer refused with %v", err)
	}

	if err := first.Close(); err != nil {
		t.Fatal(err)
	}

	third, err := LockControllerStore(root)
	if err != nil {
		t.Fatal(err)
	}
	defer third.Close()
}

// A reply too large for one frame is answered with an error, and the session goes on.
func TestDesktopIPCOversizedReply(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/profiles" {
			respond(w, 200, map[string]any{"items": strings.Repeat("x", maxDesktopReply)})
			return
		}

		respond(w, 200, map[string]any{"status": "ready"})
	})

	input := strings.NewReader(`{"version":1,"method":"GET","path":"/profiles","body":null}` + "\n" +
		`{"version":1,"method":"GET","path":"/health","body":null}` + "\n")

	var output bytes.Buffer

	if err := ServeDesktopIPC(input, &output, handler); err != nil {
		t.Fatal(err)
	}

	replies := desktopReplies(t, output.Bytes(), 2)

	var body struct {
		Error apiError `json:"error"`
	}

	if replies[0].Status != 500 || json.Unmarshal(replies[0].Body, &body) != nil ||
		body.Error.Code != "IPC_REPLY_TOO_LARGE" || replies[1].Status != 200 {
		t.Fatalf("oversized reply: %d %s, then %d", replies[0].Status, replies[0].Body, replies[1].Status)
	}
}

// Lists come page by page, so that no reply outgrows the desktop frame.
func TestDesktopIPCListPages(t *testing.T) {
	api := desktopTestAPI(t)

	for i := range 5 {
		if _, err := api.Store.CreateProfile(fmt.Sprintf("Paged %d", i)); err != nil {
			t.Fatal(err)
		}
	}

	var input strings.Builder
	for _, path := range []string{
		"/profiles?limit=2&offset=0",
		"/profiles?limit=2&offset=4",
		"/profiles?limit=2&offset=9",
		"/profiles",
		"/discovery",
	} {
		fmt.Fprintf(&input, `{"version":1,"method":"GET","path":%q,"body":null}`+"\n", path)
	}

	var output bytes.Buffer

	if err := ServeDesktopIPC(strings.NewReader(input.String()), &output, api.Handler()); err != nil {
		t.Fatal(err)
	}

	replies := desktopReplies(t, output.Bytes(), 5)

	for i, want := range []struct {
		items int
		next  any
	}{{2, float64(2)}, {1, nil}, {0, nil}, {5, nil}} {
		var page struct {
			Items []RoutingProfile `json:"items"`
			Next  any              `json:"next_offset"`
		}

		if replies[i].Status != 200 || json.Unmarshal(replies[i].Body, &page) != nil ||
			len(page.Items) != want.items || page.Next != want.next {
			t.Fatalf("page %d: %d %s", i, replies[i].Status, replies[i].Body)
		}
	}

	var discovery struct {
		Agents  []AgentStatus      `json:"agents"`
		Tunnels []DiscoveredTunnel `json:"tunnels"`
	}

	if replies[4].Status != 200 || json.Unmarshal(replies[4].Body, &discovery) != nil ||
		discovery.Agents == nil || discovery.Tunnels == nil {
		t.Fatalf("discovery: %d %s", replies[4].Status, replies[4].Body)
	}
}

func TestListPageRefusals(t *testing.T) {
	api := desktopTestAPI(t)
	handler := api.Handler()

	for _, query := range []string{
		"limit=0&offset=0", "limit=501&offset=0", "limit=2&offset=-1", "limit=2", "offset=0",
		"limit=abc&offset=0", "limit=2&offset=0&extra=1", "limit=2&limit=3&offset=0",
		"%zz", "&", "limit=2&offset=0&%zz", "limit=2;offset=0",
	} {
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "http://127.0.0.1/api/v1/endpoints?"+query, nil))

		if recorder.Code != http.StatusBadRequest || !strings.Contains(recorder.Body.String(), "BAD_PAGE") {
			t.Fatalf("%s: %d %s", query, recorder.Code, recorder.Body.String())
		}
	}
}
