package control

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

const (
	desktopIPCVersion = 1
	maxDesktopRequest = 32 * 1024
	maxDesktopReply   = 1024 * 1024
)

var ErrControllerRunning = errors.New("another EgressLab controller is using this data directory")

// ExitControllerRunning is the controller's exit status when ErrControllerRunning stops it.
const ExitControllerRunning = 3

// desktopPageQuery is the only query desktop IPC passes on: a page of a list.
var desktopPageQuery = regexp.MustCompile(`^limit=[1-9][0-9]{0,2}&offset=(0|[1-9][0-9]{0,6})$`)

type DesktopRequest struct {
	Version int             `json:"version"`
	Method  string          `json:"method"`
	Path    string          `json:"path"`
	Body    json.RawMessage `json:"body"`
}

type DesktopResponse struct {
	Version int             `json:"version"`
	Status  int             `json:"status"`
	Body    json.RawMessage `json:"body"`
}

// LockControllerStore admits one writer of root's Store, HTTP or desktop. The lock is released
// when the file is closed or the process exits; the file itself stays.
func LockControllerStore(root string) (*os.File, error) {
	if err := os.MkdirAll(root, 0o700); err != nil {
		return nil, err
	}

	path := filepath.Join(root, "controller-writer.lock")

	file, err := openLockedReservationFile(path, false, false)
	if errors.Is(err, os.ErrNotExist) {
		file, err = openLockedReservationFile(path, true, false)

		if errors.Is(err, os.ErrExist) {
			file, err = openLockedReservationFile(path, false, false)
		}
	}

	if errors.Is(err, ErrReservationBusy) {
		return nil, ErrControllerRunning
	}

	return file, err
}

func desktopRouteAllowed(method, path string) bool {
	switch method {
	case http.MethodGet:
		if list, query, ok := strings.Cut(path, "?"); ok {
			return (list == "/profiles" || list == "/endpoints") && desktopPageQuery.MatchString(query)
		}

		switch path {
		case "/health", "/overview", "/profiles", "/endpoints", "/agents", "/tunnels", "/discovery":
			return true
		}

	case http.MethodPost:
		return path == "/profiles" || path == "/endpoints"

	case http.MethodDelete:
		if id, ok := strings.CutPrefix(path, "/profiles/"); ok {
			return profileIDPattern.MatchString(id)
		}

		if id, ok := strings.CutPrefix(path, "/endpoints/"); ok {
			return endpointIDPattern.MatchString(id)
		}
	}

	return false
}

func desktopDispatch(handler http.Handler, request DesktopRequest) (DesktopResponse, error) {
	recorder := httptest.NewRecorder()

	// The allowlist comes first: httptest.NewRequest panics on a malformed method or target.
	if !desktopRouteAllowed(request.Method, request.Path) {
		fail(recorder, http.StatusForbidden, "IPC_OPERATION_DENIED", "Operation is not available through desktop IPC")
	} else {
		req := httptest.NewRequest(request.Method, "http://127.0.0.1/api/v1"+request.Path,
			bytes.NewReader(request.Body))

		if request.Method == http.MethodPost {
			req.Header.Set("Content-Type", "application/json")
		}

		handler.ServeHTTP(recorder, req)
	}

	body := recorder.Body.Bytes()
	if len(bytes.TrimSpace(body)) == 0 {
		body = []byte("null")
	}

	// Too large for one frame: the session goes on, and the desktop sees why.
	if len(body) > maxDesktopReply {
		tooLarge := httptest.NewRecorder()
		fail(tooLarge, http.StatusInternalServerError, "IPC_REPLY_TOO_LARGE",
			"The reply is larger than the desktop IPC allows")

		return DesktopResponse{Version: desktopIPCVersion, Status: tooLarge.Code,
			Body: json.RawMessage(tooLarge.Body.Bytes())}, nil
	}

	if !json.Valid(body) {
		return DesktopResponse{}, errors.New("invalid desktop response")
	}

	return DesktopResponse{Version: desktopIPCVersion, Status: recorder.Code, Body: json.RawMessage(body)}, nil
}

// ServeDesktopIPC answers one request per line, one at a time, with one line each. EOF means the
// desktop parent closed its pipe. A malformed request ends the session without a reply.
func ServeDesktopIPC(input io.Reader, output io.Writer, handler http.Handler) error {
	scanner := bufio.NewScanner(input)
	scanner.Buffer(make([]byte, 4096), maxDesktopRequest)

	encoder := json.NewEncoder(output)

	for scanner.Scan() {
		var request DesktopRequest

		decoder := json.NewDecoder(bytes.NewReader(scanner.Bytes()))
		decoder.DisallowUnknownFields()

		if err := decoder.Decode(&request); err != nil {
			return errors.New("malformed desktop request")
		}

		var extra json.RawMessage
		if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
			return errors.New("trailing desktop request data")
		}

		if request.Version != desktopIPCVersion {
			return errors.New("unsupported desktop IPC version")
		}

		response, err := desktopDispatch(handler, request)
		if err != nil {
			return err
		}

		if err := encoder.Encode(response); err != nil {
			return err
		}
	}

	return scanner.Err()
}
