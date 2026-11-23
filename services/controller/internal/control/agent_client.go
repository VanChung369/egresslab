package control

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"time"
)

const (
	defaultAgentURL = "http://127.0.0.1:8788"
	agentTimeout    = 2 * time.Second
	agentTokenBytes = 32
	maxHealthBytes  = 4096
)

type AgentStatus struct {
	ID           string `json:"id"`
	Status       string `json:"status"`
	Mode         string `json:"mode,omitempty"`
	NetworkReady bool   `json:"network_ready"`
}

type agentHealth struct {
	Status       string `json:"status"`
	Mode         string `json:"mode"`
	NetworkReady bool   `json:"network_ready"`
}

type AgentClient struct {
	baseURL string
	token   string
	client  *http.Client
}

func NewAgentClient(token string) (*AgentClient, error) {
	return newAgentClient(defaultAgentURL, token)
}

func newAgentClient(baseURL, token string) (*AgentClient, error) {
	decoded, err := hex.DecodeString(token)
	if err != nil || len(decoded) != agentTokenBytes {
		return nil, errors.New("invalid EGRESSLAB_AGENT_TOKEN: expected 64 hex characters")
	}

	parsed, err := url.Parse(baseURL)
	if err != nil || !isLocalAgentURL(parsed) {
		return nil, errors.New("agent endpoint must be a local loopback HTTP address")
	}

	client := &http.Client{
		Timeout:   agentTimeout,
		Transport: &http.Transport{Proxy: nil},
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	return &AgentClient{
		baseURL: baseURL,
		token:   token,
		client:  client,
	}, nil
}

func isLocalAgentURL(u *url.URL) bool {
	return u.Scheme == "http" &&
		u.Hostname() == "127.0.0.1" &&
		u.Port() != "" &&
		u.User == nil &&
		u.Path == "" &&
		u.RawQuery == "" &&
		u.Fragment == ""
}

func (c *AgentClient) Snapshot(ctx context.Context) AgentStatus {
	result := AgentStatus{ID: "local-agent", Status: "unreachable"}

	request, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+"/health", nil)
	if err != nil {
		result.Status = "error"
		return result
	}

	request.Header.Set("Authorization", "Bearer "+c.token)
	request.Header.Set("Accept", "application/json")

	response, err := c.client.Do(request)
	if err != nil {
		return result
	}
	defer response.Body.Close()

	switch response.StatusCode {
	case http.StatusOK:

	case http.StatusUnauthorized:
		result.Status = "unauthorized"
		return result

	default:
		result.Status = "error"
		return result
	}

	body, err := io.ReadAll(io.LimitReader(response.Body, maxHealthBytes+1))
	if err != nil || len(body) > maxHealthBytes {
		result.Status = "invalid_response"
		return result
	}

	var health agentHealth
	if err := json.Unmarshal(body, &health); err != nil || !health.supported() {
		result.Status = "invalid_response"
		return result
	}

	result.Status = "online"
	result.Mode = health.Mode

	return result
}

func (h agentHealth) supported() bool {
	return h.Status == "running" && h.Mode == "read-only" && !h.NetworkReady
}
