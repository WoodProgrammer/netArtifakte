// Package analyzer is a minimal client for the pcap-analyzer HTTP API.
//
// The operator only reads run state from it; pcaps are uploaded directly by the capture jobs.
package analyzer

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// Run is the subset of GET /runs/{id} the operator needs.
type Run struct {
	ID               int64  `json:"id"`
	Status           string `json:"status"`
	Stage            string `json:"stage"`
	Progress         int32  `json:"progress"`
	PendingApprovals int32  `json:"pending_approvals"`
	Error            string `json:"error"`
}

// Terminal run statuses in pcap-analyzer.
const (
	StatusDone      = "done"
	StatusFailed    = "failed"
	StatusCancelled = "cancelled"
)

// Credentials for HTTP Basic auth.
type Credentials struct {
	Username string
	Password string
}

// Client talks to pcap-analyzer.
type Client struct {
	BaseURL string
	HTTP    *http.Client
}

// New returns a client for baseURL (e.g. http://pcap-analyzer.pcap.svc:8000).
func New(baseURL string) *Client {
	return &Client{BaseURL: strings.TrimRight(baseURL, "/"), HTTP: &http.Client{Timeout: 15 * time.Second}}
}

// GetRun fetches a run's state.
func (c *Client) GetRun(ctx context.Context, creds Credentials, id int64) (*Run, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, fmt.Sprintf("%s/runs/%d", c.BaseURL, id), nil)
	if err != nil {
		return nil, err
	}
	req.SetBasicAuth(creds.Username, creds.Password)
	req.Header.Set("Accept", "application/json")
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return nil, fmt.Errorf("GET /runs/%d: %s: %s", id, resp.Status, strings.TrimSpace(string(body)))
	}
	var run Run
	if err := json.NewDecoder(resp.Body).Decode(&run); err != nil {
		return nil, fmt.Errorf("decode run %d: %w", id, err)
	}
	return &run, nil
}

// RunURL is the UI link of a run.
func RunURL(publicBaseURL string, id int64) string {
	return fmt.Sprintf("%s/#/r/%d", strings.TrimRight(publicBaseURL, "/"), id)
}
