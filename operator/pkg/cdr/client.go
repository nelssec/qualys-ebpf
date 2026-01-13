package cdr

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"
)

// Platform gateway URLs
var platformGateways = map[string]string{
	"US1": "gateway.qg1.apps.qualys.com",
	"US2": "gateway.qg2.apps.qualys.com",
	"US3": "gateway.qg3.apps.qualys.com",
	"US4": "gateway.qg4.apps.qualys.com",
	"EU1": "gateway.qg1.apps.qualys.eu",
	"EU2": "gateway.qg2.apps.qualys.eu",
	"CA1": "gateway.qg1.apps.qualys.ca",
	"IN1": "gateway.qg1.apps.qualys.in",
	"AE1": "gateway.qg1.apps.qualys.ae",
	"UK1": "gateway.qg1.apps.qualys.co.uk",
	"AU1": "gateway.qg1.apps.qualys.com.au",
	"KSA1": "gateway.qg1.apps.qualysksa.com",
}

// GetGatewayURL returns the gateway URL for a platform ID.
func GetGatewayURL(platform string) string {
	if url, ok := platformGateways[platform]; ok {
		return url
	}
	return ""
}

// Event represents a CDR detection event.
type Event struct {
	UUID           string                 `json:"uuid"`
	ThreatCategory string                 `json:"threatCategory"`
	Severity       int                    `json:"severity"`
	Timestamp      string                 `json:"timestamp"`
	ResourceType   string                 `json:"resourceType"`
	ResourceID     string                 `json:"resourceId"`
	EventMessage   string                 `json:"eventMessage"`
	ContainerName  string                 `json:"containerName"`
	PodName        string                 `json:"pod"`
	ProcessName    string                 `json:"processName"`
	ImageName      string                 `json:"imageName"`
	MitreInfo      map[string]interface{} `json:"mitreRulesInfo"`
	Raw            map[string]interface{} `json:"-"`
}

// Client is a Qualys CDR API client.
type Client struct {
	username   string
	password   string
	gatewayURL string
	httpClient *http.Client
	token      string
}

// NewClient creates a new CDR client.
func NewClient(username, password, gatewayURL string) *Client {
	return &Client{
		username:   username,
		password:   password,
		gatewayURL: gatewayURL,
		httpClient: &http.Client{Timeout: 30 * time.Second},
	}
}

// authenticate gets a JWT token from the gateway.
func (c *Client) authenticate(ctx context.Context) error {
	authURL := fmt.Sprintf("https://%s/auth", c.gatewayURL)

	data := url.Values{}
	data.Set("username", c.username)
	data.Set("password", c.password)
	data.Set("token", "true")

	req, err := http.NewRequestWithContext(ctx, "POST", authURL, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Body = io.NopCloser(stringReader(data.Encode()))

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("auth request failed: %w", err)
	}
	defer resp.Body.Close()

	// Accept both 200 OK and 201 Created as success
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("auth failed: %s - %s", resp.Status, string(body))
	}

	tokenBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read token: %w", err)
	}

	c.token = string(tokenBytes)
	return nil
}

// GetDetections fetches CDR events for the given lookback period.
func (c *Client) GetDetections(ctx context.Context, hours int) ([]Event, error) {
	if c.token == "" {
		if err := c.authenticate(ctx); err != nil {
			return nil, err
		}
	}

	endTime := time.Now().UTC()
	startTime := endTime.Add(-time.Duration(hours) * time.Hour)

	apiURL := fmt.Sprintf("https://%s/cdr-api/rest/v1/findings", c.gatewayURL)

	req, err := http.NewRequestWithContext(ctx, "GET", apiURL, nil)
	if err != nil {
		return nil, err
	}

	q := req.URL.Query()
	q.Set("startAt", startTime.Format("2006-01-02T15:04:05.000Z"))
	q.Set("endAt", endTime.Format("2006-01-02T15:04:05.999Z"))
	q.Set("limit", "100")
	req.URL.RawQuery = q.Encode()

	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Accept", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("API request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("API error: %s - %s", resp.Status, string(body))
	}

	var result struct {
		Content []json.RawMessage `json:"content"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	events := make([]Event, 0, len(result.Content))
	for _, raw := range result.Content {
		var event Event
		if err := json.Unmarshal(raw, &event); err != nil {
			continue
		}
		// Store raw data for policy generation
		json.Unmarshal(raw, &event.Raw)
		events = append(events, event)
	}

	return events, nil
}

type stringReader string

func (s stringReader) Read(p []byte) (n int, err error) {
	n = copy(p, s)
	return n, io.EOF
}
