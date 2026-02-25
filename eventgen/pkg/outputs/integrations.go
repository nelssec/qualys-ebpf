package outputs

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
)

// SecurityEvent represents a normalized security event for output.
type SecurityEvent struct {
	EventID       string                 `json:"eventId"`
	Timestamp     time.Time              `json:"timestamp"`
	Category      string                 `json:"category"`
	Severity      string                 `json:"severity"`
	Title         string                 `json:"title"`
	Description   string                 `json:"description"`
	ContainerID   string                 `json:"containerId,omitempty"`
	ContainerName string                 `json:"containerName,omitempty"`
	PodName       string                 `json:"podName,omitempty"`
	Namespace     string                 `json:"namespace,omitempty"`
	ImageName     string                 `json:"imageName,omitempty"`
	ProcessName   string                 `json:"processName,omitempty"`
	ProcessPath   string                 `json:"processPath,omitempty"`
	DestinationIP string                 `json:"destinationIp,omitempty"`
	MITRETechnique string                `json:"mitreTechnique,omitempty"`
	MITRETactic   string                 `json:"mitreTactic,omitempty"`
	ActionTaken   string                 `json:"actionTaken,omitempty"`
	Raw           map[string]interface{} `json:"raw,omitempty"`
}

// OutputIntegration represents an output destination.
type OutputIntegration interface {
	Name() string
	Send(ctx context.Context, event *SecurityEvent) error
}

// OutputManager manages multiple output integrations.
type OutputManager struct {
	outputs []OutputIntegration
}

// NewOutputManager creates a new output manager.
func NewOutputManager() *OutputManager {
	return &OutputManager{
		outputs: []OutputIntegration{},
	}
}

// AddOutput adds an output integration.
func (m *OutputManager) AddOutput(output OutputIntegration) {
	m.outputs = append(m.outputs, output)
}

// Send sends an event to all outputs.
func (m *OutputManager) Send(ctx context.Context, event *SecurityEvent) {
	for _, out := range m.outputs {
		go func(o OutputIntegration) {
			if err := o.Send(ctx, event); err != nil {
				fmt.Printf("[Output] %s error: %v\n", o.Name(), err)
			}
		}(out)
	}
}

// SlackOutput sends events to Slack.
type SlackOutput struct {
	WebhookURL string
	Channel    string
}

func NewSlackOutput(webhookURL, channel string) *SlackOutput {
	return &SlackOutput{WebhookURL: webhookURL, Channel: channel}
}

func (s *SlackOutput) Name() string { return "slack" }

func (s *SlackOutput) Send(ctx context.Context, event *SecurityEvent) error {
	color := "#36a64f" // green
	switch event.Severity {
	case "critical":
		color = "#ff0000"
	case "high":
		color = "#ff6600"
	case "medium":
		color = "#ffcc00"
	}

	payload := map[string]interface{}{
		"channel": s.Channel,
		"attachments": []map[string]interface{}{
			{
				"color":  color,
				"title":  fmt.Sprintf("[%s] %s", strings.ToUpper(event.Severity), event.Title),
				"text":   event.Description,
				"fields": []map[string]interface{}{
					{"title": "Category", "value": event.Category, "short": true},
					{"title": "Container", "value": event.ContainerName, "short": true},
					{"title": "Pod/Namespace", "value": fmt.Sprintf("%s/%s", event.Namespace, event.PodName), "short": true},
					{"title": "MITRE", "value": event.MITRETechnique, "short": true},
					{"title": "Process", "value": event.ProcessName, "short": true},
					{"title": "Action", "value": event.ActionTaken, "short": true},
				},
				"footer":    "Qualys CDR",
				"ts":        event.Timestamp.Unix(),
			},
		},
	}

	return sendJSON(ctx, s.WebhookURL, payload)
}

// PagerDutyOutput sends events to PagerDuty.
type PagerDutyOutput struct {
	RoutingKey string
	ServiceKey string
}

func NewPagerDutyOutput(routingKey string) *PagerDutyOutput {
	return &PagerDutyOutput{RoutingKey: routingKey}
}

func (p *PagerDutyOutput) Name() string { return "pagerduty" }

func (p *PagerDutyOutput) Send(ctx context.Context, event *SecurityEvent) error {
	// Only send critical/high severity to PagerDuty
	if event.Severity != "critical" && event.Severity != "high" {
		return nil
	}

	severity := "warning"
	if event.Severity == "critical" {
		severity = "critical"
	}

	payload := map[string]interface{}{
		"routing_key":  p.RoutingKey,
		"event_action": "trigger",
		"dedup_key":    event.EventID,
		"payload": map[string]interface{}{
			"summary":   fmt.Sprintf("[%s] %s - %s", event.Severity, event.Category, event.Title),
			"source":    fmt.Sprintf("%s/%s", event.Namespace, event.PodName),
			"severity":  severity,
			"timestamp": event.Timestamp.Format(time.RFC3339),
			"custom_details": map[string]interface{}{
				"container":       event.ContainerName,
				"image":           event.ImageName,
				"process":         event.ProcessName,
				"mitre_technique": event.MITRETechnique,
				"action_taken":    event.ActionTaken,
			},
		},
	}

	return sendJSON(ctx, "https://events.pagerduty.com/v2/enqueue", payload)
}

// TeamsOutput sends events to Microsoft Teams.
type TeamsOutput struct {
	WebhookURL string
}

func NewTeamsOutput(webhookURL string) *TeamsOutput {
	return &TeamsOutput{WebhookURL: webhookURL}
}

func (t *TeamsOutput) Name() string { return "teams" }

func (t *TeamsOutput) Send(ctx context.Context, event *SecurityEvent) error {
	color := "00FF00" // green
	switch event.Severity {
	case "critical":
		color = "FF0000"
	case "high":
		color = "FF6600"
	case "medium":
		color = "FFCC00"
	}

	payload := map[string]interface{}{
		"@type":      "MessageCard",
		"@context":   "http://schema.org/extensions",
		"themeColor": color,
		"summary":    event.Title,
		"sections": []map[string]interface{}{
			{
				"activityTitle": fmt.Sprintf("[%s] %s", strings.ToUpper(event.Severity), event.Title),
				"facts": []map[string]string{
					{"name": "Category", "value": event.Category},
					{"name": "Container", "value": event.ContainerName},
					{"name": "Namespace", "value": event.Namespace},
					{"name": "MITRE Technique", "value": event.MITRETechnique},
					{"name": "Process", "value": event.ProcessName},
					{"name": "Action Taken", "value": event.ActionTaken},
				},
				"markdown": true,
			},
		},
	}

	return sendJSON(ctx, t.WebhookURL, payload)
}

// SplunkHECOutput sends events to Splunk HTTP Event Collector.
type SplunkHECOutput struct {
	URL   string
	Token string
	Index string
}

func NewSplunkHECOutput(url, token, index string) *SplunkHECOutput {
	return &SplunkHECOutput{URL: url, Token: token, Index: index}
}

func (s *SplunkHECOutput) Name() string { return "splunk" }

func (s *SplunkHECOutput) Send(ctx context.Context, event *SecurityEvent) error {
	payload := map[string]interface{}{
		"time":       event.Timestamp.Unix(),
		"host":       event.ContainerName,
		"source":     "qualys-cdr",
		"sourcetype": "qualys:cdr:event",
		"index":      s.Index,
		"event":      event,
	}

	req, err := http.NewRequestWithContext(ctx, "POST", s.URL, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Splunk "+s.Token)
	req.Header.Set("Content-Type", "application/json")

	data, _ := json.Marshal(payload)
	req.Body = io.NopCloser(bytes.NewReader(data))

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		return fmt.Errorf("splunk returned status %d", resp.StatusCode)
	}

	return nil
}

// ElasticsearchOutput sends events to Elasticsearch.
type ElasticsearchOutput struct {
	URL      string
	Index    string
	Username string
	Password string
}

func NewElasticsearchOutput(url, index, username, password string) *ElasticsearchOutput {
	return &ElasticsearchOutput{URL: url, Index: index, Username: username, Password: password}
}

func (e *ElasticsearchOutput) Name() string { return "elasticsearch" }

func (e *ElasticsearchOutput) Send(ctx context.Context, event *SecurityEvent) error {
	url := fmt.Sprintf("%s/%s/_doc", strings.TrimSuffix(e.URL, "/"), e.Index)

	payload := map[string]interface{}{
		"@timestamp": event.Timestamp.Format(time.RFC3339),
		"event":      event,
	}

	data, _ := json.Marshal(payload)
	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(data))
	if err != nil {
		return err
	}

	req.Header.Set("Content-Type", "application/json")
	if e.Username != "" {
		req.SetBasicAuth(e.Username, e.Password)
	}

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		return fmt.Errorf("elasticsearch returned status %d", resp.StatusCode)
	}

	return nil
}

// WebhookOutput sends events to a generic webhook.
type WebhookOutput struct {
	URL     string
	Headers map[string]string
}

func NewWebhookOutput(url string, headers map[string]string) *WebhookOutput {
	return &WebhookOutput{URL: url, Headers: headers}
}

func (w *WebhookOutput) Name() string { return "webhook" }

func (w *WebhookOutput) Send(ctx context.Context, event *SecurityEvent) error {
	data, _ := json.Marshal(event)
	req, err := http.NewRequestWithContext(ctx, "POST", w.URL, bytes.NewReader(data))
	if err != nil {
		return err
	}

	req.Header.Set("Content-Type", "application/json")
	for k, v := range w.Headers {
		req.Header.Set(k, v)
	}

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		return fmt.Errorf("webhook returned status %d", resp.StatusCode)
	}

	return nil
}

// SyslogOutput sends events via syslog.
type SyslogOutput struct {
	Address  string
	Protocol string // "tcp" or "udp"
	Facility int
}

func NewSyslogOutput(address, protocol string) *SyslogOutput {
	return &SyslogOutput{
		Address:  address,
		Protocol: protocol,
		Facility: 1, // user-level
	}
}

func (s *SyslogOutput) Name() string { return "syslog" }

func (s *SyslogOutput) Send(ctx context.Context, event *SecurityEvent) error {
	// Format as CEF (Common Event Format)
	severity := 5
	switch event.Severity {
	case "critical":
		severity = 10
	case "high":
		severity = 7
	case "medium":
		severity = 5
	case "low":
		severity = 3
	}

	cef := fmt.Sprintf("CEF:0|Qualys|CDR|1.0|%s|%s|%d|src=%s dst=%s cs1=%s cs1Label=Container cs2=%s cs2Label=Process",
		event.Category,
		event.Title,
		severity,
		event.ContainerName,
		event.DestinationIP,
		event.ContainerName,
		event.ProcessName,
	)

	// Simple UDP syslog send
	if s.Protocol == "udp" {
		conn, err := net.DialTimeout("udp", s.Address, 5*time.Second)
		if err != nil {
			return err
		}
		defer conn.Close()

		priority := s.Facility*8 + severity
		msg := fmt.Sprintf("<%d>%s %s", priority, time.Now().Format(time.RFC3339), cef)
		_, err = conn.Write([]byte(msg))
		return err
	}

	return fmt.Errorf("unsupported protocol: %s", s.Protocol)
}

func sendJSON(ctx context.Context, url string, payload interface{}) error {
	data, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(data))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(body))
	}

	return nil
}
