package qualys

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

type Config struct {
	GatewayURL string
	Username   string
	Password   string
	CDRBase    string
	CSBase     string
}

func ConfigFromEnv() *Config {
	return &Config{
		GatewayURL: getEnv("QUALYS_GATEWAY_URL", "gateway.qg1.apps.qualys.ca"),
		Username:   os.Getenv("QUALYS_USERNAME"),
		Password:   os.Getenv("QUALYS_PASSWORD"),
		CDRBase:    "/cdr-api/rest/v1",
		CSBase:     "/csapi/v1.3",
	}
}

func getEnv(key, defaultVal string) string {
	if val := os.Getenv(key); val != "" {
		return val
	}
	return defaultVal
}

func (c *Config) AuthURL() string {
	return fmt.Sprintf("https://%s/auth", c.GatewayURL)
}

func (c *Config) CDRURL() string {
	return fmt.Sprintf("https://%s%s", c.GatewayURL, c.CDRBase)
}

func (c *Config) CSURL() string {
	return fmt.Sprintf("https://%s%s", c.GatewayURL, c.CSBase)
}

type Client struct {
	config     *Config
	httpClient *http.Client
	token      string
}

func NewClient(config *Config) *Client {
	return &Client{
		config: config,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

func (c *Client) getAuthToken() (string, error) {
	if c.token != "" {
		return c.token, nil
	}

	data := url.Values{}
	data.Set("username", c.config.Username)
	data.Set("password", c.config.Password)
	data.Set("token", "true")

	req, err := http.NewRequest("POST", c.config.AuthURL(), strings.NewReader(data.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("auth failed: %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	c.token = string(body)
	return c.token, nil
}

func (c *Client) apiRequest(method, url string, params map[string]string) ([]byte, error) {
	token, err := c.getAuthToken()
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest(method, url, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/json")

	if params != nil {
		q := req.URL.Query()
		for k, v := range params {
			q.Add(k, v)
		}
		req.URL.RawQuery = q.Encode()
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("API request failed: %d", resp.StatusCode)
	}

	return io.ReadAll(resp.Body)
}

type CDREvent struct {
	EventID         string            `json:"uuid"`
	EventType       string            `json:"threatCategory"`
	Severity        int               `json:"severity"`
	Timestamp       string            `json:"timestamp"`
	ResourceType    string            `json:"resourceType"`
	ResourceID      string            `json:"resourceId"`
	Description     string            `json:"eventMessage"`
	MITRETechniques []string          `json:"mitreTechniques"`
	ContainerID     string            `json:"containerName"`
	ContainerName   string            `json:"containerName"`
	PodName         string            `json:"pod"`
	ClusterName     string            `json:"deploymentName"`
	ProcessName     string            `json:"processName"`
	ProcessPath     string            `json:"processPath"`
	RawData         map[string]interface{} `json:"-"`
}

type CDRResponse struct {
	Content []json.RawMessage `json:"content"`
}

func (c *Client) GetCDRDetections(hours int, severity string, resourceType string, limit int) ([]CDREvent, error) {
	endTime := time.Now().UTC()
	startTime := endTime.Add(-time.Duration(hours) * time.Hour)

	params := map[string]string{
		"startAt": startTime.Format("2006-01-02T15:04:05.000Z"),
		"endAt":   endTime.Format("2006-01-02T15:04:05.999Z"),
		"limit":   fmt.Sprintf("%d", limit),
	}

	if resourceType != "" {
		params["resourceType"] = resourceType
	}
	if severity != "" {
		severityMap := map[string]string{"LOW": "1", "MEDIUM": "2", "HIGH": "3", "CRITICAL": "4"}
		if v, ok := severityMap[strings.ToUpper(severity)]; ok {
			params["severity"] = v
		}
	}

	url := fmt.Sprintf("%s/findings", c.config.CDRURL())
	data, err := c.apiRequest("GET", url, params)
	if err != nil {
		return nil, err
	}

	var resp CDRResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, err
	}

	var events []CDREvent
	for _, raw := range resp.Content {
		var event CDREvent
		if err := json.Unmarshal(raw, &event); err != nil {
			continue
		}
		var rawData map[string]interface{}
		json.Unmarshal(raw, &rawData)
		event.RawData = rawData

		if mitre, ok := rawData["mitreRulesInfo"].(map[string]interface{}); ok {
			for k := range mitre {
				event.MITRETechniques = append(event.MITRETechniques, k)
			}
		}

		events = append(events, event)
	}

	return events, nil
}

type ContainerImage struct {
	ImageID      string   `json:"imageId"`
	Repo         string   `json:"repo"`
	Tag          string   `json:"tag"`
	ContainerIDs []string `json:"containerIds"`
}

type ImagesResponse struct {
	Data []ContainerImage `json:"data"`
}

func (c *Client) GetImages(limit int, runningOnly bool) ([]ContainerImage, error) {
	params := map[string]string{
		"pageSize": fmt.Sprintf("%d", limit),
	}
	if runningOnly {
		params["filter"] = "containers.state:RUNNING"
	}

	url := fmt.Sprintf("%s/images", c.config.CSURL())
	data, err := c.apiRequest("GET", url, params)
	if err != nil {
		return nil, err
	}

	var resp ImagesResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, err
	}

	return resp.Data, nil
}

type Container struct {
	ContainerID string `json:"containerId"`
	Name        string `json:"name"`
	ImageID     string `json:"imageId"`
	State       string `json:"state"`
}

type ContainersResponse struct {
	Data []Container `json:"data"`
}

func (c *Client) GetRunningContainers(limit int) ([]Container, error) {
	params := map[string]string{
		"pageSize": fmt.Sprintf("%d", limit),
		"filter":   "state:RUNNING",
	}

	url := fmt.Sprintf("%s/containers", c.config.CSURL())
	data, err := c.apiRequest("GET", url, params)
	if err != nil {
		return nil, err
	}

	var resp ContainersResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, err
	}

	return resp.Data, nil
}

func SeverityToString(severity int) string {
	switch severity {
	case 1:
		return "LOW"
	case 2:
		return "MEDIUM"
	case 3:
		return "HIGH"
	case 4, 5:
		return "CRITICAL"
	default:
		return "MEDIUM"
	}
}
