package webhook

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/qualys/eventgen/pkg/reputation"
	"sigs.k8s.io/yaml"
)

// WebhookEvent represents an incoming CDR webhook event.
type WebhookEvent struct {
	EventType     string                 `json:"eventType"`
	EventID       string                 `json:"eventId"`
	Timestamp     string                 `json:"timestamp"`
	Severity      int                    `json:"severity"`
	Category      string                 `json:"category"`
	ThreatCategory string                `json:"threatCategory"`
	ResourceType  string                 `json:"resourceType"`
	ResourceID    string                 `json:"resourceId"`
	ContainerName string                 `json:"containerName"`
	PodName       string                 `json:"pod"`
	ProcessName   string                 `json:"processName"`
	DestinationIP string                 `json:"destinationIp"`
	DestinationPort int                  `json:"destinationPort"`
	SourceIP      string                 `json:"sourceIp"`
	Raw           map[string]interface{} `json:"raw,omitempty"`
}

// ManualBlockRequest for API-driven blocking.
type ManualBlockRequest struct {
	Type     string   `json:"type"`     // "ip", "cidr", "domain", "port"
	Values   []string `json:"values"`
	Reason   string   `json:"reason"`
	Duration string   `json:"duration"` // e.g., "24h", "permanent"
	Action   string   `json:"action"`   // "Post" or "Sigkill"
}

// Server handles webhook requests for real-time blocking.
type Server struct {
	addr           string
	webhookSecret  string
	action         string
	outputDir      string
	applyToCluster bool
	repChecker     *reputation.ReputationChecker

	// Track blocked indicators
	blockedIPs   map[string]time.Time
	blockedPorts map[string]time.Time
	mu           sync.RWMutex

	// Metrics
	eventsReceived  int64
	policiesCreated int64
	blocksApplied   int64
}

// NewServer creates a new webhook server.
func NewServer(addr, webhookSecret, action, outputDir string, applyToCluster bool, repChecker *reputation.ReputationChecker) *Server {
	return &Server{
		addr:           addr,
		webhookSecret:  webhookSecret,
		action:         action,
		outputDir:      outputDir,
		applyToCluster: applyToCluster,
		repChecker:     repChecker,
		blockedIPs:     make(map[string]time.Time),
		blockedPorts:   make(map[string]time.Time),
	}
}

// Start starts the webhook server.
func (s *Server) Start(ctx context.Context) error {
	mux := http.NewServeMux()

	// Qualys CDR webhook endpoint
	mux.HandleFunc("/webhook/cdr", s.handleCDRWebhook)

	// Manual blocking API
	mux.HandleFunc("/api/block", s.handleManualBlock)
	mux.HandleFunc("/api/unblock", s.handleUnblock)

	// Status and health
	mux.HandleFunc("/health", s.handleHealth)
	mux.HandleFunc("/metrics", s.handleMetrics)
	mux.HandleFunc("/status", s.handleStatus)

	server := &http.Server{
		Addr:         s.addr,
		Handler:      mux,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 30 * time.Second,
	}

	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		server.Shutdown(shutdownCtx)
	}()

	fmt.Printf("Webhook server starting on %s\n", s.addr)
	fmt.Printf("Endpoints:\n")
	fmt.Printf("  POST /webhook/cdr    - Qualys CDR webhook\n")
	fmt.Printf("  POST /api/block      - Manual blocking API\n")
	fmt.Printf("  POST /api/unblock    - Remove blocks\n")
	fmt.Printf("  GET  /health         - Health check\n")
	fmt.Printf("  GET  /metrics        - Prometheus metrics\n")
	fmt.Printf("  GET  /status         - Current block status\n")

	return server.ListenAndServe()
}

func (s *Server) handleCDRWebhook(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Verify webhook signature if secret is configured
	if s.webhookSecret != "" {
		signature := r.Header.Get("X-Qualys-Signature")
		if !s.verifySignature(r, signature) {
			http.Error(w, "Invalid signature", http.StatusUnauthorized)
			return
		}
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Failed to read body", http.StatusBadRequest)
		return
	}

	var event WebhookEvent
	if err := json.Unmarshal(body, &event); err != nil {
		// Try array format
		var events []WebhookEvent
		if err := json.Unmarshal(body, &events); err != nil {
			http.Error(w, "Invalid JSON", http.StatusBadRequest)
			return
		}
		for _, e := range events {
			s.processEvent(e)
		}
	} else {
		s.processEvent(event)
	}

	s.mu.Lock()
	s.eventsReceived++
	s.mu.Unlock()

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"status": "processed"})
}

func (s *Server) processEvent(event WebhookEvent) {
	fmt.Printf("[%s] Processing event: %s - %s\n",
		time.Now().Format(time.RFC3339),
		event.Category,
		event.EventID)

	// Extract IOCs from event
	var ipsToBlock []string
	var portsToBlock []string

	if event.DestinationIP != "" && !isPrivateIP(event.DestinationIP) {
		// Check reputation if available
		if s.repChecker != nil {
			score, _ := s.repChecker.CheckIP(context.Background(), event.DestinationIP)
			if score != nil && score.Score >= 50 {
				fmt.Printf("  IP %s has bad reputation (score: %d)\n", event.DestinationIP, score.Score)
			}
		}
		ipsToBlock = append(ipsToBlock, event.DestinationIP)
	}

	if event.DestinationPort > 0 && isSuspiciousPort(event.DestinationPort) {
		portsToBlock = append(portsToBlock, fmt.Sprintf("%d", event.DestinationPort))
	}

	// Generate and apply policy if we have IOCs
	if len(ipsToBlock) > 0 || len(portsToBlock) > 0 {
		s.createBlockPolicy(ipsToBlock, portsToBlock, event.Category)
	}
}

func (s *Server) createBlockPolicy(ips, ports []string, category string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Track what we're blocking
	now := time.Now()
	for _, ip := range ips {
		s.blockedIPs[ip] = now
	}
	for _, port := range ports {
		s.blockedPorts[port] = now
	}

	// Generate policy
	policyName := fmt.Sprintf("realtime-block-%d", time.Now().Unix())

	selectors := []map[string]interface{}{}

	if len(ips) > 0 {
		selectors = append(selectors, map[string]interface{}{
			"matchArgs": []map[string]interface{}{
				{
					"index":    1,
					"operator": "SAddr",
					"values":   ips,
				},
			},
			"matchActions": []map[string]interface{}{
				{"action": s.action},
			},
		})
	}

	if len(ports) > 0 {
		selectors = append(selectors, map[string]interface{}{
			"matchArgs": []map[string]interface{}{
				{
					"index":    1,
					"operator": "DPort",
					"values":   ports,
				},
			},
			"matchActions": []map[string]interface{}{
				{"action": s.action},
			},
		})
	}

	policy := map[string]interface{}{
		"apiVersion": "cilium.io/v1alpha1",
		"kind":       "TracingPolicy",
		"metadata": map[string]interface{}{
			"name": policyName,
			"labels": map[string]string{
				"generated-by":           "qualys-webhook",
				"qualys.com/realtime":    "true",
				"qualys.com/category":    sanitizeLabel(category),
			},
			"annotations": map[string]string{
				"blocked-ips":   strings.Join(ips, ","),
				"blocked-ports": strings.Join(ports, ","),
				"created-at":    time.Now().UTC().Format(time.RFC3339),
			},
		},
		"spec": map[string]interface{}{
			"kprobes": []map[string]interface{}{
				{
					"call":      "sys_connect",
					"syscall":   true,
					"args":      []map[string]interface{}{{"index": 1, "type": "sockaddr"}},
					"selectors": selectors,
				},
			},
		},
	}

	// Write policy
	if s.outputDir != "" {
		data, _ := yaml.Marshal(policy)
		filename := fmt.Sprintf("%s/%s.yaml", s.outputDir, policyName)
		os.WriteFile(filename, data, 0644)
		fmt.Printf("  Created: %s\n", filename)
		s.policiesCreated++
	}

	// Apply to cluster
	if s.applyToCluster {
		s.applyPolicy(policy)
		s.blocksApplied++
	}

	fmt.Printf("  Blocked: %d IPs, %d ports\n", len(ips), len(ports))
}

func (s *Server) applyPolicy(policy map[string]interface{}) {
	data, err := yaml.Marshal(policy)
	if err != nil {
		fmt.Printf("  Error marshaling policy: %v\n", err)
		return
	}

	cmd := exec.Command("kubectl", "apply", "-f", "-")
	cmd.Stdin = strings.NewReader(string(data))
	output, err := cmd.CombinedOutput()
	if err != nil {
		fmt.Printf("  Error applying policy: %v\n%s\n", err, output)
		return
	}
	fmt.Printf("  Applied to cluster\n")
}

func (s *Server) handleManualBlock(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req ManualBlockRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	if len(req.Values) == 0 {
		http.Error(w, "No values provided", http.StatusBadRequest)
		return
	}

	action := req.Action
	if action == "" {
		action = s.action
	}

	switch req.Type {
	case "ip":
		s.createBlockPolicy(req.Values, nil, "manual-block")
	case "port":
		s.createBlockPolicy(nil, req.Values, "manual-block")
	default:
		http.Error(w, "Invalid type", http.StatusBadRequest)
		return
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":  "blocked",
		"type":    req.Type,
		"count":   len(req.Values),
		"action":  action,
	})
}

func (s *Server) handleUnblock(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Type   string   `json:"type"`
		Values []string `json:"values"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	removed := 0
	for _, v := range req.Values {
		switch req.Type {
		case "ip":
			if _, ok := s.blockedIPs[v]; ok {
				delete(s.blockedIPs, v)
				removed++
			}
		case "port":
			if _, ok := s.blockedPorts[v]; ok {
				delete(s.blockedPorts, v)
				removed++
			}
		}
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":  "unblocked",
		"removed": removed,
	})
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("OK"))
}

func (s *Server) handleMetrics(w http.ResponseWriter, r *http.Request) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	metrics := fmt.Sprintf(`# HELP qualys_webhook_events_total Total webhook events received
# TYPE qualys_webhook_events_total counter
qualys_webhook_events_total %d

# HELP qualys_webhook_policies_created_total Total policies created
# TYPE qualys_webhook_policies_created_total counter
qualys_webhook_policies_created_total %d

# HELP qualys_webhook_blocks_applied_total Total blocks applied to cluster
# TYPE qualys_webhook_blocks_applied_total counter
qualys_webhook_blocks_applied_total %d

# HELP qualys_webhook_blocked_ips Current number of blocked IPs
# TYPE qualys_webhook_blocked_ips gauge
qualys_webhook_blocked_ips %d

# HELP qualys_webhook_blocked_ports Current number of blocked ports
# TYPE qualys_webhook_blocked_ports gauge
qualys_webhook_blocked_ports %d
`,
		s.eventsReceived,
		s.policiesCreated,
		s.blocksApplied,
		len(s.blockedIPs),
		len(s.blockedPorts),
	)

	w.Header().Set("Content-Type", "text/plain")
	w.Write([]byte(metrics))
}

func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	ips := make([]string, 0, len(s.blockedIPs))
	for ip := range s.blockedIPs {
		ips = append(ips, ip)
	}

	ports := make([]string, 0, len(s.blockedPorts))
	for port := range s.blockedPorts {
		ports = append(ports, port)
	}

	status := map[string]interface{}{
		"blockedIPs":      ips,
		"blockedPorts":    ports,
		"eventsReceived":  s.eventsReceived,
		"policiesCreated": s.policiesCreated,
		"blocksApplied":   s.blocksApplied,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(status)
}

func (s *Server) verifySignature(r *http.Request, signature string) bool {
	if signature == "" {
		return false
	}

	body, _ := io.ReadAll(r.Body)
	r.Body = io.NopCloser(strings.NewReader(string(body)))

	mac := hmac.New(sha256.New, []byte(s.webhookSecret))
	mac.Write(body)
	expected := hex.EncodeToString(mac.Sum(nil))

	return hmac.Equal([]byte(signature), []byte(expected))
}

func isPrivateIP(ip string) bool {
	return strings.HasPrefix(ip, "10.") ||
		strings.HasPrefix(ip, "172.16.") ||
		strings.HasPrefix(ip, "172.17.") ||
		strings.HasPrefix(ip, "172.18.") ||
		strings.HasPrefix(ip, "172.19.") ||
		strings.HasPrefix(ip, "172.2") ||
		strings.HasPrefix(ip, "172.30.") ||
		strings.HasPrefix(ip, "172.31.") ||
		strings.HasPrefix(ip, "192.168.") ||
		strings.HasPrefix(ip, "127.")
}

func isSuspiciousPort(port int) bool {
	suspicious := map[int]bool{
		4444: true, 5555: true, 6666: true, 6667: true,
		8443: true, 9001: true, 9050: true, 31337: true,
		12345: true, 27374: true, 1337: true,
	}
	return suspicious[port]
}

func sanitizeLabel(s string) string {
	s = strings.ToLower(s)
	s = strings.ReplaceAll(s, "_", "-")
	s = strings.ReplaceAll(s, " ", "-")
	if len(s) > 63 {
		s = s[:63]
	}
	return s
}
