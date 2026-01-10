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
	"strconv"
	"strings"
	"sync"
	"time"

	"qualys-policy-operator/pkg/drift"
	"qualys-policy-operator/pkg/outputs"
	"qualys-policy-operator/pkg/reputation"
	"qualys-policy-operator/pkg/response"
	"sigs.k8s.io/yaml"
)

// ServerV2 is the enhanced webhook server with full feature parity.
type ServerV2 struct {
	addr           string
	webhookSecret  string
	action         string
	outputDir      string
	applyToCluster bool

	// Enhanced components
	driftDetector  *drift.DriftDetector
	repChecker     *reputation.ReputationChecker
	responseEngine *response.ResponseEngine
	outputManager  *outputs.OutputManager

	// Tracking
	mu             sync.RWMutex
	blockedIPs     map[string]time.Time
	blockedPorts   map[string]time.Time

	// Metrics
	eventsReceived   int64
	policiesCreated  int64
	blocksApplied    int64
	driftDetected    int64
	actionsExecuted  int64
}

// ServerV2Config holds configuration for the enhanced server.
type ServerV2Config struct {
	Addr           string
	WebhookSecret  string
	Action         string
	OutputDir      string
	ApplyToCluster bool
	QuarantineDir  string
	CaptureDir     string
	LearningPeriod time.Duration
	BlockDrift     bool

	// Output integrations
	SlackWebhook     string
	SlackChannel     string
	PagerDutyKey     string
	TeamsWebhook     string
	SplunkURL        string
	SplunkToken      string
	SplunkIndex      string
	ElasticsearchURL string
	ElasticsearchIdx string
	SyslogAddress    string

	// Threat intel
	AbuseIPDBKey     string
}

// NewServerV2 creates the enhanced webhook server.
func NewServerV2(cfg *ServerV2Config) *ServerV2 {
	s := &ServerV2{
		addr:           cfg.Addr,
		webhookSecret:  cfg.WebhookSecret,
		action:         cfg.Action,
		outputDir:      cfg.OutputDir,
		applyToCluster: cfg.ApplyToCluster,
		blockedIPs:     make(map[string]time.Time),
		blockedPorts:   make(map[string]time.Time),
	}

	// Initialize drift detector
	learningPeriod := cfg.LearningPeriod
	if learningPeriod == 0 {
		learningPeriod = 48 * time.Hour // Industry standard
	}
	s.driftDetector = drift.NewDriftDetector(learningPeriod, cfg.BlockDrift)
	s.driftDetector.SetDriftCallback(s.onDriftDetected)

	// Initialize response engine
	s.responseEngine = response.NewResponseEngine(cfg.QuarantineDir, cfg.CaptureDir)

	// Initialize threat intel
	if cfg.AbuseIPDBKey != "" {
		s.repChecker = reputation.NewReputationChecker(cfg.AbuseIPDBKey)
	}

	// Initialize output integrations
	s.outputManager = outputs.NewOutputManager()
	s.configureOutputs(cfg)

	return s
}

func (s *ServerV2) configureOutputs(cfg *ServerV2Config) {
	if cfg.SlackWebhook != "" {
		s.outputManager.AddOutput(outputs.NewSlackOutput(cfg.SlackWebhook, cfg.SlackChannel))
	}

	if cfg.PagerDutyKey != "" {
		s.outputManager.AddOutput(outputs.NewPagerDutyOutput(cfg.PagerDutyKey))
	}

	if cfg.TeamsWebhook != "" {
		s.outputManager.AddOutput(outputs.NewTeamsOutput(cfg.TeamsWebhook))
	}

	if cfg.SplunkURL != "" && cfg.SplunkToken != "" {
		s.outputManager.AddOutput(outputs.NewSplunkHECOutput(cfg.SplunkURL, cfg.SplunkToken, cfg.SplunkIndex))
	}

	if cfg.ElasticsearchURL != "" {
		s.outputManager.AddOutput(outputs.NewElasticsearchOutput(cfg.ElasticsearchURL, cfg.ElasticsearchIdx, "", ""))
	}

	if cfg.SyslogAddress != "" {
		s.outputManager.AddOutput(outputs.NewSyslogOutput(cfg.SyslogAddress, "udp"))
	}
}

// Start starts the enhanced webhook server.
func (s *ServerV2) Start(ctx context.Context) error {
	mux := http.NewServeMux()

	// CDR webhook endpoints
	mux.HandleFunc("/webhook/cdr", s.handleCDRWebhook)
	mux.HandleFunc("/webhook/tetragon", s.handleTetragonWebhook)

	// API endpoints
	mux.HandleFunc("/api/block", s.handleManualBlock)
	mux.HandleFunc("/api/unblock", s.handleUnblock)
	mux.HandleFunc("/api/respond", s.handleResponseAction)

	// Drift detection
	mux.HandleFunc("/api/drift/register", s.handleDriftRegister)
	mux.HandleFunc("/api/drift/status", s.handleDriftStatus)
	mux.HandleFunc("/api/drift/baseline", s.handleDriftBaseline)

	// Status and health
	mux.HandleFunc("/health", s.handleHealth)
	mux.HandleFunc("/healthz", s.handleHealth)
	mux.HandleFunc("/readyz", s.handleReady)
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

	// Start drift event processor
	go s.processDriftEvents(ctx)

	fmt.Printf("Enhanced Webhook Server v2 starting on %s\n", s.addr)
	fmt.Printf("Endpoints:\n")
	fmt.Printf("  POST /webhook/cdr         - Qualys CDR webhook\n")
	fmt.Printf("  POST /webhook/tetragon    - Tetragon events webhook\n")
	fmt.Printf("  POST /api/block           - Manual blocking API\n")
	fmt.Printf("  POST /api/respond         - Execute response action\n")
	fmt.Printf("  POST /api/drift/register  - Register container for drift detection\n")
	fmt.Printf("  GET  /api/drift/status    - Drift detection status\n")
	fmt.Printf("  GET  /health              - Health check\n")
	fmt.Printf("  GET  /metrics             - Prometheus metrics\n")

	return server.ListenAndServe()
}

func (s *ServerV2) handleCDRWebhook(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Verify signature if configured
	signature := r.Header.Get("X-Qualys-Signature")
	if !s.verifySignature(r, signature) {
		http.Error(w, "Invalid signature", http.StatusUnauthorized)
		return
	}

	var events []WebhookEvent
	if err := json.NewDecoder(r.Body).Decode(&events); err != nil {
		// Try single event
		var event WebhookEvent
		if err := json.NewDecoder(r.Body).Decode(&event); err != nil {
			http.Error(w, "Invalid JSON", http.StatusBadRequest)
			return
		}
		events = []WebhookEvent{event}
	}

	for _, event := range events {
		s.processEnhancedEvent(r.Context(), event)
	}

	s.mu.Lock()
	s.eventsReceived += int64(len(events))
	s.mu.Unlock()

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":    "processed",
		"processed": len(events),
	})
}

func (s *ServerV2) processEnhancedEvent(ctx context.Context, event WebhookEvent) {
	fmt.Printf("[%s] Processing: %s - %s\n",
		time.Now().Format(time.RFC3339),
		event.Category,
		event.EventID)

	// Convert to security event for outputs
	secEvent := &outputs.SecurityEvent{
		EventID:        event.EventID,
		Timestamp:      time.Now(),
		Category:       event.Category,
		Severity:       s.mapSeverity(event.Severity),
		Title:          event.ThreatCategory,
		Description:    fmt.Sprintf("CDR detection: %s", event.Category),
		ContainerID:    event.Raw["containerId"].(string),
		ContainerName:  event.ContainerName,
		PodName:        event.PodName,
		ProcessName:    event.ProcessName,
		DestinationIP:  event.DestinationIP,
		MITRETechnique: s.mapMITRE(event.Category),
	}

	// Check for drift
	if event.ProcessName != "" {
		containerID := ""
		if cid, ok := event.Raw["containerId"].(string); ok {
			containerID = cid
		}

		driftEvent := s.driftDetector.ProcessExecEvent(
			containerID,
			event.ContainerName,
			"", // image name not in event
			event.ProcessName,
		)

		if driftEvent != nil {
			secEvent.Category = "drift_detected"
			secEvent.Title = "Container Drift Detected"
			secEvent.Description = fmt.Sprintf("New executable %s not in baseline", driftEvent.Path)

			s.mu.Lock()
			s.driftDetected++
			s.mu.Unlock()
		}
	}

	// Check IP reputation
	if event.DestinationIP != "" && s.repChecker != nil {
		score, _ := s.repChecker.CheckIP(ctx, event.DestinationIP)
		if score != nil && score.Score >= 50 {
			secEvent.Description += fmt.Sprintf(" [Bad IP reputation: %d]", score.Score)
		}
	}

	// Determine response action
	actionType := response.ActionAlert
	if s.action == "Sigkill" || event.Severity >= 4 {
		actionType = response.ActionKillProcess
	}

	// Execute response
	actionReq := &response.ActionRequest{
		Type:          actionType,
		ContainerID:   secEvent.ContainerID,
		ContainerName: event.ContainerName,
		PodName:       event.PodName,
		Reason:        event.Category,
		Severity:      secEvent.Severity,
		EventID:       event.EventID,
	}

	result := s.responseEngine.Execute(ctx, actionReq)
	secEvent.ActionTaken = string(result.Action)

	s.mu.Lock()
	s.actionsExecuted++
	s.mu.Unlock()

	// Send to all outputs
	s.outputManager.Send(ctx, secEvent)

	// Generate blocking policy if needed
	s.createBlockingPolicy(event)
}

func (s *ServerV2) handleTetragonWebhook(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var tetragonEvent struct {
		ProcessKprobe struct {
			Process struct {
				Binary    string `json:"binary"`
				Arguments string `json:"arguments"`
				Pod       struct {
					Name      string `json:"name"`
					Namespace string `json:"namespace"`
				} `json:"pod"`
				Docker string `json:"docker"`
			} `json:"process"`
			FunctionName string `json:"function_name"`
		} `json:"process_kprobe"`
		Time string `json:"time"`
	}

	if err := json.NewDecoder(r.Body).Decode(&tetragonEvent); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	// Process Tetragon event
	proc := tetragonEvent.ProcessKprobe.Process
	containerID := proc.Docker

	// Check for drift
	driftEvent := s.driftDetector.ProcessExecEvent(
		containerID,
		"", // container name
		"", // image name
		proc.Binary,
	)

	if driftEvent != nil {
		secEvent := &outputs.SecurityEvent{
			EventID:        fmt.Sprintf("tetragon-%d", time.Now().UnixNano()),
			Timestamp:      time.Now(),
			Category:       "drift_detected",
			Severity:       "critical",
			Title:          "Container Drift Detected",
			Description:    fmt.Sprintf("New executable %s executed", driftEvent.Path),
			ContainerID:    containerID,
			PodName:        proc.Pod.Name,
			Namespace:      proc.Pod.Namespace,
			ProcessPath:    proc.Binary,
			MITRETechnique: "T1059.004",
		}

		s.outputManager.Send(r.Context(), secEvent)
	}

	w.WriteHeader(http.StatusOK)
}

func (s *ServerV2) handleResponseAction(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req response.ActionRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	result := s.responseEngine.Execute(r.Context(), &req)

	s.mu.Lock()
	s.actionsExecuted++
	s.mu.Unlock()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(result)
}

func (s *ServerV2) handleDriftRegister(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		ContainerID string `json:"containerId"`
		ImageID     string `json:"imageId"`
		ImageName   string `json:"imageName"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	if err := s.driftDetector.RegisterContainer(req.ContainerID, req.ImageID, req.ImageName); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"status": "registered"})
}

func (s *ServerV2) handleDriftStatus(w http.ResponseWriter, r *http.Request) {
	stats := s.driftDetector.Stats()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(stats)
}

func (s *ServerV2) handleDriftBaseline(w http.ResponseWriter, r *http.Request) {
	containerID := r.URL.Query().Get("container")
	if containerID == "" {
		// Return all baselines
		baselines := s.driftDetector.GetAllBaselines()
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(baselines)
		return
	}

	baseline := s.driftDetector.GetBaseline(containerID)
	if baseline == nil {
		http.Error(w, "Container not found", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(baseline)
}

func (s *ServerV2) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("OK"))
}

func (s *ServerV2) handleReady(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("Ready"))
}

func (s *ServerV2) handleMetrics(w http.ResponseWriter, r *http.Request) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	driftStats := s.driftDetector.Stats()

	metrics := fmt.Sprintf(`# HELP qualys_webhook_events_total Total webhook events received
# TYPE qualys_webhook_events_total counter
qualys_webhook_events_total %d

# HELP qualys_webhook_policies_created_total Total policies created
# TYPE qualys_webhook_policies_created_total counter
qualys_webhook_policies_created_total %d

# HELP qualys_webhook_blocks_applied_total Total blocks applied to cluster
# TYPE qualys_webhook_blocks_applied_total counter
qualys_webhook_blocks_applied_total %d

# HELP qualys_webhook_drift_detected_total Total drift events detected
# TYPE qualys_webhook_drift_detected_total counter
qualys_webhook_drift_detected_total %d

# HELP qualys_webhook_actions_executed_total Total response actions executed
# TYPE qualys_webhook_actions_executed_total counter
qualys_webhook_actions_executed_total %d

# HELP qualys_drift_containers_learning Containers in learning mode
# TYPE qualys_drift_containers_learning gauge
qualys_drift_containers_learning %d

# HELP qualys_drift_containers_monitoring Containers being monitored
# TYPE qualys_drift_containers_monitoring gauge
qualys_drift_containers_monitoring %d

# HELP qualys_drift_executables_baselined Total executables baselined
# TYPE qualys_drift_executables_baselined gauge
qualys_drift_executables_baselined %d
`,
		s.eventsReceived,
		s.policiesCreated,
		s.blocksApplied,
		s.driftDetected,
		s.actionsExecuted,
		driftStats["containers_learning"],
		driftStats["containers_monitoring"],
		driftStats["total_executables"],
	)

	w.Header().Set("Content-Type", "text/plain")
	w.Write([]byte(metrics))
}

func (s *ServerV2) handleStatus(w http.ResponseWriter, r *http.Request) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	status := map[string]interface{}{
		"eventsReceived":   s.eventsReceived,
		"policiesCreated":  s.policiesCreated,
		"blocksApplied":    s.blocksApplied,
		"driftDetected":    s.driftDetected,
		"actionsExecuted":  s.actionsExecuted,
		"blockedIPs":       len(s.blockedIPs),
		"blockedPorts":     len(s.blockedPorts),
		"driftDetection":   s.driftDetector.Stats(),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(status)
}

func (s *ServerV2) handleManualBlock(w http.ResponseWriter, r *http.Request) {
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

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status": "blocked",
		"type":   req.Type,
		"count":  len(req.Values),
		"action": action,
	})
}

func (s *ServerV2) handleUnblock(w http.ResponseWriter, r *http.Request) {
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

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":  "unblocked",
		"type":    req.Type,
		"removed": removed,
	})
}

func (s *ServerV2) processDriftEvents(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case event := <-s.driftDetector.Events():
			s.handleDriftEvent(ctx, event)
		}
	}
}

func (s *ServerV2) onDriftDetected(event *drift.DriftEvent) {
	fmt.Printf("[DRIFT] %s: %s in container %s\n",
		event.EventType,
		event.Path,
		event.ContainerID[:12])
}

func (s *ServerV2) handleDriftEvent(ctx context.Context, event *drift.DriftEvent) {
	secEvent := &outputs.SecurityEvent{
		EventID:        fmt.Sprintf("drift-%d", time.Now().UnixNano()),
		Timestamp:      event.DetectedAt,
		Category:       "drift",
		Severity:       event.Severity,
		Title:          fmt.Sprintf("Container Drift: %s", event.EventType),
		Description:    fmt.Sprintf("Executable %s detected in container", event.Path),
		ContainerID:    event.ContainerID,
		ContainerName:  event.ContainerName,
		ImageName:      event.ImageName,
		ProcessPath:    event.Path,
		MITRETechnique: event.MITRETechnique,
	}

	s.outputManager.Send(ctx, secEvent)

	// Generate blocking policy if configured
	if s.driftDetector != nil {
		// Could generate TracingPolicy to block the executable
	}
}

func (s *ServerV2) createBlockingPolicy(event WebhookEvent) {
	var ips, ports []string

	if event.DestinationIP != "" && !isPrivateIP(event.DestinationIP) {
		ips = append(ips, event.DestinationIP)
	}
	if event.DestinationPort > 0 && isSuspiciousPort(event.DestinationPort) {
		ports = append(ports, strconv.Itoa(event.DestinationPort))
	}

	if len(ips) > 0 || len(ports) > 0 {
		s.createBlockPolicy(ips, ports, event.Category)
	}
}

func (s *ServerV2) createBlockPolicy(ips, ports []string, category string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()
	for _, ip := range ips {
		s.blockedIPs[ip] = now
	}
	for _, port := range ports {
		s.blockedPorts[port] = now
	}

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
				"qualys.com/managed": "true",
				"qualys.com/type":    "realtime-block",
				"qualys.com/source":  category,
			},
		},
		"spec": map[string]interface{}{
			"kprobes": []map[string]interface{}{
				{
					"call":      "tcp_connect",
					"syscall":   false,
					"selectors": selectors,
				},
			},
		},
	}

	policyYAML, err := yaml.Marshal(policy)
	if err != nil {
		return
	}

	if s.outputDir != "" {
		filename := fmt.Sprintf("%s/%s.yaml", s.outputDir, policyName)
		os.WriteFile(filename, policyYAML, 0644)
	}

	s.policiesCreated++
}

func (s *ServerV2) verifySignature(r *http.Request, signature string) bool {
	if s.webhookSecret == "" {
		return true // No secret configured, skip verification
	}
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

func (s *ServerV2) mapSeverity(sev int) string {
	switch {
	case sev >= 4:
		return "critical"
	case sev >= 3:
		return "high"
	case sev >= 2:
		return "medium"
	default:
		return "low"
	}
}

func (s *ServerV2) mapMITRE(category string) string {
	mapping := map[string]string{
		"Cloud_Credentials_Accessed_By_Network_Utility": "T1552.005",
		"Network_Scanning_Utility":                       "T1046",
		"Container_Escape":                               "T1611",
		"Crypto_Mining":                                  "T1496",
		"Reverse_Shell":                                  "T1059.004",
	}

	if technique, ok := mapping[category]; ok {
		return technique
	}
	return "T1059"
}
