package correlation

import (
	"context"
	"fmt"
	"sync"
	"time"
)

// EventType represents types of security events.
type EventType string

const (
	EventTypeProcess    EventType = "process"
	EventTypeNetwork    EventType = "network"
	EventTypeFile       EventType = "file"
	EventTypeDNS        EventType = "dns"
	EventTypeDrift      EventType = "drift"
	EventTypeAnomaly    EventType = "anomaly"
	EventTypeThreatIntel EventType = "threat_intel"
)

// SecurityEvent represents a single security event.
type SecurityEvent struct {
	ID            string                 `json:"id"`
	Timestamp     time.Time              `json:"timestamp"`
	Type          EventType              `json:"type"`
	Severity      string                 `json:"severity"`
	ContainerID   string                 `json:"containerId"`
	ContainerName string                 `json:"containerName"`
	PodName       string                 `json:"podName"`
	Namespace     string                 `json:"namespace"`
	ProcessName   string                 `json:"processName,omitempty"`
	ProcessPath   string                 `json:"processPath,omitempty"`
	ParentProcess string                 `json:"parentProcess,omitempty"`
	NetworkDest   string                 `json:"networkDest,omitempty"`
	NetworkPort   int                    `json:"networkPort,omitempty"`
	FilePath      string                 `json:"filePath,omitempty"`
	DNSQuery      string                 `json:"dnsQuery,omitempty"`
	Description   string                 `json:"description"`
	MITRETechnique string                `json:"mitreTechnique,omitempty"`
	MITRETactic   string                 `json:"mitreTactic,omitempty"`
	RawData       map[string]interface{} `json:"rawData,omitempty"`
}

// AttackChain represents a correlated sequence of events that form an attack.
type AttackChain struct {
	ID           string           `json:"id"`
	StartTime    time.Time        `json:"startTime"`
	LastUpdate   time.Time        `json:"lastUpdate"`
	Severity     string           `json:"severity"`
	ContainerID  string           `json:"containerId"`
	PodName      string           `json:"podName"`
	Namespace    string           `json:"namespace"`
	Events       []*SecurityEvent `json:"events"`
	Tactics      []string         `json:"tactics"`
	Techniques   []string         `json:"techniques"`
	Score        float64          `json:"score"` // Attack confidence score
	Status       string           `json:"status"` // "active", "completed", "mitigated"
	Description  string           `json:"description"`
}

// AttackPattern defines a known attack pattern for correlation.
type AttackPattern struct {
	Name         string      `json:"name"`
	Description  string      `json:"description"`
	Severity     string      `json:"severity"`
	EventTypes   []EventType `json:"eventTypes"`
	Sequence     []string    `json:"sequence"` // Ordered MITRE techniques
	TimeWindow   time.Duration `json:"timeWindow"`
	MinEvents    int         `json:"minEvents"`
}

// CorrelationEngine correlates security events into attack chains.
type CorrelationEngine struct {
	mu sync.RWMutex

	// Active attack chains per container
	activeChains map[string]*AttackChain

	// Event buffer for correlation
	eventBuffer  []*SecurityEvent
	maxBufferSize int

	// Attack patterns
	patterns     []*AttackPattern

	// Correlation window
	correlationWindow time.Duration

	// Callbacks
	onAttackDetected func(*AttackChain)
	onChainUpdated   func(*AttackChain)

	// Statistics
	totalEvents      int64
	chainsCreated    int64
	chainsCompleted  int64
}

// NewCorrelationEngine creates a new correlation engine.
func NewCorrelationEngine(correlationWindow time.Duration) *CorrelationEngine {
	if correlationWindow == 0 {
		correlationWindow = 30 * time.Minute
	}

	engine := &CorrelationEngine{
		activeChains:      make(map[string]*AttackChain),
		eventBuffer:       make([]*SecurityEvent, 0),
		maxBufferSize:     10000,
		correlationWindow: correlationWindow,
	}

	// Load default attack patterns
	engine.loadDefaultPatterns()

	return engine
}

// SetCallbacks sets event callbacks.
func (e *CorrelationEngine) SetCallbacks(onAttack func(*AttackChain), onUpdate func(*AttackChain)) {
	e.onAttackDetected = onAttack
	e.onChainUpdated = onUpdate
}

// loadDefaultPatterns loads known attack patterns.
func (e *CorrelationEngine) loadDefaultPatterns() {
	e.patterns = []*AttackPattern{
		{
			Name:        "Container Breakout",
			Description: "Sequence of events indicating container escape attempt",
			Severity:    "critical",
			EventTypes:  []EventType{EventTypeProcess, EventTypeFile, EventTypeNetwork},
			Sequence:    []string{"T1611", "T1068", "T1059"},
			TimeWindow:  15 * time.Minute,
			MinEvents:   3,
		},
		{
			Name:        "Cryptominer Deployment",
			Description: "Malware download followed by cryptominer execution",
			Severity:    "high",
			EventTypes:  []EventType{EventTypeNetwork, EventTypeDNS, EventTypeProcess},
			Sequence:    []string{"T1105", "T1059", "T1496"},
			TimeWindow:  30 * time.Minute,
			MinEvents:   2,
		},
		{
			Name:        "Credential Theft",
			Description: "Access to credentials followed by network exfiltration",
			Severity:    "critical",
			EventTypes:  []EventType{EventTypeFile, EventTypeNetwork},
			Sequence:    []string{"T1552", "T1041"},
			TimeWindow:  20 * time.Minute,
			MinEvents:   2,
		},
		{
			Name:        "Reverse Shell",
			Description: "Network connection followed by interactive shell",
			Severity:    "critical",
			EventTypes:  []EventType{EventTypeNetwork, EventTypeProcess},
			Sequence:    []string{"T1071", "T1059.004"},
			TimeWindow:  5 * time.Minute,
			MinEvents:   2,
		},
		{
			Name:        "Reconnaissance to Lateral Movement",
			Description: "Network scanning followed by lateral movement attempt",
			Severity:    "high",
			EventTypes:  []EventType{EventTypeNetwork, EventTypeProcess},
			Sequence:    []string{"T1046", "T1021"},
			TimeWindow:  30 * time.Minute,
			MinEvents:   2,
		},
		{
			Name:        "Persistence Establishment",
			Description: "Privilege escalation followed by persistence mechanism",
			Severity:    "high",
			EventTypes:  []EventType{EventTypeProcess, EventTypeFile},
			Sequence:    []string{"T1548", "T1053"},
			TimeWindow:  30 * time.Minute,
			MinEvents:   2,
		},
		{
			Name:        "Defense Evasion Chain",
			Description: "Log clearing followed by process hiding",
			Severity:    "high",
			EventTypes:  []EventType{EventTypeFile, EventTypeProcess},
			Sequence:    []string{"T1070", "T1564"},
			TimeWindow:  15 * time.Minute,
			MinEvents:   2,
		},
	}
}

// AddPattern adds a custom attack pattern.
func (e *CorrelationEngine) AddPattern(pattern *AttackPattern) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.patterns = append(e.patterns, pattern)
}

// ProcessEvent processes a new security event.
func (e *CorrelationEngine) ProcessEvent(ctx context.Context, event *SecurityEvent) []*AttackChain {
	e.mu.Lock()
	defer e.mu.Unlock()

	e.totalEvents++

	// Add to buffer
	if len(e.eventBuffer) >= e.maxBufferSize {
		e.eventBuffer = e.eventBuffer[1:]
	}
	e.eventBuffer = append(e.eventBuffer, event)

	// Find or create chain for this container
	chainKey := e.getChainKey(event)
	chain, exists := e.activeChains[chainKey]

	if !exists {
		// Create new chain
		chain = &AttackChain{
			ID:          fmt.Sprintf("chain-%d", time.Now().UnixNano()),
			StartTime:   event.Timestamp,
			LastUpdate:  event.Timestamp,
			ContainerID: event.ContainerID,
			PodName:     event.PodName,
			Namespace:   event.Namespace,
			Events:      make([]*SecurityEvent, 0),
			Tactics:     make([]string, 0),
			Techniques:  make([]string, 0),
			Status:      "active",
		}
		e.activeChains[chainKey] = chain
		e.chainsCreated++
	}

	// Add event to chain
	chain.Events = append(chain.Events, event)
	chain.LastUpdate = event.Timestamp

	// Add technique if present
	if event.MITRETechnique != "" && !contains(chain.Techniques, event.MITRETechnique) {
		chain.Techniques = append(chain.Techniques, event.MITRETechnique)
	}
	if event.MITRETactic != "" && !contains(chain.Tactics, event.MITRETactic) {
		chain.Tactics = append(chain.Tactics, event.MITRETactic)
	}

	// Update severity
	chain.Severity = e.calculateChainSeverity(chain)
	chain.Score = e.calculateChainScore(chain)

	// Check for pattern matches
	matchedPatterns := e.matchPatterns(chain)

	if len(matchedPatterns) > 0 {
		chain.Description = e.buildChainDescription(chain, matchedPatterns)

		// Trigger callback for new attack detection
		if e.onAttackDetected != nil && len(chain.Events) == len(matchedPatterns[0].Sequence) {
			go e.onAttackDetected(chain)
		} else if e.onChainUpdated != nil {
			go e.onChainUpdated(chain)
		}
	}

	// Clean up old chains
	e.cleanupOldChains()

	// Return any chains that match patterns
	var matchedChains []*AttackChain
	for _, c := range e.activeChains {
		if len(e.matchPatterns(c)) > 0 {
			matchedChains = append(matchedChains, c)
		}
	}

	return matchedChains
}

func (e *CorrelationEngine) getChainKey(event *SecurityEvent) string {
	if event.ContainerID != "" {
		return event.ContainerID
	}
	if event.PodName != "" && event.Namespace != "" {
		return fmt.Sprintf("%s/%s", event.Namespace, event.PodName)
	}
	return "unknown"
}

func (e *CorrelationEngine) matchPatterns(chain *AttackChain) []*AttackPattern {
	matched := []*AttackPattern{}

	for _, pattern := range e.patterns {
		if e.patternMatches(chain, pattern) {
			matched = append(matched, pattern)
		}
	}

	return matched
}

func (e *CorrelationEngine) patternMatches(chain *AttackChain, pattern *AttackPattern) bool {
	// Check minimum events
	if len(chain.Events) < pattern.MinEvents {
		return false
	}

	// Check time window
	if chain.LastUpdate.Sub(chain.StartTime) > pattern.TimeWindow {
		return false
	}

	// Check technique sequence (partial match)
	matchedTechniques := 0
	for _, requiredTech := range pattern.Sequence {
		for _, chainTech := range chain.Techniques {
			if chainTech == requiredTech || hasPrefix(chainTech, requiredTech) {
				matchedTechniques++
				break
			}
		}
	}

	// Require at least half of the sequence to match
	return matchedTechniques >= len(pattern.Sequence)/2
}

func (e *CorrelationEngine) calculateChainSeverity(chain *AttackChain) string {
	criticalCount := 0
	highCount := 0

	for _, event := range chain.Events {
		switch event.Severity {
		case "critical":
			criticalCount++
		case "high":
			highCount++
		}
	}

	if criticalCount >= 2 || (criticalCount >= 1 && highCount >= 2) {
		return "critical"
	}
	if criticalCount >= 1 || highCount >= 2 {
		return "high"
	}
	if highCount >= 1 || len(chain.Events) >= 3 {
		return "medium"
	}
	return "low"
}

func (e *CorrelationEngine) calculateChainScore(chain *AttackChain) float64 {
	score := 0.0

	// Base score from event count
	score += float64(len(chain.Events)) * 10

	// Bonus for technique diversity
	score += float64(len(chain.Techniques)) * 15

	// Bonus for tactic diversity
	score += float64(len(chain.Tactics)) * 20

	// Severity bonus
	switch chain.Severity {
	case "critical":
		score += 30
	case "high":
		score += 20
	case "medium":
		score += 10
	}

	// Pattern match bonus
	matchedPatterns := e.matchPatterns(chain)
	score += float64(len(matchedPatterns)) * 25

	// Cap at 100
	if score > 100 {
		score = 100
	}

	return score
}

func (e *CorrelationEngine) buildChainDescription(chain *AttackChain, patterns []*AttackPattern) string {
	if len(patterns) > 0 {
		return fmt.Sprintf("Attack chain detected: %s. %d events across %d techniques.",
			patterns[0].Name,
			len(chain.Events),
			len(chain.Techniques))
	}

	return fmt.Sprintf("Suspicious activity chain: %d events across %d techniques in %s.",
		len(chain.Events),
		len(chain.Techniques),
		chain.LastUpdate.Sub(chain.StartTime).String())
}

func (e *CorrelationEngine) cleanupOldChains() {
	cutoff := time.Now().Add(-e.correlationWindow * 2)

	for key, chain := range e.activeChains {
		if chain.LastUpdate.Before(cutoff) {
			chain.Status = "completed"
			e.chainsCompleted++
			delete(e.activeChains, key)
		}
	}
}

// GetActiveChains returns all active attack chains.
func (e *CorrelationEngine) GetActiveChains() []*AttackChain {
	e.mu.RLock()
	defer e.mu.RUnlock()

	chains := make([]*AttackChain, 0, len(e.activeChains))
	for _, chain := range e.activeChains {
		chains = append(chains, chain)
	}
	return chains
}

// GetChain returns a specific attack chain.
func (e *CorrelationEngine) GetChain(id string) *AttackChain {
	e.mu.RLock()
	defer e.mu.RUnlock()

	for _, chain := range e.activeChains {
		if chain.ID == id {
			return chain
		}
	}
	return nil
}

// GetChainByContainer returns the chain for a specific container.
func (e *CorrelationEngine) GetChainByContainer(containerID string) *AttackChain {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.activeChains[containerID]
}

// Stats returns correlation engine statistics.
func (e *CorrelationEngine) Stats() map[string]interface{} {
	e.mu.RLock()
	defer e.mu.RUnlock()

	highSeverityChains := 0
	criticalChains := 0

	for _, chain := range e.activeChains {
		switch chain.Severity {
		case "critical":
			criticalChains++
		case "high":
			highSeverityChains++
		}
	}

	return map[string]interface{}{
		"total_events":      e.totalEvents,
		"chains_created":    e.chainsCreated,
		"chains_completed":  e.chainsCompleted,
		"active_chains":     len(e.activeChains),
		"critical_chains":   criticalChains,
		"high_sev_chains":   highSeverityChains,
		"patterns_loaded":   len(e.patterns),
		"buffer_size":       len(e.eventBuffer),
		"correlation_window": e.correlationWindow.String(),
	}
}

// GenerateReport generates a report for an attack chain.
func (e *CorrelationEngine) GenerateReport(chain *AttackChain) map[string]interface{} {
	report := map[string]interface{}{
		"chain_id":    chain.ID,
		"severity":    chain.Severity,
		"score":       chain.Score,
		"status":      chain.Status,
		"start_time":  chain.StartTime,
		"last_update": chain.LastUpdate,
		"duration":    chain.LastUpdate.Sub(chain.StartTime).String(),
		"description": chain.Description,
		"target": map[string]string{
			"container_id": chain.ContainerID,
			"pod_name":     chain.PodName,
			"namespace":    chain.Namespace,
		},
		"mitre_coverage": map[string]interface{}{
			"tactics":    chain.Tactics,
			"techniques": chain.Techniques,
		},
		"event_timeline": e.buildEventTimeline(chain),
		"recommendations": e.generateRecommendations(chain),
	}

	return report
}

func (e *CorrelationEngine) buildEventTimeline(chain *AttackChain) []map[string]interface{} {
	timeline := make([]map[string]interface{}, len(chain.Events))

	for i, event := range chain.Events {
		timeline[i] = map[string]interface{}{
			"sequence":       i + 1,
			"timestamp":      event.Timestamp,
			"type":           event.Type,
			"severity":       event.Severity,
			"description":    event.Description,
			"mitre_technique": event.MITRETechnique,
			"process":        event.ProcessName,
			"network_dest":   event.NetworkDest,
			"file_path":      event.FilePath,
		}
	}

	return timeline
}

func (e *CorrelationEngine) generateRecommendations(chain *AttackChain) []string {
	recommendations := []string{}

	// Based on detected patterns
	for _, pattern := range e.matchPatterns(chain) {
		switch pattern.Name {
		case "Container Breakout":
			recommendations = append(recommendations,
				"Immediately isolate the container",
				"Review container security context (privileged, capabilities)",
				"Check for mounted sensitive host paths",
				"Audit container image for vulnerabilities")
		case "Cryptominer Deployment":
			recommendations = append(recommendations,
				"Kill the mining process",
				"Block outbound connections to mining pools",
				"Scan the container for additional malware",
				"Review network policies")
		case "Credential Theft":
			recommendations = append(recommendations,
				"Rotate all credentials accessed by this workload",
				"Review IAM permissions",
				"Enable credential monitoring",
				"Check for lateral movement")
		case "Reverse Shell":
			recommendations = append(recommendations,
				"Immediately terminate the connection",
				"Block the destination IP",
				"Capture forensic data",
				"Review ingress points")
		}
	}

	// Default recommendations
	if len(recommendations) == 0 {
		recommendations = []string{
			"Investigate the event sequence",
			"Consider isolating the workload",
			"Capture forensic data for analysis",
			"Review security policies",
		}
	}

	return recommendations
}

func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

func hasPrefix(s, prefix string) bool {
	return len(s) >= len(prefix) && s[:len(prefix)] == prefix
}
