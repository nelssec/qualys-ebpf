package behavior

import (
	"context"
	"fmt"
	"math"
	"sync"
	"time"
)

// EventType represents types of behavioral events.
type EventType string

const (
	EventTypeProcess    EventType = "process"
	EventTypeNetwork    EventType = "network"
	EventTypeFile       EventType = "file"
	EventTypeSyscall    EventType = "syscall"
	EventTypeDNS        EventType = "dns"
)

// BehaviorEvent represents a single behavioral observation.
type BehaviorEvent struct {
	Timestamp     time.Time         `json:"timestamp"`
	Type          EventType         `json:"type"`
	ContainerID   string            `json:"containerId"`
	ContainerName string            `json:"containerName"`
	ProcessName   string            `json:"processName,omitempty"`
	ProcessPath   string            `json:"processPath,omitempty"`
	ParentProcess string            `json:"parentProcess,omitempty"`
	NetworkDest   string            `json:"networkDest,omitempty"`
	NetworkPort   int               `json:"networkPort,omitempty"`
	FilePath      string            `json:"filePath,omitempty"`
	FileOp        string            `json:"fileOp,omitempty"`
	DNSQuery      string            `json:"dnsQuery,omitempty"`
	Syscall       string            `json:"syscall,omitempty"`
	Attributes    map[string]string `json:"attributes,omitempty"`
}

// BehaviorProfile represents learned behavior for a container/workload.
type BehaviorProfile struct {
	ContainerID   string    `json:"containerId"`
	ContainerName string    `json:"containerName"`
	ImageName     string    `json:"imageName"`
	CreatedAt     time.Time `json:"createdAt"`
	LearningUntil time.Time `json:"learningUntil"`
	IsLearning    bool      `json:"isLearning"`

	// Process behavior
	KnownProcesses    map[string]*ProcessProfile `json:"knownProcesses"`
	ProcessTreeDepth  int                        `json:"processTreeDepth"`

	// Network behavior
	KnownDestinations map[string]*NetworkProfile `json:"knownDestinations"`
	KnownPorts        map[int]int                `json:"knownPorts"` // port -> count

	// File behavior
	KnownFilePaths    map[string]*FileProfile    `json:"knownFilePaths"`
	KnownFilePatterns []string                   `json:"knownFilePatterns"`

	// DNS behavior
	KnownDNSQueries   map[string]int             `json:"knownDnsQueries"` // domain -> count

	// Statistics for anomaly detection
	Stats             *ProfileStats              `json:"stats"`
}

// ProcessProfile tracks process execution patterns.
type ProcessProfile struct {
	Path          string    `json:"path"`
	Count         int       `json:"count"`
	LastSeen      time.Time `json:"lastSeen"`
	ParentProcess string    `json:"parentProcess"`
	Arguments     []string  `json:"arguments,omitempty"`
}

// NetworkProfile tracks network connection patterns.
type NetworkProfile struct {
	Destination string    `json:"destination"`
	Port        int       `json:"port"`
	Protocol    string    `json:"protocol"`
	Count       int       `json:"count"`
	LastSeen    time.Time `json:"lastSeen"`
	BytesSent   int64     `json:"bytesSent"`
	BytesRecv   int64     `json:"bytesRecv"`
}

// FileProfile tracks file access patterns.
type FileProfile struct {
	Path      string    `json:"path"`
	Operation string    `json:"operation"` // read, write, execute
	Count     int       `json:"count"`
	LastSeen  time.Time `json:"lastSeen"`
}

// ProfileStats holds statistical data for anomaly detection.
type ProfileStats struct {
	TotalEvents       int64   `json:"totalEvents"`
	ProcessEvents     int64   `json:"processEvents"`
	NetworkEvents     int64   `json:"networkEvents"`
	FileEvents        int64   `json:"fileEvents"`
	DNSEvents         int64   `json:"dnsEvents"`

	// Rate statistics (events per minute)
	ProcessRate       float64 `json:"processRate"`
	NetworkRate       float64 `json:"networkRate"`
	FileRate          float64 `json:"fileRate"`

	// Standard deviations for anomaly detection
	ProcessRateStdDev float64 `json:"processRateStdDev"`
	NetworkRateStdDev float64 `json:"networkRateStdDev"`
}

// Anomaly represents a detected behavioral anomaly.
type Anomaly struct {
	Timestamp     time.Time              `json:"timestamp"`
	ContainerID   string                 `json:"containerId"`
	ContainerName string                 `json:"containerName"`
	Type          string                 `json:"type"`
	Severity      string                 `json:"severity"`
	Description   string                 `json:"description"`
	Score         float64                `json:"score"` // 0-100, higher = more anomalous
	Event         *BehaviorEvent         `json:"event"`
	Context       map[string]interface{} `json:"context"`
}

// BehaviorProfiler performs behavioral profiling and anomaly detection.
type BehaviorProfiler struct {
	profiles       map[string]*BehaviorProfile
	mu             sync.RWMutex
	learningPeriod time.Duration
	anomalyThreshold float64

	// Anomaly channel
	anomalyChan    chan *Anomaly

	// Callbacks
	onAnomaly      func(*Anomaly)
}

// NewBehaviorProfiler creates a new behavior profiler.
func NewBehaviorProfiler(learningPeriod time.Duration, anomalyThreshold float64) *BehaviorProfiler {
	if anomalyThreshold == 0 {
		anomalyThreshold = 70.0 // Default threshold
	}

	return &BehaviorProfiler{
		profiles:         make(map[string]*BehaviorProfile),
		learningPeriod:   learningPeriod,
		anomalyThreshold: anomalyThreshold,
		anomalyChan:      make(chan *Anomaly, 100),
	}
}

// SetAnomalyCallback sets the callback for anomaly events.
func (p *BehaviorProfiler) SetAnomalyCallback(callback func(*Anomaly)) {
	p.onAnomaly = callback
}

// Anomalies returns the channel for anomaly events.
func (p *BehaviorProfiler) Anomalies() <-chan *Anomaly {
	return p.anomalyChan
}

// RegisterContainer creates a new profile for a container.
func (p *BehaviorProfiler) RegisterContainer(containerID, imageName string) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if _, exists := p.profiles[containerID]; exists {
		return
	}

	now := time.Now()
	p.profiles[containerID] = &BehaviorProfile{
		ContainerID:       containerID,
		ImageName:         imageName,
		CreatedAt:         now,
		LearningUntil:     now.Add(p.learningPeriod),
		IsLearning:        true,
		KnownProcesses:    make(map[string]*ProcessProfile),
		KnownDestinations: make(map[string]*NetworkProfile),
		KnownPorts:        make(map[int]int),
		KnownFilePaths:    make(map[string]*FileProfile),
		KnownDNSQueries:   make(map[string]int),
		Stats:             &ProfileStats{},
	}

	fmt.Printf("[Behavior] Registered container %s, learning for %v\n", containerID[:12], p.learningPeriod)
}

// ProcessEvent processes a behavioral event.
func (p *BehaviorProfiler) ProcessEvent(ctx context.Context, event *BehaviorEvent) *Anomaly {
	p.mu.Lock()
	defer p.mu.Unlock()

	profile, exists := p.profiles[event.ContainerID]
	if !exists {
		// Auto-register
		now := time.Now()
		profile = &BehaviorProfile{
			ContainerID:       event.ContainerID,
			ContainerName:     event.ContainerName,
			CreatedAt:         now,
			LearningUntil:     now.Add(p.learningPeriod),
			IsLearning:        true,
			KnownProcesses:    make(map[string]*ProcessProfile),
			KnownDestinations: make(map[string]*NetworkProfile),
			KnownPorts:        make(map[int]int),
			KnownFilePaths:    make(map[string]*FileProfile),
			KnownDNSQueries:   make(map[string]int),
			Stats:             &ProfileStats{},
		}
		p.profiles[event.ContainerID] = profile
	}

	// Check if still in learning mode
	if time.Now().Before(profile.LearningUntil) {
		profile.IsLearning = true
	} else if profile.IsLearning {
		profile.IsLearning = false
		fmt.Printf("[Behavior] Container %s learning complete\n", event.ContainerID[:12])
	}

	// Update statistics
	profile.Stats.TotalEvents++

	// Process based on event type
	var anomaly *Anomaly

	switch event.Type {
	case EventTypeProcess:
		anomaly = p.processProcessEvent(profile, event)
	case EventTypeNetwork:
		anomaly = p.processNetworkEvent(profile, event)
	case EventTypeFile:
		anomaly = p.processFileEvent(profile, event)
	case EventTypeDNS:
		anomaly = p.processDNSEvent(profile, event)
	}

	if anomaly != nil && anomaly.Score >= p.anomalyThreshold {
		p.emitAnomaly(anomaly)
	}

	return anomaly
}

func (p *BehaviorProfiler) processProcessEvent(profile *BehaviorProfile, event *BehaviorEvent) *Anomaly {
	profile.Stats.ProcessEvents++

	key := event.ProcessPath
	if key == "" {
		key = event.ProcessName
	}

	existing, known := profile.KnownProcesses[key]

	if profile.IsLearning {
		// Learning mode - record the process
		if !known {
			profile.KnownProcesses[key] = &ProcessProfile{
				Path:          event.ProcessPath,
				Count:         1,
				LastSeen:      event.Timestamp,
				ParentProcess: event.ParentProcess,
			}
		} else {
			existing.Count++
			existing.LastSeen = event.Timestamp
		}
		return nil
	}

	// Detection mode - check for anomalies
	if !known {
		return &Anomaly{
			Timestamp:     event.Timestamp,
			ContainerID:   event.ContainerID,
			ContainerName: event.ContainerName,
			Type:          "unknown_process",
			Severity:      "high",
			Description:   fmt.Sprintf("Unknown process executed: %s", key),
			Score:         85.0,
			Event:         event,
			Context: map[string]interface{}{
				"process":       key,
				"parent":        event.ParentProcess,
				"known_count":   len(profile.KnownProcesses),
			},
		}
	}

	// Check for unusual parent process
	if existing.ParentProcess != "" && event.ParentProcess != existing.ParentProcess {
		return &Anomaly{
			Timestamp:     event.Timestamp,
			ContainerID:   event.ContainerID,
			ContainerName: event.ContainerName,
			Type:          "unusual_parent",
			Severity:      "medium",
			Description:   fmt.Sprintf("Process %s spawned by unusual parent: %s (expected: %s)", key, event.ParentProcess, existing.ParentProcess),
			Score:         65.0,
			Event:         event,
			Context: map[string]interface{}{
				"process":         key,
				"actual_parent":   event.ParentProcess,
				"expected_parent": existing.ParentProcess,
			},
		}
	}

	existing.Count++
	existing.LastSeen = event.Timestamp
	return nil
}

func (p *BehaviorProfiler) processNetworkEvent(profile *BehaviorProfile, event *BehaviorEvent) *Anomaly {
	profile.Stats.NetworkEvents++

	key := fmt.Sprintf("%s:%d", event.NetworkDest, event.NetworkPort)
	existing, known := profile.KnownDestinations[key]

	if profile.IsLearning {
		if !known {
			profile.KnownDestinations[key] = &NetworkProfile{
				Destination: event.NetworkDest,
				Port:        event.NetworkPort,
				Count:       1,
				LastSeen:    event.Timestamp,
			}
			profile.KnownPorts[event.NetworkPort]++
		} else {
			existing.Count++
			existing.LastSeen = event.Timestamp
		}
		return nil
	}

	// Detection mode
	if !known {
		// Check if at least the port is known
		_, portKnown := profile.KnownPorts[event.NetworkPort]

		severity := "high"
		score := 80.0
		if portKnown {
			severity = "medium"
			score = 60.0
		}

		return &Anomaly{
			Timestamp:     event.Timestamp,
			ContainerID:   event.ContainerID,
			ContainerName: event.ContainerName,
			Type:          "unknown_network_dest",
			Severity:      severity,
			Description:   fmt.Sprintf("Connection to unknown destination: %s", key),
			Score:         score,
			Event:         event,
			Context: map[string]interface{}{
				"destination":   event.NetworkDest,
				"port":          event.NetworkPort,
				"port_known":    portKnown,
				"known_dests":   len(profile.KnownDestinations),
			},
		}
	}

	existing.Count++
	existing.LastSeen = event.Timestamp
	return nil
}

func (p *BehaviorProfiler) processFileEvent(profile *BehaviorProfile, event *BehaviorEvent) *Anomaly {
	profile.Stats.FileEvents++

	key := event.FilePath
	existing, known := profile.KnownFilePaths[key]

	if profile.IsLearning {
		if !known {
			profile.KnownFilePaths[key] = &FileProfile{
				Path:      event.FilePath,
				Operation: event.FileOp,
				Count:     1,
				LastSeen:  event.Timestamp,
			}
		} else {
			existing.Count++
			existing.LastSeen = event.Timestamp
		}
		return nil
	}

	// Detection mode - check for sensitive file access
	sensitiveFiles := map[string]bool{
		"/etc/passwd":  true,
		"/etc/shadow":  true,
		"/etc/sudoers": true,
		"/.ssh/":       true,
		"/.aws/":       true,
	}

	for pattern := range sensitiveFiles {
		if containsPattern(key, pattern) && !known {
			return &Anomaly{
				Timestamp:     event.Timestamp,
				ContainerID:   event.ContainerID,
				ContainerName: event.ContainerName,
				Type:          "sensitive_file_access",
				Severity:      "critical",
				Description:   fmt.Sprintf("Access to sensitive file: %s", key),
				Score:         90.0,
				Event:         event,
				Context: map[string]interface{}{
					"file":      key,
					"operation": event.FileOp,
				},
			}
		}
	}

	if !known {
		return &Anomaly{
			Timestamp:     event.Timestamp,
			ContainerID:   event.ContainerID,
			ContainerName: event.ContainerName,
			Type:          "unknown_file_access",
			Severity:      "low",
			Description:   fmt.Sprintf("Access to unknown file: %s", key),
			Score:         40.0,
			Event:         event,
			Context: map[string]interface{}{
				"file":        key,
				"operation":   event.FileOp,
				"known_files": len(profile.KnownFilePaths),
			},
		}
	}

	existing.Count++
	existing.LastSeen = event.Timestamp
	return nil
}

func (p *BehaviorProfiler) processDNSEvent(profile *BehaviorProfile, event *BehaviorEvent) *Anomaly {
	profile.Stats.DNSEvents++

	domain := event.DNSQuery
	count, known := profile.KnownDNSQueries[domain]

	if profile.IsLearning {
		profile.KnownDNSQueries[domain] = count + 1
		return nil
	}

	// Detection mode - check for suspicious DNS patterns
	if !known {
		score := 50.0
		severity := "low"

		// Check for DGA-like domains (high entropy)
		if isDGALike(domain) {
			score = 85.0
			severity = "high"
		}

		// Check for known malicious TLDs
		if hasSuspiciousTLD(domain) {
			score = math.Max(score, 70.0)
			severity = "medium"
		}

		return &Anomaly{
			Timestamp:     event.Timestamp,
			ContainerID:   event.ContainerID,
			ContainerName: event.ContainerName,
			Type:          "unknown_dns_query",
			Severity:      severity,
			Description:   fmt.Sprintf("DNS query for unknown domain: %s", domain),
			Score:         score,
			Event:         event,
			Context: map[string]interface{}{
				"domain":        domain,
				"known_domains": len(profile.KnownDNSQueries),
			},
		}
	}

	profile.KnownDNSQueries[domain] = count + 1
	return nil
}

func (p *BehaviorProfiler) emitAnomaly(anomaly *Anomaly) {
	select {
	case p.anomalyChan <- anomaly:
	default:
		fmt.Printf("[Behavior] Anomaly channel full, dropping\n")
	}

	if p.onAnomaly != nil {
		go p.onAnomaly(anomaly)
	}
}

// GetProfile returns the profile for a container.
func (p *BehaviorProfiler) GetProfile(containerID string) *BehaviorProfile {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.profiles[containerID]
}

// GetAllProfiles returns all profiles.
func (p *BehaviorProfiler) GetAllProfiles() map[string]*BehaviorProfile {
	p.mu.RLock()
	defer p.mu.RUnlock()

	result := make(map[string]*BehaviorProfile)
	for k, v := range p.profiles {
		result[k] = v
	}
	return result
}

// Stats returns profiler statistics.
func (p *BehaviorProfiler) Stats() map[string]interface{} {
	p.mu.RLock()
	defer p.mu.RUnlock()

	learning := 0
	monitoring := 0
	totalProcesses := 0
	totalNetworkDests := 0

	for _, profile := range p.profiles {
		if profile.IsLearning {
			learning++
		} else {
			monitoring++
		}
		totalProcesses += len(profile.KnownProcesses)
		totalNetworkDests += len(profile.KnownDestinations)
	}

	return map[string]interface{}{
		"containers_learning":   learning,
		"containers_monitoring": monitoring,
		"total_profiles":        len(p.profiles),
		"total_known_processes": totalProcesses,
		"total_known_network":   totalNetworkDests,
		"anomaly_threshold":     p.anomalyThreshold,
		"learning_period":       p.learningPeriod.String(),
	}
}

// Helper functions

func containsPattern(s, pattern string) bool {
	return len(s) >= len(pattern) && (s == pattern ||
		(len(s) > len(pattern) && s[:len(pattern)] == pattern) ||
		(len(s) > len(pattern) && s[len(s)-len(pattern):] == pattern))
}

func isDGALike(domain string) bool {
	// Simple entropy check for DGA detection
	if len(domain) < 10 {
		return false
	}

	// Count consonants vs vowels ratio
	vowels := 0
	consonants := 0
	numbers := 0

	for _, c := range domain {
		switch c {
		case 'a', 'e', 'i', 'o', 'u':
			vowels++
		case '.', '-':
			// ignore
		case '0', '1', '2', '3', '4', '5', '6', '7', '8', '9':
			numbers++
		default:
			consonants++
		}
	}

	// DGA domains often have unusual ratios
	if consonants > 0 && float64(vowels)/float64(consonants) < 0.2 {
		return true
	}

	// Many numbers in domain name
	if numbers > 5 {
		return true
	}

	return false
}

func hasSuspiciousTLD(domain string) bool {
	suspiciousTLDs := []string{
		".tk", ".ml", ".ga", ".cf", ".gq", // Free TLDs often abused
		".top", ".xyz", ".work", ".click",
		".onion", // Tor
	}

	for _, tld := range suspiciousTLDs {
		if len(domain) > len(tld) && domain[len(domain)-len(tld):] == tld {
			return true
		}
	}

	return false
}
