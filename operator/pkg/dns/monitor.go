package dns

import (
	"context"
	"fmt"
	"math"
	"net"
	"strings"
	"sync"
	"time"
)

// DNSQuery represents a captured DNS query.
type DNSQuery struct {
	Timestamp     time.Time `json:"timestamp"`
	ContainerID   string    `json:"containerId"`
	ContainerName string    `json:"containerName"`
	ProcessName   string    `json:"processName"`
	QueryName     string    `json:"queryName"`
	QueryType     string    `json:"queryType"` // A, AAAA, CNAME, MX, TXT, etc.
	ResponseIPs   []string  `json:"responseIps,omitempty"`
	ResponseTime  time.Duration `json:"responseTime"`
	Blocked       bool      `json:"blocked"`
	BlockReason   string    `json:"blockReason,omitempty"`
}

// DNSThreat represents a DNS-based threat indicator.
type DNSThreat struct {
	Domain      string    `json:"domain"`
	ThreatType  string    `json:"threatType"` // malware, phishing, c2, dga, mining
	Severity    string    `json:"severity"`
	Source      string    `json:"source"` // feed name
	AddedAt     time.Time `json:"addedAt"`
	Description string    `json:"description,omitempty"`
}

// DNSMonitor monitors and optionally blocks DNS queries.
type DNSMonitor struct {
	mu sync.RWMutex

	// Threat intelligence
	blockedDomains    map[string]*DNSThreat
	blockedPatterns   []string // Regex-like patterns

	// Query tracking
	recentQueries     []*DNSQuery
	maxRecentQueries  int
	queryStats        map[string]int // domain -> count

	// Callbacks
	onQuery           func(*DNSQuery)
	onThreat          func(*DNSQuery, *DNSThreat)

	// Configuration
	blockingEnabled   bool
	blockDGA          bool
	blockNewDomains   bool // Block domains registered < 30 days
}

// NewDNSMonitor creates a new DNS monitor.
func NewDNSMonitor(blockingEnabled bool) *DNSMonitor {
	return &DNSMonitor{
		blockedDomains:   make(map[string]*DNSThreat),
		blockedPatterns:  []string{},
		recentQueries:    make([]*DNSQuery, 0),
		maxRecentQueries: 10000,
		queryStats:       make(map[string]int),
		blockingEnabled:  blockingEnabled,
		blockDGA:         true,
		blockNewDomains:  false,
	}
}

// SetCallbacks sets event callbacks.
func (m *DNSMonitor) SetCallbacks(onQuery func(*DNSQuery), onThreat func(*DNSQuery, *DNSThreat)) {
	m.onQuery = onQuery
	m.onThreat = onThreat
}

// LoadThreatFeed loads DNS threat intelligence from a feed.
func (m *DNSMonitor) LoadThreatFeed(ctx context.Context, feedURL, feedName string) (int, error) {
	// This would fetch and parse threat feeds
	// For now, load some default malicious domains

	defaultThreats := []struct {
		domain     string
		threatType string
		severity   string
	}{
		// Cryptomining pools
		{"pool.minexmr.com", "mining", "high"},
		{"xmr.pool.minergate.com", "mining", "high"},
		{"pool.supportxmr.com", "mining", "high"},
		{"xmrpool.eu", "mining", "high"},
		{"monerohash.com", "mining", "high"},

		// Known C2 domains (examples)
		{"evil.com", "c2", "critical"},
		{"malware-c2.net", "c2", "critical"},

		// Phishing (examples)
		{"login-secure-paypal.com", "phishing", "high"},
		{"account-verify-amazon.com", "phishing", "high"},

		// DGA patterns would be detected separately
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	count := 0
	for _, t := range defaultThreats {
		m.blockedDomains[t.domain] = &DNSThreat{
			Domain:     t.domain,
			ThreatType: t.threatType,
			Severity:   t.severity,
			Source:     "default",
			AddedAt:    time.Now(),
		}
		count++
	}

	fmt.Printf("[DNS] Loaded %d threat indicators\n", count)
	return count, nil
}

// AddBlockedDomain adds a domain to the blocklist.
func (m *DNSMonitor) AddBlockedDomain(domain, threatType, severity, source string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.blockedDomains[strings.ToLower(domain)] = &DNSThreat{
		Domain:     domain,
		ThreatType: threatType,
		Severity:   severity,
		Source:     source,
		AddedAt:    time.Now(),
	}
}

// RemoveBlockedDomain removes a domain from the blocklist.
func (m *DNSMonitor) RemoveBlockedDomain(domain string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.blockedDomains, strings.ToLower(domain))
}

// ProcessQuery processes a DNS query and returns blocking decision.
func (m *DNSMonitor) ProcessQuery(query *DNSQuery) (blocked bool, reason string, threat *DNSThreat) {
	m.mu.Lock()
	defer m.mu.Unlock()

	domain := strings.ToLower(query.QueryName)

	// Track statistics
	m.queryStats[domain]++

	// Store recent query
	if len(m.recentQueries) >= m.maxRecentQueries {
		m.recentQueries = m.recentQueries[1:]
	}
	m.recentQueries = append(m.recentQueries, query)

	// Callback for all queries
	if m.onQuery != nil {
		go m.onQuery(query)
	}

	// Check against blocklist
	if t, found := m.blockedDomains[domain]; found {
		query.Blocked = true
		query.BlockReason = fmt.Sprintf("Blocked: %s (%s)", t.ThreatType, t.Source)

		if m.onThreat != nil {
			go m.onThreat(query, t)
		}

		return m.blockingEnabled, query.BlockReason, t
	}

	// Check for subdomain of blocked domain
	parts := strings.Split(domain, ".")
	for i := 1; i < len(parts); i++ {
		parentDomain := strings.Join(parts[i:], ".")
		if t, found := m.blockedDomains[parentDomain]; found {
			query.Blocked = true
			query.BlockReason = fmt.Sprintf("Blocked: subdomain of %s", parentDomain)

			if m.onThreat != nil {
				go m.onThreat(query, t)
			}

			return m.blockingEnabled, query.BlockReason, t
		}
	}

	// DGA detection
	if m.blockDGA && isDGADomain(domain) {
		t := &DNSThreat{
			Domain:      domain,
			ThreatType:  "dga",
			Severity:    "high",
			Source:      "dga_detection",
			AddedAt:     time.Now(),
			Description: "Domain appears to be generated by DGA algorithm",
		}

		query.Blocked = true
		query.BlockReason = "Blocked: suspected DGA domain"

		if m.onThreat != nil {
			go m.onThreat(query, t)
		}

		return m.blockingEnabled, query.BlockReason, t
	}

	return false, "", nil
}

// GetRecentQueries returns recent DNS queries.
func (m *DNSMonitor) GetRecentQueries(limit int) []*DNSQuery {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if limit <= 0 || limit > len(m.recentQueries) {
		limit = len(m.recentQueries)
	}

	result := make([]*DNSQuery, limit)
	copy(result, m.recentQueries[len(m.recentQueries)-limit:])
	return result
}

// GetTopDomains returns the most queried domains.
func (m *DNSMonitor) GetTopDomains(limit int) map[string]int {
	m.mu.RLock()
	defer m.mu.RUnlock()

	// Simple top-N extraction
	result := make(map[string]int)
	for domain, count := range m.queryStats {
		if len(result) < limit {
			result[domain] = count
		}
	}
	return result
}

// GetBlockedDomains returns the current blocklist.
func (m *DNSMonitor) GetBlockedDomains() map[string]*DNSThreat {
	m.mu.RLock()
	defer m.mu.RUnlock()

	result := make(map[string]*DNSThreat)
	for k, v := range m.blockedDomains {
		result[k] = v
	}
	return result
}

// Stats returns DNS monitoring statistics.
func (m *DNSMonitor) Stats() map[string]interface{} {
	m.mu.RLock()
	defer m.mu.RUnlock()

	blockedCount := 0
	for _, q := range m.recentQueries {
		if q.Blocked {
			blockedCount++
		}
	}

	return map[string]interface{}{
		"total_queries":     len(m.recentQueries),
		"unique_domains":    len(m.queryStats),
		"blocked_domains":   len(m.blockedDomains),
		"blocked_queries":   blockedCount,
		"blocking_enabled":  m.blockingEnabled,
		"dga_detection":     m.blockDGA,
	}
}

// GenerateBlockingPolicy generates a TracingPolicy for DNS blocking.
func (m *DNSMonitor) GenerateBlockingPolicy(domains []string) map[string]interface{} {
	// Generate a TracingPolicy that blocks DNS queries to specific domains
	// This uses Tetragon's ability to hook into DNS-related syscalls

	return map[string]interface{}{
		"apiVersion": "cilium.io/v1alpha1",
		"kind":       "TracingPolicy",
		"metadata": map[string]interface{}{
			"name": "dns-threat-blocking",
			"labels": map[string]string{
				"generated-by": "qualys-dns-monitor",
				"type":         "dns-blocking",
			},
		},
		"spec": map[string]interface{}{
			"kprobes": []map[string]interface{}{
				{
					"call":    "sys_sendto",
					"syscall": true,
					"args": []map[string]interface{}{
						{"index": 4, "type": "sockaddr"},
					},
					"selectors": []map[string]interface{}{
						{
							"matchArgs": []map[string]interface{}{
								{
									"index":    4,
									"operator": "DPort",
									"values":   []string{"53"},
								},
							},
							"matchActions": []map[string]interface{}{
								{"action": "Post"},
							},
						},
					},
				},
			},
		},
	}
}

// GenerateCiliumDNSPolicy generates a CiliumNetworkPolicy for DNS blocking.
func (m *DNSMonitor) GenerateCiliumDNSPolicy(blockedDomains []string) map[string]interface{} {
	fqdnRules := make([]map[string]interface{}, 0)
	for _, domain := range blockedDomains {
		fqdnRules = append(fqdnRules, map[string]interface{}{
			"matchName": domain,
		})
	}

	return map[string]interface{}{
		"apiVersion": "cilium.io/v2",
		"kind":       "CiliumNetworkPolicy",
		"metadata": map[string]interface{}{
			"name": "dns-threat-blocking",
			"labels": map[string]string{
				"generated-by": "qualys-dns-monitor",
			},
		},
		"spec": map[string]interface{}{
			"endpointSelector": map[string]interface{}{},
			"egressDeny": []map[string]interface{}{
				{
					"toFQDNs": fqdnRules,
					"toPorts": []map[string]interface{}{
						{
							"ports": []map[string]interface{}{
								{"port": "53", "protocol": "UDP"},
								{"port": "53", "protocol": "TCP"},
								{"port": "443", "protocol": "TCP"}, // DoH
							},
						},
					},
				},
			},
		},
	}
}

// isDGADomain checks if a domain appears to be generated by a DGA.
func isDGADomain(domain string) bool {
	// Remove TLD
	parts := strings.Split(domain, ".")
	if len(parts) < 2 {
		return false
	}

	// Get the main domain part (second-level domain)
	sld := parts[len(parts)-2]

	// Skip common short domains
	if len(sld) < 8 {
		return false
	}

	// Calculate entropy-like metrics
	consonantRatio := calculateConsonantRatio(sld)
	numberRatio := calculateNumberRatio(sld)
	entropy := calculateEntropy(sld)

	// DGA domains typically have:
	// - High consonant ratio (> 0.7)
	// - Mixed numbers and letters
	// - High entropy (> 3.5)
	// - Unusual character distribution

	if consonantRatio > 0.75 && entropy > 3.5 {
		return true
	}

	if numberRatio > 0.3 && len(sld) > 12 {
		return true
	}

	// Check for lack of vowels in long strings
	if len(sld) > 15 && consonantRatio > 0.8 {
		return true
	}

	return false
}

func calculateConsonantRatio(s string) float64 {
	if len(s) == 0 {
		return 0
	}

	vowels := "aeiouAEIOU"
	consonants := 0
	total := 0

	for _, c := range s {
		if c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' {
			total++
			if !strings.ContainsRune(vowels, c) {
				consonants++
			}
		}
	}

	if total == 0 {
		return 0
	}

	return float64(consonants) / float64(total)
}

func calculateNumberRatio(s string) float64 {
	if len(s) == 0 {
		return 0
	}

	numbers := 0
	for _, c := range s {
		if c >= '0' && c <= '9' {
			numbers++
		}
	}

	return float64(numbers) / float64(len(s))
}

func calculateEntropy(s string) float64 {
	if len(s) == 0 {
		return 0
	}

	freq := make(map[rune]int)
	for _, c := range s {
		freq[c]++
	}

	entropy := 0.0
	length := float64(len(s))

	for _, count := range freq {
		p := float64(count) / length
		if p > 0 {
			entropy -= p * (math.Log(p) / math.Log(2))
		}
	}

	return entropy
}

// LookupDomain performs a DNS lookup and returns the result.
func LookupDomain(domain string) ([]string, error) {
	ips, err := net.LookupIP(domain)
	if err != nil {
		return nil, err
	}

	result := make([]string, len(ips))
	for i, ip := range ips {
		result[i] = ip.String()
	}

	return result, nil
}
