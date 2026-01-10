package reputation

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// ReputationScore represents an IP's threat score.
type ReputationScore struct {
	IP              string
	Score           int       // 0-100 (100 = definitely malicious)
	Category        string    // "c2", "scanner", "spam", "tor", "proxy", "botnet"
	Source          string    // Which feed flagged it
	LastChecked     time.Time
	BlockRecommended bool
}

// ReputationChecker checks IPs against multiple threat feeds.
type ReputationChecker struct {
	httpClient    *http.Client
	abuseIPDBKey  string
	cache         map[string]*ReputationScore
	cacheMu       sync.RWMutex
	cacheTTL      time.Duration

	// Known bad IPs from threat feeds
	knownBadIPs   map[string]*ReputationScore
	feedsMu       sync.RWMutex
}

// NewReputationChecker creates a new checker.
func NewReputationChecker(abuseIPDBKey string) *ReputationChecker {
	return &ReputationChecker{
		httpClient:   &http.Client{Timeout: 10 * time.Second},
		abuseIPDBKey: abuseIPDBKey,
		cache:        make(map[string]*ReputationScore),
		cacheTTL:     1 * time.Hour,
		knownBadIPs:  make(map[string]*ReputationScore),
	}
}

// LoadThreatFeeds downloads and parses public threat intelligence feeds.
func (r *ReputationChecker) LoadThreatFeeds(ctx context.Context) error {
	feeds := []struct {
		name     string
		url      string
		category string
	}{
		{
			name:     "feodo-c2",
			url:      "https://feodotracker.abuse.ch/downloads/ipblocklist.txt",
			category: "c2",
		},
		{
			name:     "tor-exit",
			url:      "https://check.torproject.org/torbulkexitlist",
			category: "tor",
		},
		{
			name:     "emerging-threats",
			url:      "https://rules.emergingthreats.net/blockrules/compromised-ips.txt",
			category: "compromised",
		},
		{
			name:     "blocklist-de",
			url:      "https://lists.blocklist.de/lists/all.txt",
			category: "attacker",
		},
		{
			name:     "cinsscore",
			url:      "https://cinsscore.com/list/ci-badguys.txt",
			category: "scanner",
		},
	}

	var wg sync.WaitGroup
	errors := make(chan error, len(feeds))

	for _, feed := range feeds {
		wg.Add(1)
		go func(f struct {
			name     string
			url      string
			category string
		}) {
			defer wg.Done()
			if err := r.loadFeed(ctx, f.name, f.url, f.category); err != nil {
				errors <- fmt.Errorf("%s: %w", f.name, err)
			}
		}(feed)
	}

	wg.Wait()
	close(errors)

	// Collect errors but don't fail completely
	var errs []string
	for err := range errors {
		errs = append(errs, err.Error())
	}

	if len(errs) > 0 {
		return fmt.Errorf("some feeds failed: %s", strings.Join(errs, "; "))
	}

	return nil
}

func (r *ReputationChecker) loadFeed(ctx context.Context, name, url, category string) error {
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return err
	}

	resp, err := r.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("HTTP %d", resp.StatusCode)
	}

	scanner := bufio.NewScanner(resp.Body)
	count := 0

	r.feedsMu.Lock()
	defer r.feedsMu.Unlock()

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		// Skip comments and empty lines
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}

		// Extract IP (some feeds have additional data)
		parts := strings.Fields(line)
		if len(parts) == 0 {
			continue
		}
		ip := parts[0]

		// Validate IP
		if net.ParseIP(ip) == nil {
			continue
		}

		r.knownBadIPs[ip] = &ReputationScore{
			IP:               ip,
			Score:            85, // High score for known bad
			Category:         category,
			Source:           name,
			LastChecked:      time.Now(),
			BlockRecommended: true,
		}
		count++
	}

	fmt.Printf("Loaded %d IPs from %s\n", count, name)
	return scanner.Err()
}

// CheckIP returns the reputation score for an IP.
func (r *ReputationChecker) CheckIP(ctx context.Context, ip string) (*ReputationScore, error) {
	// Check cache first
	r.cacheMu.RLock()
	if cached, ok := r.cache[ip]; ok {
		if time.Since(cached.LastChecked) < r.cacheTTL {
			r.cacheMu.RUnlock()
			return cached, nil
		}
	}
	r.cacheMu.RUnlock()

	// Check known bad IPs from feeds
	r.feedsMu.RLock()
	if known, ok := r.knownBadIPs[ip]; ok {
		r.feedsMu.RUnlock()
		r.cacheResult(known)
		return known, nil
	}
	r.feedsMu.RUnlock()

	// Check AbuseIPDB if API key is available
	if r.abuseIPDBKey != "" {
		score, err := r.checkAbuseIPDB(ctx, ip)
		if err == nil {
			r.cacheResult(score)
			return score, nil
		}
	}

	// Default: unknown
	score := &ReputationScore{
		IP:               ip,
		Score:            0,
		Category:         "unknown",
		Source:           "none",
		LastChecked:      time.Now(),
		BlockRecommended: false,
	}
	r.cacheResult(score)
	return score, nil
}

func (r *ReputationChecker) checkAbuseIPDB(ctx context.Context, ip string) (*ReputationScore, error) {
	url := fmt.Sprintf("https://api.abuseipdb.com/api/v2/check?ipAddress=%s&maxAgeInDays=90", ip)

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Key", r.abuseIPDBKey)
	req.Header.Set("Accept", "application/json")

	resp, err := r.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var result struct {
		Data struct {
			AbuseConfidenceScore int    `json:"abuseConfidenceScore"`
			UsageType            string `json:"usageType"`
			TotalReports         int    `json:"totalReports"`
		} `json:"data"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}

	return &ReputationScore{
		IP:               ip,
		Score:            result.Data.AbuseConfidenceScore,
		Category:         result.Data.UsageType,
		Source:           "abuseipdb",
		LastChecked:      time.Now(),
		BlockRecommended: result.Data.AbuseConfidenceScore >= 50,
	}, nil
}

func (r *ReputationChecker) cacheResult(score *ReputationScore) {
	r.cacheMu.Lock()
	defer r.cacheMu.Unlock()
	r.cache[score.IP] = score
}

// CheckBatch checks multiple IPs and returns those that should be blocked.
func (r *ReputationChecker) CheckBatch(ctx context.Context, ips []string, threshold int) []*ReputationScore {
	var blocked []*ReputationScore
	var mu sync.Mutex
	var wg sync.WaitGroup

	// Limit concurrency
	sem := make(chan struct{}, 10)

	for _, ip := range ips {
		wg.Add(1)
		go func(ip string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			score, err := r.CheckIP(ctx, ip)
			if err != nil {
				return
			}

			if score.Score >= threshold || score.BlockRecommended {
				mu.Lock()
				blocked = append(blocked, score)
				mu.Unlock()
			}
		}(ip)
	}

	wg.Wait()
	return blocked
}

// GetAllKnownBad returns all IPs from threat feeds.
func (r *ReputationChecker) GetAllKnownBad() map[string]*ReputationScore {
	r.feedsMu.RLock()
	defer r.feedsMu.RUnlock()

	result := make(map[string]*ReputationScore, len(r.knownBadIPs))
	for k, v := range r.knownBadIPs {
		result[k] = v
	}
	return result
}

// Stats returns statistics about loaded threat intel.
func (r *ReputationChecker) Stats() map[string]int {
	r.feedsMu.RLock()
	defer r.feedsMu.RUnlock()

	categories := make(map[string]int)
	for _, score := range r.knownBadIPs {
		categories[score.Category]++
	}

	stats := map[string]int{
		"total_known_bad": len(r.knownBadIPs),
		"cache_size":      len(r.cache),
	}
	for cat, count := range categories {
		stats["category_"+cat] = count
	}
	return stats
}

// GenerateBlocklistPolicy creates a policy from all known bad IPs.
func (r *ReputationChecker) GenerateBlocklistPolicy(name string, action string) map[string]interface{} {
	r.feedsMu.RLock()
	defer r.feedsMu.RUnlock()

	var ips []string
	for ip := range r.knownBadIPs {
		ips = append(ips, ip)
	}

	// Limit to first 1000 IPs to avoid policy size limits
	if len(ips) > 1000 {
		ips = ips[:1000]
	}

	return map[string]interface{}{
		"apiVersion": "cilium.io/v1alpha1",
		"kind":       "TracingPolicy",
		"metadata": map[string]interface{}{
			"name": name,
			"labels": map[string]string{
				"generated-by":           "qualys-cdr-operator",
				"policy.qualys.com/type": "threat-intel-blocklist",
			},
			"annotations": map[string]string{
				"blocked-ips":  fmt.Sprintf("%d", len(ips)),
				"generated-at": time.Now().UTC().Format(time.RFC3339),
				"sources":      "feodo,tor,emerging-threats,blocklist-de,cinsscore",
			},
		},
		"spec": map[string]interface{}{
			"kprobes": []map[string]interface{}{
				{
					"call":    "sys_connect",
					"syscall": true,
					"args":    []map[string]interface{}{{"index": 1, "type": "sockaddr"}},
					"selectors": []map[string]interface{}{
						{
							"matchArgs": []map[string]interface{}{
								{
									"index":    1,
									"operator": "SAddr",
									"values":   ips,
								},
							},
							"matchActions": []map[string]interface{}{
								{"action": action},
							},
						},
					},
				},
			},
		},
	}
}
