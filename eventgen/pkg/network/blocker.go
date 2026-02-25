package network

import (
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/qualys/eventgen/pkg/qualys"
)

// ThreatIndicator represents an extracted network IOC.
type ThreatIndicator struct {
	Type      string    // "ip", "cidr", "domain", "port"
	Value     string
	Severity  string
	Category  string
	Source    string    // CDR event UUID
	FirstSeen time.Time
	LastSeen  time.Time
	HitCount  int
}

// NetworkBlocklist maintains extracted IOCs from CDR events.
type NetworkBlocklist struct {
	IPs     map[string]*ThreatIndicator
	CIDRs   map[string]*ThreatIndicator
	Domains map[string]*ThreatIndicator
	Ports   map[string]*ThreatIndicator
}

// NewNetworkBlocklist creates an empty blocklist.
func NewNetworkBlocklist() *NetworkBlocklist {
	return &NetworkBlocklist{
		IPs:     make(map[string]*ThreatIndicator),
		CIDRs:   make(map[string]*ThreatIndicator),
		Domains: make(map[string]*ThreatIndicator),
		Ports:   make(map[string]*ThreatIndicator),
	}
}

// ExtractFromEvents parses CDR events and extracts network IOCs.
func (b *NetworkBlocklist) ExtractFromEvents(events []qualys.CDREvent) {
	for _, event := range events {
		b.extractFromEvent(event)
	}
}

func (b *NetworkBlocklist) extractFromEvent(event qualys.CDREvent) {
	now := time.Now()
	category := event.EventType
	severity := mapSeverity(event.Severity)

	// Extract destination IP
	if destIP := event.RawData["destinationIp"]; destIP != nil {
		if ip, ok := destIP.(string); ok && isValidIP(ip) && !isPrivateIP(ip) {
			b.addIP(ip, severity, category, event.EventID, now)
		}
	}

	// Extract triggered resource (often contains IP)
	if triggered := event.RawData["triggeredResource"]; triggered != nil {
		if val, ok := triggered.(string); ok {
			if isValidIP(val) && !isPrivateIP(val) {
				b.addIP(val, severity, category, event.EventID, now)
			}
		}
	}

	// Extract affected resource
	if affected := event.RawData["affectedResource"]; affected != nil {
		if val, ok := affected.(string); ok {
			if isValidIP(val) && !isPrivateIP(val) {
				b.addIP(val, severity, category, event.EventID, now)
			}
		}
	}

	// Extract destination port for suspicious connections
	if destPort := event.RawData["destinationPort"]; destPort != nil {
		if port, ok := destPort.(float64); ok {
			portStr := fmt.Sprintf("%d", int(port))
			if isSuspiciousPort(int(port)) {
				b.addPort(portStr, severity, category, event.EventID, now)
			}
		}
	}

	// Extract domain from network info
	if netInfo := event.RawData["networkInformation"]; netInfo != nil {
		if info, ok := netInfo.(map[string]interface{}); ok {
			if domain := info["domain"]; domain != nil {
				if d, ok := domain.(string); ok && isValidDomain(d) {
					b.addDomain(d, severity, category, event.EventID, now)
				}
			}
		}
	}
}

func (b *NetworkBlocklist) addIP(ip, severity, category, source string, now time.Time) {
	if existing, ok := b.IPs[ip]; ok {
		existing.LastSeen = now
		existing.HitCount++
	} else {
		b.IPs[ip] = &ThreatIndicator{
			Type:      "ip",
			Value:     ip,
			Severity:  severity,
			Category:  category,
			Source:    source,
			FirstSeen: now,
			LastSeen:  now,
			HitCount:  1,
		}
	}
}

func (b *NetworkBlocklist) addPort(port, severity, category, source string, now time.Time) {
	if existing, ok := b.Ports[port]; ok {
		existing.LastSeen = now
		existing.HitCount++
	} else {
		b.Ports[port] = &ThreatIndicator{
			Type:      "port",
			Value:     port,
			Severity:  severity,
			Category:  category,
			Source:    source,
			FirstSeen: now,
			LastSeen:  now,
			HitCount:  1,
		}
	}
}

func (b *NetworkBlocklist) addDomain(domain, severity, category, source string, now time.Time) {
	if existing, ok := b.Domains[domain]; ok {
		existing.LastSeen = now
		existing.HitCount++
	} else {
		b.Domains[domain] = &ThreatIndicator{
			Type:      "domain",
			Value:     domain,
			Severity:  severity,
			Category:  category,
			Source:    source,
			FirstSeen: now,
			LastSeen:  now,
			HitCount:  1,
		}
	}
}

// GenerateNetworkPolicy creates a Qualys NetworkPolicy from the blocklist.
func (b *NetworkBlocklist) GenerateNetworkPolicy(name, namespace string) map[string]interface{} {
	// Collect IPs for CIDR deny rules
	var denyIPs []string
	for ip := range b.IPs {
		denyIPs = append(denyIPs, ip+"/32")
	}

	// Collect domains for FQDN deny
	var denyDomains []map[string]string
	for domain := range b.Domains {
		denyDomains = append(denyDomains, map[string]string{
			"matchName": domain,
		})
	}

	// Collect ports
	var denyPorts []map[string]string
	for port := range b.Ports {
		denyPorts = append(denyPorts, map[string]string{
			"port":     port,
			"protocol": "TCP",
		})
	}

	policy := map[string]interface{}{
		"apiVersion": "cilium.io/v2",
		"kind":       "CiliumNetworkPolicy",
		"metadata": map[string]interface{}{
			"name":      name,
			"namespace": namespace,
			"labels": map[string]string{
				"generated-by":                "qualys-cdr-operator",
				"qualys.com/auto-generated":   "true",
				"policy.qualys.com/type":      "dynamic-blocklist",
			},
			"annotations": map[string]string{
				"description":   "Auto-generated from CDR findings",
				"blocked-ips":   fmt.Sprintf("%d", len(denyIPs)),
				"blocked-domains": fmt.Sprintf("%d", len(denyDomains)),
				"blocked-ports": fmt.Sprintf("%d", len(denyPorts)),
				"generated-at":  time.Now().UTC().Format(time.RFC3339),
			},
		},
		"spec": map[string]interface{}{
			"endpointSelector": map[string]interface{}{},
			"egressDeny":       []map[string]interface{}{},
		},
	}

	egressDeny := []map[string]interface{}{}

	// Add IP-based deny rules
	if len(denyIPs) > 0 {
		egressDeny = append(egressDeny, map[string]interface{}{
			"toCIDR": denyIPs,
		})
	}

	// Add domain-based deny rules
	if len(denyDomains) > 0 {
		egressDeny = append(egressDeny, map[string]interface{}{
			"toFQDNs": denyDomains,
		})
	}

	// Add port-based deny rules
	if len(denyPorts) > 0 {
		egressDeny = append(egressDeny, map[string]interface{}{
			"toPorts": []map[string]interface{}{
				{"ports": denyPorts},
			},
		})
	}

	policy["spec"].(map[string]interface{})["egressDeny"] = egressDeny

	return policy
}

// GenerateTracingPolicy creates a Qualys TracingPolicy for network blocking.
func (b *NetworkBlocklist) GenerateTracingPolicy(name string, action string) map[string]interface{} {
	var ipValues []string
	for ip := range b.IPs {
		ipValues = append(ipValues, ip)
	}

	var portValues []string
	for port := range b.Ports {
		portValues = append(portValues, port)
	}

	selectors := []map[string]interface{}{}

	// Block connections to malicious IPs
	if len(ipValues) > 0 {
		selectors = append(selectors, map[string]interface{}{
			"matchArgs": []map[string]interface{}{
				{
					"index":    1,
					"operator": "SAddr",
					"values":   ipValues,
				},
			},
			"matchActions": []map[string]interface{}{
				{"action": action},
			},
		})
	}

	// Block connections to suspicious ports
	if len(portValues) > 0 {
		selectors = append(selectors, map[string]interface{}{
			"matchArgs": []map[string]interface{}{
				{
					"index":    1,
					"operator": "DPort",
					"values":   portValues,
				},
			},
			"matchActions": []map[string]interface{}{
				{"action": action},
			},
		})
	}

	return map[string]interface{}{
		"apiVersion": "cilium.io/v1alpha1",
		"kind":       "TracingPolicy",
		"metadata": map[string]interface{}{
			"name": name,
			"labels": map[string]string{
				"generated-by":              "qualys-cdr-operator",
				"qualys.com/auto-generated": "true",
				"policy.qualys.com/type":    "dynamic-blocklist",
			},
			"annotations": map[string]string{
				"blocked-ips":   fmt.Sprintf("%d", len(ipValues)),
				"blocked-ports": fmt.Sprintf("%d", len(portValues)),
				"generated-at":  time.Now().UTC().Format(time.RFC3339),
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
}

// Stats returns blocklist statistics.
func (b *NetworkBlocklist) Stats() map[string]int {
	return map[string]int{
		"ips":     len(b.IPs),
		"cidrs":   len(b.CIDRs),
		"domains": len(b.Domains),
		"ports":   len(b.Ports),
	}
}

func mapSeverity(severity int) string {
	switch severity {
	case 4, 5:
		return "CRITICAL"
	case 3:
		return "HIGH"
	case 2:
		return "MEDIUM"
	default:
		return "LOW"
	}
}

func isValidIP(s string) bool {
	return net.ParseIP(s) != nil
}

func isPrivateIP(s string) bool {
	ip := net.ParseIP(s)
	if ip == nil {
		return false
	}
	privateBlocks := []string{
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
		"127.0.0.0/8",
		"169.254.0.0/16",
	}
	for _, block := range privateBlocks {
		_, cidr, _ := net.ParseCIDR(block)
		if cidr.Contains(ip) {
			return true
		}
	}
	return false
}

func isValidDomain(s string) bool {
	if len(s) < 3 || len(s) > 255 {
		return false
	}
	if strings.Contains(s, " ") {
		return false
	}
	if !strings.Contains(s, ".") {
		return false
	}
	return true
}

func isSuspiciousPort(port int) bool {
	suspicious := map[int]bool{
		4444:  true, // Metasploit
		5555:  true, // Various backdoors
		6666:  true, // IRC/backdoors
		6667:  true, // IRC
		8443:  true, // Alt HTTPS (often C2)
		9001:  true, // Tor
		9050:  true, // Tor SOCKS
		31337: true, // Elite/backdoors
		12345: true, // NetBus
		27374: true, // SubSeven
		1337:  true, // Elite
	}
	return suspicious[port]
}
