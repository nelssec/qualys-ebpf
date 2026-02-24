package vuln

import (
	"strings"

	"github.com/qualys/eventgen/pkg/qualys"
)

type CorrelatorConfig struct {
	ContainerMatchConfidence float64
	BinaryMatchConfidence    float64
	MITREOverlapConfidence   float64
	CVESignatureConfidence   float64
	MinConfidenceThreshold   float64
}

func DefaultCorrelatorConfig() *CorrelatorConfig {
	return &CorrelatorConfig{
		ContainerMatchConfidence: 0.9,
		BinaryMatchConfidence:    0.95,
		MITREOverlapConfidence:   0.7,
		CVESignatureConfidence:   1.0,
		MinConfidenceThreshold:   0.5,
	}
}

var CVEExploitSignatures = map[string]struct {
	ProcessPaths  []string
	ProcessNames  []string
	Syscalls      []string
	MITRE         []string
	Ports         []int
}{
	"CVE-2024-21626": {
		ProcessPaths: []string{"/proc/self/fd"},
		Syscalls:     []string{"sys_setns", "sys_unshare"},
		MITRE:        []string{"T1611"},
	},
	"CVE-2023-44487": {
		Ports: []int{80, 443, 8080, 8443},
		MITRE: []string{"T1499"},
	},
	"CVE-2023-38545": {
		ProcessNames: []string{"curl"},
		MITRE:        []string{"T1071"},
	},
	"CVE-2024-3094": {
		ProcessNames: []string{"sshd"},
		ProcessPaths: []string{"/usr/sbin/sshd"},
		MITRE:        []string{"T1059"},
	},
	"CVE-2023-4911": {
		ProcessPaths: []string{"/lib/x86_64-linux-gnu/libc.so"},
		MITRE:        []string{"T1068"},
	},
}

type Correlator struct {
	config *CorrelatorConfig
}

func NewCorrelator(config *CorrelatorConfig) *Correlator {
	if config == nil {
		config = DefaultCorrelatorConfig()
	}
	return &Correlator{config: config}
}

func (c *Correlator) Correlate(vulns []*Vulnerability, events []qualys.CDREvent) []*Correlation {
	vulnsByContainer := c.groupByContainer(vulns)
	vulnsByBinary := c.groupByBinary(vulns)
	vulnsByTechnique := c.groupByTechnique(vulns)
	vulnsByCVE := make(map[string]*Vulnerability)
	for _, v := range vulns {
		if v.CVEID != "" {
			vulnsByCVE[v.CVEID] = v
		}
	}

	correlations := make(map[string]*Correlation)

	for _, event := range events {
		matches := c.findMatches(event, vulnsByContainer, vulnsByBinary, vulnsByTechnique, vulnsByCVE)

		for _, match := range matches {
			if match.Confidence < c.config.MinConfidenceThreshold {
				continue
			}

			key := match.Vulnerability.VulnID + ":" + match.Vulnerability.ImageID
			if existing, ok := correlations[key]; ok {
				existing.Events = append(existing.Events, event)
				if match.Confidence > existing.Confidence {
					existing.Confidence = match.Confidence
					existing.MatchedBy = match.MatchedBy
				}
			} else {
				match.Events = []qualys.CDREvent{event}
				correlations[key] = match
			}
		}
	}

	result := make([]*Correlation, 0, len(correlations))
	for _, corr := range correlations {
		corr.CombinedRiskScore = corr.CalculateCombinedRisk()
		result = append(result, corr)
	}

	return result
}

type matchResult struct {
	Vulnerability *Vulnerability
	Confidence    float64
	MatchedBy     string
}

func (c *Correlator) findMatches(
	event qualys.CDREvent,
	vulnsByContainer map[string][]*Vulnerability,
	vulnsByBinary map[string][]*Vulnerability,
	vulnsByTechnique map[string][]*Vulnerability,
	vulnsByCVE map[string]*Vulnerability,
) []*Correlation {
	var matches []*Correlation
	seen := make(map[string]bool)

	if event.ContainerID != "" {
		if vulns, ok := vulnsByContainer[event.ContainerID]; ok {
			for _, v := range vulns {
				key := v.VulnID + ":" + v.ImageID
				if !seen[key] {
					seen[key] = true
					matches = append(matches, &Correlation{
						Vulnerability: v,
						Confidence:    c.config.ContainerMatchConfidence,
						MatchedBy:     "container_match",
					})
				}
			}
		}
	}

	processPath := event.ProcessPath
	if processPath != "" {
		if vulns, ok := vulnsByBinary[processPath]; ok {
			for _, v := range vulns {
				key := v.VulnID + ":" + v.ImageID
				if !seen[key] {
					seen[key] = true
					matches = append(matches, &Correlation{
						Vulnerability: v,
						Confidence:    c.config.BinaryMatchConfidence,
						MatchedBy:     "process_binary",
					})
				}
			}
		}
	}

	for _, technique := range event.MITRETechniques {
		if vulns, ok := vulnsByTechnique[technique]; ok {
			for _, v := range vulns {
				key := v.VulnID + ":" + v.ImageID
				if !seen[key] {
					seen[key] = true
					matches = append(matches, &Correlation{
						Vulnerability: v,
						Confidence:    c.config.MITREOverlapConfidence,
						MatchedBy:     "mitre_overlap",
					})
				}
			}
		}
	}

	cveMatches := c.matchCVESignatures(event, vulnsByCVE)
	for _, m := range cveMatches {
		key := m.Vulnerability.VulnID + ":" + m.Vulnerability.ImageID
		if !seen[key] {
			seen[key] = true
			matches = append(matches, m)
		}
	}

	return matches
}

func (c *Correlator) matchCVESignatures(event qualys.CDREvent, vulnsByCVE map[string]*Vulnerability) []*Correlation {
	var matches []*Correlation

	for cveID, sig := range CVEExploitSignatures {
		vuln, exists := vulnsByCVE[cveID]
		if !exists {
			continue
		}

		matched := false

		for _, path := range sig.ProcessPaths {
			if strings.Contains(event.ProcessPath, path) {
				matched = true
				break
			}
		}

		if !matched {
			for _, name := range sig.ProcessNames {
				if strings.Contains(event.ProcessName, name) {
					matched = true
					break
				}
			}
		}

		if !matched {
			for _, tech := range sig.MITRE {
				for _, eventTech := range event.MITRETechniques {
					if tech == eventTech {
						matched = true
						break
					}
				}
				if matched {
					break
				}
			}
		}

		if matched {
			matches = append(matches, &Correlation{
				Vulnerability: vuln,
				Confidence:    c.config.CVESignatureConfidence,
				MatchedBy:     "cve_signature",
			})
		}
	}

	return matches
}

func (c *Correlator) groupByContainer(vulns []*Vulnerability) map[string][]*Vulnerability {
	result := make(map[string][]*Vulnerability)
	for _, v := range vulns {
		for _, containerID := range v.ContainerIDs {
			result[containerID] = append(result[containerID], v)
		}
	}
	return result
}

func (c *Correlator) groupByBinary(vulns []*Vulnerability) map[string][]*Vulnerability {
	result := make(map[string][]*Vulnerability)
	for _, v := range vulns {
		if v.PackagePath != "" {
			result[v.PackagePath] = append(result[v.PackagePath], v)
		}
	}
	return result
}

func (c *Correlator) groupByTechnique(vulns []*Vulnerability) map[string][]*Vulnerability {
	result := make(map[string][]*Vulnerability)
	for _, v := range vulns {
		for _, tech := range v.MITRETechniques {
			result[tech] = append(result[tech], v)
		}
	}
	return result
}
