package vuln

import (
	"encoding/json"
	"fmt"

	"github.com/qualys/eventgen/pkg/qualys"
)

type Severity int

const (
	SeverityLow Severity = iota + 1
	SeverityMedium
	SeverityHigh
	SeverityCritical
	SeverityUrgent
)

func (s Severity) String() string {
	switch s {
	case SeverityLow:
		return "LOW"
	case SeverityMedium:
		return "MEDIUM"
	case SeverityHigh:
		return "HIGH"
	case SeverityCritical:
		return "CRITICAL"
	case SeverityUrgent:
		return "URGENT"
	default:
		return "MEDIUM"
	}
}

func SeverityFromString(s string) Severity {
	switch s {
	case "LOW":
		return SeverityLow
	case "MEDIUM":
		return SeverityMedium
	case "HIGH":
		return SeverityHigh
	case "CRITICAL":
		return SeverityCritical
	case "URGENT":
		return SeverityUrgent
	default:
		return SeverityMedium
	}
}

type Vulnerability struct {
	VulnID           string   `json:"vuln_id"`
	CVEID            string   `json:"cve_id"`
	Severity         int      `json:"severity"`
	CVSSScore        float64  `json:"cvss_score"`
	ImageID          string   `json:"image_id"`
	ImageName        string   `json:"image_name"`
	ContainerIDs     []string `json:"container_ids"`
	PackageName      string   `json:"package_name"`
	PackagePath      string   `json:"package_path"`
	MITRETechniques  []string `json:"mitre_techniques"`
	Exploitable      bool     `json:"exploitable"`
	ActivelyExploited bool    `json:"actively_exploited"`
	Title            string   `json:"title"`
	Description      string   `json:"description"`
	FixVersion       string   `json:"fix_version"`
}

func (v *Vulnerability) SeverityString() string {
	return Severity(v.Severity).String()
}

func (v *Vulnerability) IsCritical() bool {
	return v.Severity >= int(SeverityCritical)
}

func (v *Vulnerability) RiskScore() float64 {
	base := (float64(v.Severity) / 5.0) * (v.CVSSScore / 10.0)
	if v.CVSSScore == 0 {
		base = float64(v.Severity) / 5.0 * 0.5
	}

	multiplier := 1.0
	if v.ActivelyExploited {
		multiplier = 2.0
	} else if v.Exploitable {
		multiplier = 1.5
	}

	score := base * multiplier * 100
	if score > 100 {
		return 100
	}
	return score
}

type Correlation struct {
	Vulnerability     *Vulnerability     `json:"vulnerability"`
	Events            []qualys.CDREvent  `json:"events"`
	Confidence        float64            `json:"confidence"`
	MatchedBy         string             `json:"matched_by"`
	CombinedRiskScore float64            `json:"combined_risk_score"`
}

func (c *Correlation) CalculateCombinedRisk() float64 {
	vulnRisk := c.Vulnerability.RiskScore()
	exposureMultiplier := 1.0 + (0.1 * float64(len(c.Events)))
	score := vulnRisk * exposureMultiplier * c.Confidence
	if score > 100 {
		return 100
	}
	return score
}

type AnalyticsReport struct {
	TotalVulnerabilities    int                    `json:"total_vulnerabilities"`
	WithRuntimeCorrelation  int                    `json:"with_runtime_correlation"`
	UniqueImagesAffected    int                    `json:"unique_images_affected"`
	RunningContainers       int                    `json:"running_containers"`
	BySeverity              map[string]int         `json:"by_severity"`
	ParetoVulns             []ParetoVuln           `json:"pareto_vulns"`
	ParetoCoverage          float64                `json:"pareto_coverage"`
	HighestRisk             []RiskVuln             `json:"highest_risk"`
}

type ParetoVuln struct {
	VulnID           string  `json:"vuln_id"`
	CVEID            string  `json:"cve_id"`
	Severity         string  `json:"severity"`
	Title            string  `json:"title"`
	EventCount       int     `json:"event_count"`
	RiskScore        float64 `json:"risk_score"`
	ActivelyExploited bool   `json:"actively_exploited"`
}

type RiskVuln struct {
	VulnID           string  `json:"vuln_id"`
	CVEID            string  `json:"cve_id"`
	Severity         string  `json:"severity"`
	CVSSScore        float64 `json:"cvss_score"`
	ActivelyExploited bool   `json:"actively_exploited"`
	Exploitable      bool    `json:"exploitable"`
	RiskScore        float64 `json:"risk_score"`
	ImageName        string  `json:"image_name"`
	PackageName      string  `json:"package_name"`
	CorrelatedEvents int     `json:"correlated_events"`
}

func (r *AnalyticsReport) ToJSON() ([]byte, error) {
	return json.MarshalIndent(r, "", "  ")
}

func (r *AnalyticsReport) FormatText() string {
	out := ""
	out += "================================================================================\n"
	out += "Vulnerability Analytics Report\n"
	out += "================================================================================\n\n"

	out += "SUMMARY\n"
	out += fmt.Sprintf("  Total Vulnerabilities:     %d\n", r.TotalVulnerabilities)
	out += fmt.Sprintf("  With Runtime Correlation:  %d\n", r.WithRuntimeCorrelation)
	out += fmt.Sprintf("  Unique Images Affected:    %d\n", r.UniqueImagesAffected)
	out += fmt.Sprintf("  Running Containers:        %d\n", r.RunningContainers)
	out += "\n"

	if len(r.ParetoVulns) > 0 {
		out += fmt.Sprintf("PARETO ANALYSIS (Top vulns that fix %.1f%% of issues)\n", r.ParetoCoverage)
		out += fmt.Sprintf("  Fixing %d vulnerabilities would address %.1f%% of correlated events:\n\n", len(r.ParetoVulns), r.ParetoCoverage)

		for i, v := range r.ParetoVulns {
			if i >= 10 {
				break
			}
			cve := v.CVEID
			if cve == "" {
				cve = v.VulnID
			}
			exploited := ""
			if v.ActivelyExploited {
				exploited = " *"
			}
			out += fmt.Sprintf("  %2d. %-16s (%-8s) - %-30s [%d events]%s\n",
				i+1, cve, v.Severity, truncate(v.Title, 30), v.EventCount, exploited)
		}
		out += "\n"
	}

	if len(r.HighestRisk) > 0 {
		out += "HIGHEST RISK VULNERABILITIES\n"
		out += "  #   CVE              Severity  CVSS   Exploited  Risk Score\n"
		out += "  " + repeatStr("-", 60) + "\n"

		for i, v := range r.HighestRisk {
			if i >= 10 {
				break
			}
			cve := v.CVEID
			if cve == "" {
				cve = v.VulnID
			}
			cvss := "N/A"
			if v.CVSSScore > 0 {
				cvss = fmt.Sprintf("%.1f", v.CVSSScore)
			}
			exploited := "NO"
			if v.ActivelyExploited {
				exploited = "YES"
			}
			out += fmt.Sprintf("  %2d  %-16s %-9s %-6s %-10s %.1f\n",
				i+1, truncate(cve, 16), v.Severity, cvss, exploited, v.RiskScore)
		}
		out += "\n"
	}

	if len(r.BySeverity) > 0 {
		out += "BY SEVERITY\n"
		order := []string{"CRITICAL", "URGENT", "HIGH", "MEDIUM", "LOW"}
		for _, sev := range order {
			if count, ok := r.BySeverity[sev]; ok {
				out += fmt.Sprintf("  %s: %d\n", sev, count)
			}
		}
		out += "\n"
	}

	return out
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max-3] + "..."
}

func repeatStr(s string, n int) string {
	result := ""
	for i := 0; i < n; i++ {
		result += s
	}
	return result
}
