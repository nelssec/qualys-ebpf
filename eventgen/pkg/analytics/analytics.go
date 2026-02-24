package analytics

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"sort"

	"github.com/qualys/eventgen/pkg/qualys"
	"github.com/qualys/eventgen/pkg/vuln"
)

func ParetoAnalysis(correlations []*vuln.Correlation, targetCoverage float64) ([]vuln.ParetoVuln, float64) {
	vulnEventCounts := make(map[string]*vuln.ParetoVuln)

	for _, corr := range correlations {
		v := corr.Vulnerability
		key := v.CVEID
		if key == "" {
			key = v.VulnID
		}

		if existing, ok := vulnEventCounts[key]; ok {
			existing.EventCount += len(corr.Events)
		} else {
			vulnEventCounts[key] = &vuln.ParetoVuln{
				VulnID:           v.VulnID,
				CVEID:            v.CVEID,
				Severity:         v.SeverityString(),
				Title:            v.Title,
				EventCount:       len(corr.Events),
				RiskScore:        v.RiskScore(),
				ActivelyExploited: v.ActivelyExploited,
			}
			if vulnEventCounts[key].Title == "" {
				vulnEventCounts[key].Title = v.PackageName
			}
		}
	}

	sorted := make([]vuln.ParetoVuln, 0, len(vulnEventCounts))
	for _, v := range vulnEventCounts {
		sorted = append(sorted, *v)
	}
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].EventCount > sorted[j].EventCount
	})

	totalEvents := 0
	for _, v := range sorted {
		totalEvents += v.EventCount
	}

	if totalEvents == 0 {
		return nil, 0
	}

	cumulative := 0
	var paretoVulns []vuln.ParetoVuln

	for _, v := range sorted {
		cumulative += v.EventCount
		paretoVulns = append(paretoVulns, v)

		if float64(cumulative)/float64(totalEvents) >= targetCoverage {
			break
		}
	}

	coverage := float64(cumulative) / float64(totalEvents) * 100

	return paretoVulns, coverage
}

func HighestRiskVulns(vulnerabilities []*vuln.Vulnerability, correlations []*vuln.Correlation, topN int) []vuln.RiskVuln {
	eventCounts := make(map[string]int)
	for _, corr := range correlations {
		eventCounts[corr.Vulnerability.VulnID] += len(corr.Events)
	}

	risks := make([]vuln.RiskVuln, 0, len(vulnerabilities))
	for _, v := range vulnerabilities {
		risk := CalculateRiskScore(v, eventCounts[v.VulnID])
		risks = append(risks, vuln.RiskVuln{
			VulnID:           v.VulnID,
			CVEID:            v.CVEID,
			Severity:         v.SeverityString(),
			CVSSScore:        v.CVSSScore,
			ActivelyExploited: v.ActivelyExploited,
			Exploitable:      v.Exploitable,
			RiskScore:        risk,
			ImageName:        v.ImageName,
			PackageName:      v.PackageName,
			CorrelatedEvents: eventCounts[v.VulnID],
		})
	}

	sort.Slice(risks, func(i, j int) bool {
		return risks[i].RiskScore > risks[j].RiskScore
	})

	if topN > 0 && len(risks) > topN {
		risks = risks[:topN]
	}

	return risks
}

func CalculateRiskScore(v *vuln.Vulnerability, correlatedEvents int) float64 {
	severityFactor := float64(v.Severity) / 5.0
	cvssFactor := v.CVSSScore / 10.0
	if v.CVSSScore == 0 {
		cvssFactor = 0.5
	}

	exploitMultiplier := 1.0
	if v.ActivelyExploited {
		exploitMultiplier = 2.0
	} else if v.Exploitable {
		exploitMultiplier = 1.5
	}

	exposureMultiplier := 1.0 + (0.1 * float64(correlatedEvents))

	score := severityFactor * cvssFactor * exploitMultiplier * exposureMultiplier * 100
	if score > 100 {
		return 100
	}
	return score
}

func GenerateReport(
	vulnerabilities []*vuln.Vulnerability,
	correlations []*vuln.Correlation,
	containers []qualys.Container,
) *vuln.AnalyticsReport {
	bySeverity := make(map[string]int)
	uniqueImages := make(map[string]bool)

	for _, v := range vulnerabilities {
		bySeverity[v.SeverityString()]++
		uniqueImages[v.ImageID] = true
	}

	correlatedVulnIDs := make(map[string]bool)
	for _, c := range correlations {
		correlatedVulnIDs[c.Vulnerability.VulnID] = true
	}

	paretoVulns, paretoCoverage := ParetoAnalysis(correlations, 0.8)
	topRisks := HighestRiskVulns(vulnerabilities, correlations, 10)

	return &vuln.AnalyticsReport{
		TotalVulnerabilities:   len(vulnerabilities),
		WithRuntimeCorrelation: len(correlatedVulnIDs),
		UniqueImagesAffected:   len(uniqueImages),
		RunningContainers:      len(containers),
		BySeverity:             bySeverity,
		ParetoVulns:            paretoVulns,
		ParetoCoverage:         paretoCoverage,
		HighestRisk:            topRisks,
	}
}

func ExportJSON(
	vulnerabilities []*vuln.Vulnerability,
	events []qualys.CDREvent,
	correlations []*vuln.Correlation,
	report *vuln.AnalyticsReport,
) ([]byte, error) {
	data := map[string]interface{}{
		"vulnerabilities": vulnerabilities,
		"events":          events,
		"correlations":    formatCorrelations(correlations),
		"analytics":       report,
	}
	return json.MarshalIndent(data, "", "  ")
}

func ExportCSV(vulnerabilities []*vuln.Vulnerability, correlations []*vuln.Correlation, w io.Writer) error {
	writer := csv.NewWriter(w)
	defer writer.Flush()

	header := []string{
		"vuln_id", "cve_id", "severity", "cvss_score", "image_name",
		"package_name", "exploitable", "actively_exploited", "risk_score", "correlated_events",
	}
	if err := writer.Write(header); err != nil {
		return err
	}

	eventCounts := make(map[string]int)
	for _, c := range correlations {
		eventCounts[c.Vulnerability.VulnID] += len(c.Events)
	}

	for _, v := range vulnerabilities {
		record := []string{
			v.VulnID,
			v.CVEID,
			v.SeverityString(),
			fmt.Sprintf("%.1f", v.CVSSScore),
			v.ImageName,
			v.PackageName,
			fmt.Sprintf("%t", v.Exploitable),
			fmt.Sprintf("%t", v.ActivelyExploited),
			fmt.Sprintf("%.1f", v.RiskScore()),
			fmt.Sprintf("%d", eventCounts[v.VulnID]),
		}
		if err := writer.Write(record); err != nil {
			return err
		}
	}

	return nil
}

func formatCorrelations(correlations []*vuln.Correlation) []map[string]interface{} {
	result := make([]map[string]interface{}, len(correlations))
	for i, c := range correlations {
		result[i] = map[string]interface{}{
			"vuln_id":             c.Vulnerability.VulnID,
			"cve_id":              c.Vulnerability.CVEID,
			"event_count":         len(c.Events),
			"confidence":          c.Confidence,
			"matched_by":          c.MatchedBy,
			"combined_risk_score": c.CombinedRiskScore,
		}
	}
	return result
}
