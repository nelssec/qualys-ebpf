package ai

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	"github.com/qualys/eventgen/pkg/vuln"
)

const SystemPrompt = `You are a security expert specializing in container security, vulnerability analysis, and eBPF-based runtime protection. You help security teams understand vulnerabilities, validate potential exploits, and create effective detection/prevention policies.

Your expertise includes:
- CVE analysis and exploit techniques
- MITRE ATT&CK framework mapping
- Kubernetes and container security
- eBPF/Tetragon TracingPolicy creation
- Runtime threat detection

When analyzing vulnerabilities:
1. Explain the technical details clearly
2. Describe how the vulnerability could be exploited in containers
3. Identify what syscalls, file accesses, or network activity would indicate exploitation
4. Suggest specific TracingPolicy rules for detection/prevention

Always respond in JSON format with the structure specified in the user prompt.`

type Analyzer struct {
	apiKey     string
	model      string
	httpClient *http.Client
}

func NewAnalyzer(apiKey string, model string) (*Analyzer, error) {
	if apiKey == "" {
		apiKey = os.Getenv("ANTHROPIC_API_KEY")
	}
	if apiKey == "" {
		return nil, fmt.Errorf("ANTHROPIC_API_KEY required")
	}
	if model == "" {
		model = "claude-sonnet-4-20250514"
	}
	return &Analyzer{
		apiKey: apiKey,
		model:  model,
		httpClient: &http.Client{
			Timeout: 60 * time.Second,
		},
	}, nil
}

type claudeRequest struct {
	Model     string          `json:"model"`
	MaxTokens int             `json:"max_tokens"`
	System    string          `json:"system"`
	Messages  []claudeMessage `json:"messages"`
}

type claudeMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type claudeResponse struct {
	Content []struct {
		Text string `json:"text"`
	} `json:"content"`
	Error *struct {
		Message string `json:"message"`
	} `json:"error"`
}

func (a *Analyzer) callClaude(prompt string) (string, error) {
	reqBody := claudeRequest{
		Model:     a.model,
		MaxTokens: 4096,
		System:    SystemPrompt,
		Messages: []claudeMessage{
			{Role: "user", Content: prompt},
		},
	}

	jsonData, err := json.Marshal(reqBody)
	if err != nil {
		return "", err
	}

	req, err := http.NewRequest("POST", "https://api.anthropic.com/v1/messages", bytes.NewBuffer(jsonData))
	if err != nil {
		return "", err
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("x-api-key", a.apiKey)
	req.Header.Set("anthropic-version", "2023-06-01")

	resp, err := a.httpClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("API error %d: %s", resp.StatusCode, string(body))
	}

	var claudeResp claudeResponse
	if err := json.Unmarshal(body, &claudeResp); err != nil {
		return "", err
	}

	if claudeResp.Error != nil {
		return "", fmt.Errorf("Claude error: %s", claudeResp.Error.Message)
	}

	if len(claudeResp.Content) == 0 {
		return "", fmt.Errorf("empty response from Claude")
	}

	return claudeResp.Content[0].Text, nil
}

type AnalysisResult struct {
	AnalysisType    string                 `json:"analysis_type"`
	InputSummary    string                 `json:"input_summary"`
	Analysis        string                 `json:"analysis"`
	Confidence      float64                `json:"confidence"`
	Recommendations []string               `json:"recommendations"`
	SuggestedPolicy map[string]interface{} `json:"suggested_policy,omitempty"`
	RiskLevel       string                 `json:"risk_level,omitempty"`
	RawResponse     string                 `json:"raw_response"`
}

func (a *Analyzer) ExplainCVE(cveID string, context map[string]interface{}) (*AnalysisResult, error) {
	contextStr := ""
	if context != nil {
		jsonCtx, _ := json.MarshalIndent(context, "", "  ")
		contextStr = fmt.Sprintf("\n\nAdditional context:\n%s", string(jsonCtx))
	}

	prompt := fmt.Sprintf(`Analyze the vulnerability %s for container security purposes.%s

Respond in JSON format:
{
    "cve_id": "%s",
    "title": "Brief title",
    "severity_assessment": "CRITICAL|HIGH|MEDIUM|LOW",
    "technical_description": "Detailed technical explanation",
    "container_impact": "How this affects containerized workloads",
    "exploit_indicators": {
        "syscalls": ["list of syscalls that might indicate exploitation"],
        "file_accesses": ["files that might be accessed"],
        "network_activity": ["network patterns to watch for"],
        "process_behavior": ["suspicious process patterns"]
    },
    "mitre_techniques": ["T1234", "T5678"],
    "detection_strategy": "How to detect exploitation attempts",
    "prevention_strategy": "How to prevent exploitation",
    "confidence": 0.95
}`, cveID, contextStr, cveID)

	response, err := a.callClaude(prompt)
	if err != nil {
		return nil, err
	}

	var data map[string]interface{}
	json.Unmarshal([]byte(response), &data)

	analysis := response
	if desc, ok := data["technical_description"].(string); ok {
		analysis = desc
	}

	confidence := 0.8
	if c, ok := data["confidence"].(float64); ok {
		confidence = c
	}

	riskLevel := ""
	if sev, ok := data["severity_assessment"].(string); ok {
		riskLevel = sev
	}

	var recommendations []string
	if det, ok := data["detection_strategy"].(string); ok && det != "" {
		recommendations = append(recommendations, det)
	}
	if prev, ok := data["prevention_strategy"].(string); ok && prev != "" {
		recommendations = append(recommendations, prev)
	}

	return &AnalysisResult{
		AnalysisType:    "explain_cve",
		InputSummary:    fmt.Sprintf("CVE: %s", cveID),
		Analysis:        analysis,
		Confidence:      confidence,
		Recommendations: recommendations,
		RiskLevel:       riskLevel,
		RawResponse:     response,
	}, nil
}

func (a *Analyzer) ValidateExploit(v *vuln.Vulnerability, eventCount int) (*AnalysisResult, error) {
	vulnData := map[string]interface{}{
		"cve_id":       v.CVEID,
		"vuln_id":      v.VulnID,
		"severity":     v.SeverityString(),
		"package":      v.PackageName,
		"package_path": v.PackagePath,
		"mitre":        v.MITRETechniques,
	}

	vulnJSON, _ := json.MarshalIndent(vulnData, "", "  ")

	prompt := fmt.Sprintf(`Analyze if runtime events could indicate exploitation of this vulnerability.

Vulnerability:
%s

Number of correlated runtime events: %d

Assess:
1. What patterns would indicate actual exploitation vs. benign activity?
2. What is typical false positive rate for this type of vulnerability?
3. What additional indicators should we look for?

Respond in JSON format:
{
    "is_likely_exploit": true|false,
    "confidence": 0.0-1.0,
    "reasoning": "Detailed explanation",
    "matching_indicators": ["indicators that suggest exploitation"],
    "false_positive_likelihood": "HIGH|MEDIUM|LOW",
    "recommended_action": "BLOCK|ALERT|INVESTIGATE|IGNORE",
    "additional_monitoring": ["what else to watch for"]
}`, string(vulnJSON), eventCount)

	response, err := a.callClaude(prompt)
	if err != nil {
		return nil, err
	}

	var data map[string]interface{}
	json.Unmarshal([]byte(response), &data)

	analysis := response
	if reasoning, ok := data["reasoning"].(string); ok {
		analysis = reasoning
	}

	confidence := 0.5
	if c, ok := data["confidence"].(float64); ok {
		confidence = c
	}

	var recommendations []string
	if action, ok := data["recommended_action"].(string); ok {
		recommendations = append(recommendations, action)
	}
	if monitoring, ok := data["additional_monitoring"].([]interface{}); ok {
		for _, m := range monitoring {
			if s, ok := m.(string); ok {
				recommendations = append(recommendations, s)
			}
		}
	}

	riskLevel := "MEDIUM"
	if action, ok := data["recommended_action"].(string); ok {
		switch action {
		case "BLOCK":
			riskLevel = "CRITICAL"
		case "ALERT":
			riskLevel = "HIGH"
		case "INVESTIGATE":
			riskLevel = "MEDIUM"
		case "IGNORE":
			riskLevel = "LOW"
		}
	}

	return &AnalysisResult{
		AnalysisType:    "validate_exploit",
		InputSummary:    fmt.Sprintf("Vuln: %s, Events: %d", v.CVEID, eventCount),
		Analysis:        analysis,
		Confidence:      confidence,
		Recommendations: recommendations,
		RiskLevel:       riskLevel,
		RawResponse:     response,
	}, nil
}

func (a *Analyzer) SuggestPolicy(v *vuln.Vulnerability, action string) (*AnalysisResult, error) {
	vulnData := map[string]interface{}{
		"cve_id":       v.CVEID,
		"vuln_id":      v.VulnID,
		"severity":     v.SeverityString(),
		"cvss_score":   v.CVSSScore,
		"package":      v.PackageName,
		"package_path": v.PackagePath,
		"mitre":        v.MITRETechniques,
		"description":  v.Description,
	}

	vulnJSON, _ := json.MarshalIndent(vulnData, "", "  ")

	prompt := fmt.Sprintf(`Generate a Cilium/Tetragon TracingPolicy to detect or prevent exploitation of this vulnerability.

Vulnerability:
%s

Requested action: %s (Post = audit/alert, Sigkill = block/kill)

Create a TracingPolicy that:
1. Monitors syscalls, file accesses, or network activity specific to this CVE's exploit pattern
2. Uses appropriate selectors (matchBinaries, matchArgs, etc.)
3. Minimizes false positives while catching exploit attempts

Respond in JSON format:
{
    "policy_name": "cve-xxx-detection",
    "description": "What this policy detects",
    "tracing_policy": {
        "apiVersion": "cilium.io/v1alpha1",
        "kind": "TracingPolicy",
        "metadata": {...},
        "spec": {...}
    },
    "detection_logic": "Explanation of what the policy monitors and why",
    "false_positive_notes": "Potential false positives and how to tune",
    "confidence": 0.0-1.0
}`, string(vulnJSON), action)

	response, err := a.callClaude(prompt)
	if err != nil {
		return nil, err
	}

	var data map[string]interface{}
	json.Unmarshal([]byte(response), &data)

	analysis := response
	if logic, ok := data["detection_logic"].(string); ok {
		analysis = logic
	}

	confidence := 0.7
	if c, ok := data["confidence"].(float64); ok {
		confidence = c
	}

	var policy map[string]interface{}
	if p, ok := data["tracing_policy"].(map[string]interface{}); ok {
		policy = p
	}

	var recommendations []string
	if fp, ok := data["false_positive_notes"].(string); ok && fp != "" {
		recommendations = append(recommendations, fp)
	}

	return &AnalysisResult{
		AnalysisType:    "suggest_policy",
		InputSummary:    fmt.Sprintf("Policy for %s", v.CVEID),
		Analysis:        analysis,
		Confidence:      confidence,
		Recommendations: recommendations,
		SuggestedPolicy: policy,
		RawResponse:     response,
	}, nil
}

func (a *Analyzer) AssessRisk(vulnCount, correlationCount int, topVulns []string) (*AnalysisResult, error) {
	prompt := fmt.Sprintf(`Perform a risk assessment for a container environment.

Summary:
- Total vulnerabilities: %d
- Runtime correlations: %d
- Top correlated CVEs: %v

Provide:
1. Overall risk assessment
2. Prioritized remediation recommendations
3. Security posture improvement suggestions

Respond in JSON format:
{
    "overall_risk_level": "CRITICAL|HIGH|MEDIUM|LOW",
    "risk_score": 0-100,
    "executive_summary": "2-3 sentence summary for leadership",
    "prioritized_remediation": [
        {"priority": 1, "action": "...", "impact": "..."}
    ],
    "security_improvements": ["list of general improvements"],
    "confidence": 0.0-1.0
}`, vulnCount, correlationCount, topVulns)

	response, err := a.callClaude(prompt)
	if err != nil {
		return nil, err
	}

	var data map[string]interface{}
	json.Unmarshal([]byte(response), &data)

	analysis := response
	if summary, ok := data["executive_summary"].(string); ok {
		analysis = summary
	}

	confidence := 0.7
	if c, ok := data["confidence"].(float64); ok {
		confidence = c
	}

	riskLevel := "MEDIUM"
	if r, ok := data["overall_risk_level"].(string); ok {
		riskLevel = r
	}

	var recommendations []string
	if remediation, ok := data["prioritized_remediation"].([]interface{}); ok {
		for _, item := range remediation {
			if m, ok := item.(map[string]interface{}); ok {
				if action, ok := m["action"].(string); ok {
					priority := 0
					if p, ok := m["priority"].(float64); ok {
						priority = int(p)
					}
					recommendations = append(recommendations, fmt.Sprintf("[P%d] %s", priority, action))
				}
			}
		}
	}
	if improvements, ok := data["security_improvements"].([]interface{}); ok {
		for _, item := range improvements {
			if s, ok := item.(string); ok {
				recommendations = append(recommendations, s)
			}
		}
	}

	return &AnalysisResult{
		AnalysisType:    "risk_assessment",
		InputSummary:    fmt.Sprintf("Vulns: %d, Correlations: %d", vulnCount, correlationCount),
		Analysis:        analysis,
		Confidence:      confidence,
		Recommendations: recommendations,
		RiskLevel:       riskLevel,
		RawResponse:     response,
	}, nil
}

func (r *AnalysisResult) Format(verbose bool) string {
	out := ""
	out += "======================================================================\n"
	out += fmt.Sprintf("AI Analysis: %s\n", r.AnalysisType)
	out += "======================================================================\n"
	out += fmt.Sprintf("Input: %s\n", r.InputSummary)
	out += fmt.Sprintf("Confidence: %.0f%%\n", r.Confidence*100)
	if r.RiskLevel != "" {
		out += fmt.Sprintf("Risk Level: %s\n", r.RiskLevel)
	}
	out += "\nANALYSIS:\n"
	out += r.Analysis + "\n\n"

	if len(r.Recommendations) > 0 {
		out += "RECOMMENDATIONS:\n"
		for _, rec := range r.Recommendations {
			if rec != "" {
				out += fmt.Sprintf("  - %s\n", rec)
			}
		}
		out += "\n"
	}

	if verbose {
		out += "RAW RESPONSE:\n"
		out += r.RawResponse + "\n"
	}

	return out
}
