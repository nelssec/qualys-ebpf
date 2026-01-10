package policy

import (
	"fmt"
	"strings"
	"time"

	"github.com/qualys/qualys-policy-operator/pkg/cdr"
)

// TracingPolicy represents a Cilium Tetragon TracingPolicy.
type TracingPolicy struct {
	APIVersion string            `json:"apiVersion"`
	Kind       string            `json:"kind"`
	Metadata   Metadata          `json:"metadata"`
	Spec       TracingPolicySpec `json:"spec"`
	Name       string            `json:"-"` // Used for filename
}

type Metadata struct {
	Name        string            `json:"name"`
	Labels      map[string]string `json:"labels,omitempty"`
	Annotations map[string]string `json:"annotations,omitempty"`
}

type TracingPolicySpec struct {
	Kprobes []Kprobe `json:"kprobes,omitempty"`
}

type Kprobe struct {
	Call      string     `json:"call"`
	Syscall   bool       `json:"syscall"`
	Args      []Arg      `json:"args,omitempty"`
	Selectors []Selector `json:"selectors,omitempty"`
}

type Arg struct {
	Index int    `json:"index"`
	Type  string `json:"type"`
}

type Selector struct {
	MatchArgs     []MatchArg     `json:"matchArgs,omitempty"`
	MatchBinaries []MatchBinary  `json:"matchBinaries,omitempty"`
	MatchActions  []MatchAction  `json:"matchActions,omitempty"`
}

type MatchArg struct {
	Index    int      `json:"index"`
	Operator string   `json:"operator"`
	Values   []string `json:"values"`
}

type MatchBinary struct {
	Operator string   `json:"operator"`
	Values   []string `json:"values"`
}

type MatchAction struct {
	Action string `json:"action"`
}

// Generator creates TracingPolicies from CDR events.
type Generator struct {
	action string
}

// NewGenerator creates a new policy generator.
func NewGenerator(action string) *Generator {
	return &Generator{action: action}
}

// FromEvents generates TracingPolicies from CDR events.
func (g *Generator) FromEvents(events []cdr.Event) []TracingPolicy {
	// Group events by threat category
	byCategory := make(map[string][]cdr.Event)
	for _, e := range events {
		if e.ThreatCategory != "" {
			byCategory[e.ThreatCategory] = append(byCategory[e.ThreatCategory], e)
		}
	}

	var policies []TracingPolicy
	for category, catEvents := range byCategory {
		if policy := g.policyForCategory(category, catEvents); policy != nil {
			policies = append(policies, *policy)
		}
	}

	return policies
}

func (g *Generator) policyForCategory(category string, events []cdr.Event) *TracingPolicy {
	categoryLower := strings.ToLower(category)
	dateStr := time.Now().Format("20060102")

	switch {
	case strings.Contains(categoryLower, "cloud_credentials"):
		return g.cloudCredentialPolicy(events, dateStr)
	case strings.Contains(categoryLower, "network_scanning"):
		return g.networkScanningPolicy(events, dateStr)
	case strings.Contains(categoryLower, "container_escape"):
		return g.containerEscapePolicy(events, dateStr)
	case strings.Contains(categoryLower, "privilege_escalation"):
		return g.privilegeEscalationPolicy(events, dateStr)
	case strings.Contains(categoryLower, "crypto_mining"):
		return g.cryptoMiningPolicy(events, dateStr)
	case strings.Contains(categoryLower, "reverse_shell"):
		return g.reverseShellPolicy(events, dateStr)
	case strings.Contains(categoryLower, "suspicious_communication"):
		return g.suspiciousNetworkPolicy(events, dateStr)
	default:
		return nil
	}
}

func (g *Generator) cloudCredentialPolicy(events []cdr.Event, dateStr string) *TracingPolicy {
	// Extract detected processes
	processes := extractProcesses(events)

	name := fmt.Sprintf("cdr-block-cloud-creds-%s", dateStr)
	return &TracingPolicy{
		APIVersion: "cilium.io/v1alpha1",
		Kind:       "TracingPolicy",
		Name:       name,
		Metadata: Metadata{
			Name: name,
			Labels: map[string]string{
				"generated-by":             "qualys-cdr-operator",
				"mitre.attack/technique":   "T1552.005",
				"mitre.attack/tactic":      "credential-access",
				"policy.qualys.com/priority": "critical",
			},
			Annotations: map[string]string{
				"description":       "Block network utilities accessing cloud metadata endpoints",
				"detected-processes": strings.Join(processes, ","),
				"event-count":       fmt.Sprintf("%d", len(events)),
			},
		},
		Spec: TracingPolicySpec{
			Kprobes: []Kprobe{
				{
					Call:    "sys_connect",
					Syscall: true,
					Args: []Arg{
						{Index: 0, Type: "int"},
						{Index: 1, Type: "sockaddr"},
					},
					Selectors: []Selector{
						{
							MatchArgs: []MatchArg{
								{Index: 1, Operator: "SAddr", Values: []string{"169.254.169.254"}},
							},
							MatchBinaries: []MatchBinary{
								{Operator: "In", Values: []string{
									"/usr/bin/curl", "/usr/bin/wget", "/usr/bin/fetch",
								}},
							},
							MatchActions: []MatchAction{{Action: g.action}},
						},
					},
				},
			},
		},
	}
}

func (g *Generator) networkScanningPolicy(events []cdr.Event, dateStr string) *TracingPolicy {
	tools := extractProcesses(events)

	name := fmt.Sprintf("cdr-block-network-scan-%s", dateStr)
	return &TracingPolicy{
		APIVersion: "cilium.io/v1alpha1",
		Kind:       "TracingPolicy",
		Name:       name,
		Metadata: Metadata{
			Name: name,
			Labels: map[string]string{
				"generated-by":             "qualys-cdr-operator",
				"mitre.attack/technique":   "T1046",
				"mitre.attack/tactic":      "discovery",
				"policy.qualys.com/priority": "high",
			},
			Annotations: map[string]string{
				"description":    "Block network scanning and enumeration tools",
				"detected-tools": strings.Join(tools, ","),
				"event-count":    fmt.Sprintf("%d", len(events)),
			},
		},
		Spec: TracingPolicySpec{
			Kprobes: []Kprobe{
				{
					Call:    "sys_execve",
					Syscall: true,
					Args:    []Arg{{Index: 0, Type: "string"}},
					Selectors: []Selector{
						{
							MatchArgs: []MatchArg{
								{Index: 0, Operator: "Postfix", Values: []string{
									"/nmap", "/masscan", "/zmap", "/rustscan",
									"/netcat", "/nc", "/ncat", "/socat",
								}},
							},
							MatchActions: []MatchAction{{Action: g.action}},
						},
					},
				},
				{
					Call:    "sys_socket",
					Syscall: true,
					Args: []Arg{
						{Index: 0, Type: "int"},
						{Index: 1, Type: "int"},
					},
					Selectors: []Selector{
						{
							MatchArgs: []MatchArg{
								{Index: 1, Operator: "Equal", Values: []string{"3"}}, // SOCK_RAW
							},
							MatchActions: []MatchAction{{Action: g.action}},
						},
					},
				},
			},
		},
	}
}

func (g *Generator) containerEscapePolicy(events []cdr.Event, dateStr string) *TracingPolicy {
	name := fmt.Sprintf("cdr-block-container-escape-%s", dateStr)
	return &TracingPolicy{
		APIVersion: "cilium.io/v1alpha1",
		Kind:       "TracingPolicy",
		Name:       name,
		Metadata: Metadata{
			Name: name,
			Labels: map[string]string{
				"generated-by":             "qualys-cdr-operator",
				"mitre.attack/technique":   "T1611",
				"policy.qualys.com/priority": "critical",
			},
		},
		Spec: TracingPolicySpec{
			Kprobes: []Kprobe{
				{
					Call:    "sys_unshare",
					Syscall: true,
					Args:    []Arg{{Index: 0, Type: "int"}},
					Selectors: []Selector{
						{MatchActions: []MatchAction{{Action: g.action}}},
					},
				},
				{
					Call:    "sys_setns",
					Syscall: true,
					Args: []Arg{
						{Index: 0, Type: "int"},
						{Index: 1, Type: "int"},
					},
					Selectors: []Selector{
						{MatchActions: []MatchAction{{Action: g.action}}},
					},
				},
			},
		},
	}
}

func (g *Generator) privilegeEscalationPolicy(events []cdr.Event, dateStr string) *TracingPolicy {
	name := fmt.Sprintf("cdr-block-privesc-%s", dateStr)
	return &TracingPolicy{
		APIVersion: "cilium.io/v1alpha1",
		Kind:       "TracingPolicy",
		Name:       name,
		Metadata: Metadata{
			Name: name,
			Labels: map[string]string{
				"generated-by":             "qualys-cdr-operator",
				"mitre.attack/technique":   "T1548",
				"policy.qualys.com/priority": "high",
			},
		},
		Spec: TracingPolicySpec{
			Kprobes: []Kprobe{
				{
					Call:    "sys_setuid",
					Syscall: true,
					Args:    []Arg{{Index: 0, Type: "int"}},
					Selectors: []Selector{
						{
							MatchArgs: []MatchArg{
								{Index: 0, Operator: "Equal", Values: []string{"0"}},
							},
							MatchActions: []MatchAction{{Action: g.action}},
						},
					},
				},
			},
		},
	}
}

func (g *Generator) cryptoMiningPolicy(events []cdr.Event, dateStr string) *TracingPolicy {
	name := fmt.Sprintf("cdr-block-crypto-mining-%s", dateStr)
	return &TracingPolicy{
		APIVersion: "cilium.io/v1alpha1",
		Kind:       "TracingPolicy",
		Name:       name,
		Metadata: Metadata{
			Name: name,
			Labels: map[string]string{
				"generated-by":             "qualys-cdr-operator",
				"mitre.attack/technique":   "T1496",
				"policy.qualys.com/priority": "high",
			},
		},
		Spec: TracingPolicySpec{
			Kprobes: []Kprobe{
				{
					Call:    "sys_connect",
					Syscall: true,
					Args:    []Arg{{Index: 1, Type: "sockaddr"}},
					Selectors: []Selector{
						{
							MatchArgs: []MatchArg{
								{Index: 1, Operator: "DPort", Values: []string{
									"3333", "4444", "5555", "14433", "14444",
								}},
							},
							MatchActions: []MatchAction{{Action: g.action}},
						},
					},
				},
			},
		},
	}
}

func (g *Generator) reverseShellPolicy(events []cdr.Event, dateStr string) *TracingPolicy {
	name := fmt.Sprintf("cdr-block-reverse-shell-%s", dateStr)
	return &TracingPolicy{
		APIVersion: "cilium.io/v1alpha1",
		Kind:       "TracingPolicy",
		Name:       name,
		Metadata: Metadata{
			Name: name,
			Labels: map[string]string{
				"generated-by":             "qualys-cdr-operator",
				"mitre.attack/technique":   "T1059.004",
				"policy.qualys.com/priority": "critical",
			},
		},
		Spec: TracingPolicySpec{
			Kprobes: []Kprobe{
				{
					Call:    "sys_execve",
					Syscall: true,
					Args:    []Arg{{Index: 0, Type: "string"}},
					Selectors: []Selector{
						{
							MatchArgs: []MatchArg{
								{Index: 0, Operator: "Postfix", Values: []string{
									"/sh", "/bash", "/dash", "/zsh",
								}},
							},
							MatchActions: []MatchAction{{Action: g.action}},
						},
					},
				},
			},
		},
	}
}

func (g *Generator) suspiciousNetworkPolicy(events []cdr.Event, dateStr string) *TracingPolicy {
	name := fmt.Sprintf("cdr-suspicious-network-%s", dateStr)
	return &TracingPolicy{
		APIVersion: "cilium.io/v1alpha1",
		Kind:       "TracingPolicy",
		Name:       name,
		Metadata: Metadata{
			Name: name,
			Labels: map[string]string{
				"generated-by":             "qualys-cdr-operator",
				"policy.qualys.com/priority": "high",
			},
		},
		Spec: TracingPolicySpec{
			Kprobes: []Kprobe{
				{
					Call:    "sys_connect",
					Syscall: true,
					Args:    []Arg{{Index: 1, Type: "sockaddr"}},
					Selectors: []Selector{
						{
							MatchArgs: []MatchArg{
								{Index: 1, Operator: "DPort", Values: []string{
									"4444", "5555", "6666", "8443",
								}},
							},
							MatchActions: []MatchAction{{Action: g.action}},
						},
					},
				},
			},
		},
	}
}

func extractProcesses(events []cdr.Event) []string {
	seen := make(map[string]bool)
	var processes []string
	for _, e := range events {
		if e.ProcessName != "" && !seen[e.ProcessName] {
			seen[e.ProcessName] = true
			processes = append(processes, e.ProcessName)
		}
	}
	return processes
}
