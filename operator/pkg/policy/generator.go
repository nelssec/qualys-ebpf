package policy

import (
	"fmt"
	"strings"
	"time"

	"qualys-policy-operator/pkg/cdr"
)

// TracingPolicy represents a Qualys TracingPolicy for eBPF enforcement.
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
	case strings.Contains(categoryLower, "sensitive_file") || strings.Contains(categoryLower, "credential_file"):
		return g.sensitiveFileAccessPolicy(events, dateStr)
	case strings.Contains(categoryLower, "persistence") || strings.Contains(categoryLower, "cron"):
		return g.persistencePolicy(events, dateStr)
	case strings.Contains(categoryLower, "log_tampering") || strings.Contains(categoryLower, "defense_evasion"):
		return g.defenseEvasionPolicy(events, dateStr)
	case strings.Contains(categoryLower, "lateral_movement") || strings.Contains(categoryLower, "ssh"):
		return g.lateralMovementPolicy(events, dateStr)
	case strings.Contains(categoryLower, "exfiltration") || strings.Contains(categoryLower, "data_staging"):
		return g.dataExfiltrationPolicy(events, dateStr)
	case strings.Contains(categoryLower, "webshell"):
		return g.webshellPolicy(events, dateStr)
	case strings.Contains(categoryLower, "kernel_module"):
		return g.kernelModulePolicy(events, dateStr)
	case strings.Contains(categoryLower, "account_manipulation") || strings.Contains(categoryLower, "user_modification"):
		return g.accountManipulationPolicy(events, dateStr)
	case strings.Contains(categoryLower, "account_creation") || strings.Contains(categoryLower, "user_creation"):
		return g.accountCreationPolicy(events, dateStr)
	case strings.Contains(categoryLower, "container_build") || strings.Contains(categoryLower, "image_build"):
		return g.containerBuildPolicy(events, dateStr)
	case strings.Contains(categoryLower, "data_destruction") || strings.Contains(categoryLower, "file_deletion"):
		return g.dataDestructionPolicy(events, dateStr)
	case strings.Contains(categoryLower, "system_recovery") || strings.Contains(categoryLower, "backup_deletion"):
		return g.inhibitRecoveryPolicy(events, dateStr)
	case strings.Contains(categoryLower, "group_discovery") || strings.Contains(categoryLower, "permission_enumeration"):
		return g.groupDiscoveryPolicy(events, dateStr)
	case strings.Contains(categoryLower, "remote_services") || strings.Contains(categoryLower, "rdp") || strings.Contains(categoryLower, "vnc"):
		return g.remoteServicesPolicy(events, dateStr)
	case strings.Contains(categoryLower, "deploy_container"):
		return g.deployContainerPolicy(events, dateStr)
	case strings.Contains(categoryLower, "admin_command") || strings.Contains(categoryLower, "kubectl_exec"):
		return g.containerAdminPolicy(events, dateStr)
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

func (g *Generator) sensitiveFileAccessPolicy(events []cdr.Event, dateStr string) *TracingPolicy {
	name := fmt.Sprintf("cdr-block-sensitive-file-%s", dateStr)
	return &TracingPolicy{
		APIVersion: "cilium.io/v1alpha1",
		Kind:       "TracingPolicy",
		Name:       name,
		Metadata: Metadata{
			Name: name,
			Labels: map[string]string{
				"generated-by":               "qualys-cdr-operator",
				"mitre.attack/technique":     "T1552.001",
				"mitre.attack/tactic":        "credential-access",
				"policy.qualys.com/priority": "high",
			},
			Annotations: map[string]string{
				"description": "Block access to sensitive credential files",
				"event-count": fmt.Sprintf("%d", len(events)),
			},
		},
		Spec: TracingPolicySpec{
			Kprobes: []Kprobe{
				{
					Call:    "sys_openat",
					Syscall: true,
					Args: []Arg{
						{Index: 0, Type: "int"},
						{Index: 1, Type: "string"},
					},
					Selectors: []Selector{
						{
							MatchArgs: []MatchArg{
								{Index: 1, Operator: "Prefix", Values: []string{
									"/etc/shadow", "/etc/passwd", "/etc/gshadow",
									"/root/.ssh/", "/home/", "/var/run/secrets/kubernetes.io/",
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

func (g *Generator) persistencePolicy(events []cdr.Event, dateStr string) *TracingPolicy {
	name := fmt.Sprintf("cdr-block-persistence-%s", dateStr)
	return &TracingPolicy{
		APIVersion: "cilium.io/v1alpha1",
		Kind:       "TracingPolicy",
		Name:       name,
		Metadata: Metadata{
			Name: name,
			Labels: map[string]string{
				"generated-by":               "qualys-cdr-operator",
				"mitre.attack/technique":     "T1053.003",
				"mitre.attack/tactic":        "persistence",
				"policy.qualys.com/priority": "high",
			},
			Annotations: map[string]string{
				"description": "Block persistence mechanism creation",
				"event-count": fmt.Sprintf("%d", len(events)),
			},
		},
		Spec: TracingPolicySpec{
			Kprobes: []Kprobe{
				{
					Call:    "sys_openat",
					Syscall: true,
					Args: []Arg{
						{Index: 0, Type: "int"},
						{Index: 1, Type: "string"},
						{Index: 2, Type: "int"},
					},
					Selectors: []Selector{
						{
							MatchArgs: []MatchArg{
								{Index: 1, Operator: "Prefix", Values: []string{
									"/etc/cron", "/var/spool/cron",
									"/etc/systemd/system/", "/etc/init.d/",
								}},
								{Index: 2, Operator: "Mask", Values: []string{"O_WRONLY", "O_RDWR", "O_CREAT"}},
							},
							MatchActions: []MatchAction{{Action: g.action}},
						},
					},
				},
			},
		},
	}
}

func (g *Generator) defenseEvasionPolicy(events []cdr.Event, dateStr string) *TracingPolicy {
	name := fmt.Sprintf("cdr-block-defense-evasion-%s", dateStr)
	return &TracingPolicy{
		APIVersion: "cilium.io/v1alpha1",
		Kind:       "TracingPolicy",
		Name:       name,
		Metadata: Metadata{
			Name: name,
			Labels: map[string]string{
				"generated-by":               "qualys-cdr-operator",
				"mitre.attack/technique":     "T1070.002",
				"mitre.attack/tactic":        "defense-evasion",
				"policy.qualys.com/priority": "high",
			},
			Annotations: map[string]string{
				"description": "Block log tampering and defense evasion",
				"event-count": fmt.Sprintf("%d", len(events)),
			},
		},
		Spec: TracingPolicySpec{
			Kprobes: []Kprobe{
				{
					Call:    "sys_unlinkat",
					Syscall: true,
					Args: []Arg{
						{Index: 0, Type: "int"},
						{Index: 1, Type: "string"},
					},
					Selectors: []Selector{
						{
							MatchArgs: []MatchArg{
								{Index: 1, Operator: "Prefix", Values: []string{
									"/var/log/", "/var/audit/",
								}},
							},
							MatchActions: []MatchAction{{Action: g.action}},
						},
					},
				},
				{
					Call:    "sys_truncate",
					Syscall: true,
					Args:    []Arg{{Index: 0, Type: "string"}},
					Selectors: []Selector{
						{
							MatchArgs: []MatchArg{
								{Index: 0, Operator: "Prefix", Values: []string{
									"/var/log/", "/.bash_history",
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

func (g *Generator) lateralMovementPolicy(events []cdr.Event, dateStr string) *TracingPolicy {
	name := fmt.Sprintf("cdr-block-lateral-movement-%s", dateStr)
	return &TracingPolicy{
		APIVersion: "cilium.io/v1alpha1",
		Kind:       "TracingPolicy",
		Name:       name,
		Metadata: Metadata{
			Name: name,
			Labels: map[string]string{
				"generated-by":               "qualys-cdr-operator",
				"mitre.attack/technique":     "T1021.004",
				"mitre.attack/tactic":        "lateral-movement",
				"policy.qualys.com/priority": "high",
			},
			Annotations: map[string]string{
				"description": "Block lateral movement via SSH/SCP",
				"event-count": fmt.Sprintf("%d", len(events)),
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
									"/ssh", "/scp", "/sftp", "/rsync",
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

func (g *Generator) dataExfiltrationPolicy(events []cdr.Event, dateStr string) *TracingPolicy {
	name := fmt.Sprintf("cdr-block-exfiltration-%s", dateStr)
	return &TracingPolicy{
		APIVersion: "cilium.io/v1alpha1",
		Kind:       "TracingPolicy",
		Name:       name,
		Metadata: Metadata{
			Name: name,
			Labels: map[string]string{
				"generated-by":               "qualys-cdr-operator",
				"mitre.attack/technique":     "T1041",
				"mitre.attack/tactic":        "exfiltration",
				"policy.qualys.com/priority": "critical",
			},
			Annotations: map[string]string{
				"description": "Block data exfiltration tools and methods",
				"event-count": fmt.Sprintf("%d", len(events)),
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
									"/base64", "/xxd", "/openssl",
									"/rclone", "/ftp", "/tftp",
								}},
							},
							MatchActions: []MatchAction{{Action: g.action}},
						},
					},
				},
				{
					Call:    "sys_connect",
					Syscall: true,
					Args:    []Arg{{Index: 1, Type: "sockaddr"}},
					Selectors: []Selector{
						{
							MatchArgs: []MatchArg{
								{Index: 1, Operator: "DPort", Values: []string{
									"20", "21", "69", "873",
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

func (g *Generator) webshellPolicy(events []cdr.Event, dateStr string) *TracingPolicy {
	name := fmt.Sprintf("cdr-block-webshell-%s", dateStr)
	return &TracingPolicy{
		APIVersion: "cilium.io/v1alpha1",
		Kind:       "TracingPolicy",
		Name:       name,
		Metadata: Metadata{
			Name: name,
			Labels: map[string]string{
				"generated-by":               "qualys-cdr-operator",
				"mitre.attack/technique":     "T1505.003",
				"mitre.attack/tactic":        "persistence",
				"policy.qualys.com/priority": "critical",
			},
			Annotations: map[string]string{
				"description": "Block webshell execution from web servers",
				"event-count": fmt.Sprintf("%d", len(events)),
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
									"/sh", "/bash", "/python", "/php", "/perl",
								}},
							},
							MatchBinaries: []MatchBinary{
								{Operator: "In", Values: []string{
									"/usr/sbin/nginx", "/usr/sbin/apache2",
									"/usr/sbin/httpd", "/usr/bin/php-fpm",
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

func (g *Generator) kernelModulePolicy(events []cdr.Event, dateStr string) *TracingPolicy {
	name := fmt.Sprintf("cdr-block-kernel-module-%s", dateStr)
	return &TracingPolicy{
		APIVersion: "cilium.io/v1alpha1",
		Kind:       "TracingPolicy",
		Name:       name,
		Metadata: Metadata{
			Name: name,
			Labels: map[string]string{
				"generated-by":               "qualys-cdr-operator",
				"mitre.attack/technique":     "T1547.006",
				"mitre.attack/tactic":        "persistence",
				"policy.qualys.com/priority": "critical",
			},
			Annotations: map[string]string{
				"description": "Block kernel module loading in containers",
				"event-count": fmt.Sprintf("%d", len(events)),
			},
		},
		Spec: TracingPolicySpec{
			Kprobes: []Kprobe{
				{
					Call:    "sys_init_module",
					Syscall: true,
					Selectors: []Selector{
						{MatchActions: []MatchAction{{Action: g.action}}},
					},
				},
				{
					Call:    "sys_finit_module",
					Syscall: true,
					Selectors: []Selector{
						{MatchActions: []MatchAction{{Action: g.action}}},
					},
				},
				{
					Call:    "sys_execve",
					Syscall: true,
					Args:    []Arg{{Index: 0, Type: "string"}},
					Selectors: []Selector{
						{
							MatchArgs: []MatchArg{
								{Index: 0, Operator: "Postfix", Values: []string{
									"/insmod", "/modprobe", "/rmmod",
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

func (g *Generator) accountManipulationPolicy(events []cdr.Event, dateStr string) *TracingPolicy {
	name := fmt.Sprintf("cdr-block-account-manipulation-%s", dateStr)
	return &TracingPolicy{
		APIVersion: "cilium.io/v1alpha1",
		Kind:       "TracingPolicy",
		Name:       name,
		Metadata: Metadata{
			Name: name,
			Labels: map[string]string{
				"generated-by":               "qualys-cdr-operator",
				"mitre.attack/technique":     "T1098",
				"mitre.attack/tactic":        "persistence",
				"policy.qualys.com/priority": "high",
			},
			Annotations: map[string]string{
				"description": "Block account manipulation commands",
				"event-count": fmt.Sprintf("%d", len(events)),
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
									"/passwd", "/chage", "/usermod", "/chsh", "/chfn",
									"/gpasswd", "/groupmod",
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

func (g *Generator) accountCreationPolicy(events []cdr.Event, dateStr string) *TracingPolicy {
	name := fmt.Sprintf("cdr-block-account-creation-%s", dateStr)
	return &TracingPolicy{
		APIVersion: "cilium.io/v1alpha1",
		Kind:       "TracingPolicy",
		Name:       name,
		Metadata: Metadata{
			Name: name,
			Labels: map[string]string{
				"generated-by":               "qualys-cdr-operator",
				"mitre.attack/technique":     "T1136",
				"mitre.attack/tactic":        "persistence",
				"policy.qualys.com/priority": "high",
			},
			Annotations: map[string]string{
				"description": "Block account creation commands",
				"event-count": fmt.Sprintf("%d", len(events)),
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
									"/useradd", "/adduser", "/groupadd", "/addgroup",
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

func (g *Generator) containerBuildPolicy(events []cdr.Event, dateStr string) *TracingPolicy {
	name := fmt.Sprintf("cdr-block-container-build-%s", dateStr)
	return &TracingPolicy{
		APIVersion: "cilium.io/v1alpha1",
		Kind:       "TracingPolicy",
		Name:       name,
		Metadata: Metadata{
			Name: name,
			Labels: map[string]string{
				"generated-by":               "qualys-cdr-operator",
				"mitre.attack/technique":     "T1612",
				"mitre.attack/tactic":        "defense-evasion",
				"policy.qualys.com/priority": "high",
			},
			Annotations: map[string]string{
				"description": "Block container image builds on host",
				"event-count": fmt.Sprintf("%d", len(events)),
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
									"/docker", "/podman", "/buildah", "/nerdctl", "/kaniko",
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

func (g *Generator) dataDestructionPolicy(events []cdr.Event, dateStr string) *TracingPolicy {
	name := fmt.Sprintf("cdr-block-data-destruction-%s", dateStr)
	return &TracingPolicy{
		APIVersion: "cilium.io/v1alpha1",
		Kind:       "TracingPolicy",
		Name:       name,
		Metadata: Metadata{
			Name: name,
			Labels: map[string]string{
				"generated-by":               "qualys-cdr-operator",
				"mitre.attack/technique":     "T1485",
				"mitre.attack/tactic":        "impact",
				"policy.qualys.com/priority": "critical",
			},
			Annotations: map[string]string{
				"description": "Block mass data destruction commands",
				"event-count": fmt.Sprintf("%d", len(events)),
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
									"/shred", "/wipe", "/srm", "/secure-delete",
								}},
							},
							MatchActions: []MatchAction{{Action: g.action}},
						},
					},
				},
				{
					Call:    "sys_unlinkat",
					Syscall: true,
					Args: []Arg{
						{Index: 0, Type: "int"},
						{Index: 1, Type: "string"},
					},
					Selectors: []Selector{
						{
							MatchArgs: []MatchArg{
								{Index: 1, Operator: "Prefix", Values: []string{
									"/var/lib/", "/data/", "/home/",
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

func (g *Generator) inhibitRecoveryPolicy(events []cdr.Event, dateStr string) *TracingPolicy {
	name := fmt.Sprintf("cdr-block-inhibit-recovery-%s", dateStr)
	return &TracingPolicy{
		APIVersion: "cilium.io/v1alpha1",
		Kind:       "TracingPolicy",
		Name:       name,
		Metadata: Metadata{
			Name: name,
			Labels: map[string]string{
				"generated-by":               "qualys-cdr-operator",
				"mitre.attack/technique":     "T1490",
				"mitre.attack/tactic":        "impact",
				"policy.qualys.com/priority": "critical",
			},
			Annotations: map[string]string{
				"description": "Block attempts to inhibit system recovery",
				"event-count": fmt.Sprintf("%d", len(events)),
			},
		},
		Spec: TracingPolicySpec{
			Kprobes: []Kprobe{
				{
					Call:    "sys_unlinkat",
					Syscall: true,
					Args: []Arg{
						{Index: 0, Type: "int"},
						{Index: 1, Type: "string"},
					},
					Selectors: []Selector{
						{
							MatchArgs: []MatchArg{
								{Index: 1, Operator: "Prefix", Values: []string{
									"/var/backup/", "/backup/", "/var/lib/etcd/",
								}},
							},
							MatchActions: []MatchAction{{Action: g.action}},
						},
					},
				},
				{
					Call:    "sys_execve",
					Syscall: true,
					Args:    []Arg{{Index: 0, Type: "string"}},
					Selectors: []Selector{
						{
							MatchArgs: []MatchArg{
								{Index: 0, Operator: "Postfix", Values: []string{
									"/vgremove", "/lvremove", "/pvremove",
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

func (g *Generator) groupDiscoveryPolicy(events []cdr.Event, dateStr string) *TracingPolicy {
	name := fmt.Sprintf("cdr-block-group-discovery-%s", dateStr)
	return &TracingPolicy{
		APIVersion: "cilium.io/v1alpha1",
		Kind:       "TracingPolicy",
		Name:       name,
		Metadata: Metadata{
			Name: name,
			Labels: map[string]string{
				"generated-by":               "qualys-cdr-operator",
				"mitre.attack/technique":     "T1069",
				"mitre.attack/tactic":        "discovery",
				"policy.qualys.com/priority": "medium",
			},
			Annotations: map[string]string{
				"description": "Detect permission and group enumeration",
				"event-count": fmt.Sprintf("%d", len(events)),
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
									"/id", "/groups", "/getent", "/members",
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

func (g *Generator) remoteServicesPolicy(events []cdr.Event, dateStr string) *TracingPolicy {
	name := fmt.Sprintf("cdr-block-remote-services-%s", dateStr)
	return &TracingPolicy{
		APIVersion: "cilium.io/v1alpha1",
		Kind:       "TracingPolicy",
		Name:       name,
		Metadata: Metadata{
			Name: name,
			Labels: map[string]string{
				"generated-by":               "qualys-cdr-operator",
				"mitre.attack/technique":     "T1133",
				"mitre.attack/tactic":        "initial-access",
				"policy.qualys.com/priority": "high",
			},
			Annotations: map[string]string{
				"description": "Block external remote service clients",
				"event-count": fmt.Sprintf("%d", len(events)),
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
									"/rdesktop", "/xfreerdp", "/vncviewer", "/tigervnc",
									"/remmina", "/vinagre",
								}},
							},
							MatchActions: []MatchAction{{Action: g.action}},
						},
					},
				},
				{
					Call:    "sys_connect",
					Syscall: true,
					Args:    []Arg{{Index: 1, Type: "sockaddr"}},
					Selectors: []Selector{
						{
							MatchArgs: []MatchArg{
								{Index: 1, Operator: "DPort", Values: []string{
									"3389", "5900", "5901", "5902",
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

func (g *Generator) deployContainerPolicy(events []cdr.Event, dateStr string) *TracingPolicy {
	name := fmt.Sprintf("cdr-block-deploy-container-%s", dateStr)
	return &TracingPolicy{
		APIVersion: "cilium.io/v1alpha1",
		Kind:       "TracingPolicy",
		Name:       name,
		Metadata: Metadata{
			Name: name,
			Labels: map[string]string{
				"generated-by":               "qualys-cdr-operator",
				"mitre.attack/technique":     "T1610",
				"mitre.attack/tactic":        "execution",
				"policy.qualys.com/priority": "high",
			},
			Annotations: map[string]string{
				"description": "Block unauthorized container deployments",
				"event-count": fmt.Sprintf("%d", len(events)),
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
									"/docker", "/podman", "/ctr", "/crictl", "/nerdctl",
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

func (g *Generator) containerAdminPolicy(events []cdr.Event, dateStr string) *TracingPolicy {
	name := fmt.Sprintf("cdr-block-container-admin-%s", dateStr)
	return &TracingPolicy{
		APIVersion: "cilium.io/v1alpha1",
		Kind:       "TracingPolicy",
		Name:       name,
		Metadata: Metadata{
			Name: name,
			Labels: map[string]string{
				"generated-by":               "qualys-cdr-operator",
				"mitre.attack/technique":     "T1609",
				"mitre.attack/tactic":        "execution",
				"policy.qualys.com/priority": "high",
			},
			Annotations: map[string]string{
				"description": "Block container administration commands from untrusted sources",
				"event-count": fmt.Sprintf("%d", len(events)),
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
									"/kubectl", "/oc", "/helm", "/kustomize",
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

// Anomaly represents an AI-detected anomaly for policy generation.
type Anomaly struct {
	Type          string
	Feature       string
	ContainerID   string
	ContainerName string
	Namespace     string
	Score         float64
	ProcessName   string
	FilePath      string
	NetworkPort   int
	Description   string
}

// FromAnomaly generates a TracingPolicy from an AI-detected anomaly.
func (g *Generator) FromAnomaly(anomaly Anomaly) *TracingPolicy {
	dateStr := time.Now().Format("20060102")

	switch {
	case anomaly.Feature == "syscall_rate" || anomaly.Feature == "exec_rate":
		return g.anomalyExecRatePolicy(anomaly, dateStr)
	case anomaly.Feature == "network_connections" || anomaly.Feature == "outbound_bytes":
		return g.anomalyNetworkPolicy(anomaly, dateStr)
	case anomaly.Feature == "file_access" || anomaly.Feature == "file_writes":
		return g.anomalyFileAccessPolicy(anomaly, dateStr)
	case anomaly.Feature == "privilege_escalation":
		return g.anomalyPrivEscPolicy(anomaly, dateStr)
	default:
		return g.anomalyGenericPolicy(anomaly, dateStr)
	}
}

func (g *Generator) anomalyExecRatePolicy(anomaly Anomaly, dateStr string) *TracingPolicy {
	name := fmt.Sprintf("ai-anomaly-exec-%s-%s", anomaly.ContainerName, dateStr)
	return &TracingPolicy{
		APIVersion: "cilium.io/v1alpha1",
		Kind:       "TracingPolicy",
		Name:       name,
		Metadata: Metadata{
			Name: name,
			Labels: map[string]string{
				"generated-by":               "qualys-ai-detector",
				"ai.qualys.com/anomaly-type": anomaly.Type,
				"ai.qualys.com/feature":      anomaly.Feature,
				"policy.qualys.com/priority": "high",
			},
			Annotations: map[string]string{
				"description":           fmt.Sprintf("AI-detected execution anomaly: %s", anomaly.Description),
				"ai.qualys.com/score":   fmt.Sprintf("%.2f", anomaly.Score),
				"container-id":          anomaly.ContainerID,
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
							MatchActions: []MatchAction{{Action: g.action}},
						},
					},
				},
			},
		},
	}
}

func (g *Generator) anomalyNetworkPolicy(anomaly Anomaly, dateStr string) *TracingPolicy {
	name := fmt.Sprintf("ai-anomaly-network-%s-%s", anomaly.ContainerName, dateStr)

	portValues := []string{"0"}
	if anomaly.NetworkPort > 0 {
		portValues = []string{fmt.Sprintf("%d", anomaly.NetworkPort)}
	}

	return &TracingPolicy{
		APIVersion: "cilium.io/v1alpha1",
		Kind:       "TracingPolicy",
		Name:       name,
		Metadata: Metadata{
			Name: name,
			Labels: map[string]string{
				"generated-by":               "qualys-ai-detector",
				"ai.qualys.com/anomaly-type": anomaly.Type,
				"ai.qualys.com/feature":      anomaly.Feature,
				"mitre.attack/technique":     "T1071",
				"policy.qualys.com/priority": "high",
			},
			Annotations: map[string]string{
				"description":           fmt.Sprintf("AI-detected network anomaly: %s", anomaly.Description),
				"ai.qualys.com/score":   fmt.Sprintf("%.2f", anomaly.Score),
				"container-id":          anomaly.ContainerID,
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
								{Index: 1, Operator: "DPort", Values: portValues},
							},
							MatchActions: []MatchAction{{Action: g.action}},
						},
					},
				},
			},
		},
	}
}

func (g *Generator) anomalyFileAccessPolicy(anomaly Anomaly, dateStr string) *TracingPolicy {
	name := fmt.Sprintf("ai-anomaly-file-%s-%s", anomaly.ContainerName, dateStr)

	pathValues := []string{"/"}
	if anomaly.FilePath != "" {
		pathValues = []string{anomaly.FilePath}
	}

	return &TracingPolicy{
		APIVersion: "cilium.io/v1alpha1",
		Kind:       "TracingPolicy",
		Name:       name,
		Metadata: Metadata{
			Name: name,
			Labels: map[string]string{
				"generated-by":               "qualys-ai-detector",
				"ai.qualys.com/anomaly-type": anomaly.Type,
				"ai.qualys.com/feature":      anomaly.Feature,
				"mitre.attack/technique":     "T1083",
				"policy.qualys.com/priority": "medium",
			},
			Annotations: map[string]string{
				"description":           fmt.Sprintf("AI-detected file access anomaly: %s", anomaly.Description),
				"ai.qualys.com/score":   fmt.Sprintf("%.2f", anomaly.Score),
				"container-id":          anomaly.ContainerID,
			},
		},
		Spec: TracingPolicySpec{
			Kprobes: []Kprobe{
				{
					Call:    "sys_openat",
					Syscall: true,
					Args: []Arg{
						{Index: 0, Type: "int"},
						{Index: 1, Type: "string"},
					},
					Selectors: []Selector{
						{
							MatchArgs: []MatchArg{
								{Index: 1, Operator: "Prefix", Values: pathValues},
							},
							MatchActions: []MatchAction{{Action: g.action}},
						},
					},
				},
			},
		},
	}
}

func (g *Generator) anomalyPrivEscPolicy(anomaly Anomaly, dateStr string) *TracingPolicy {
	name := fmt.Sprintf("ai-anomaly-privesc-%s-%s", anomaly.ContainerName, dateStr)
	return &TracingPolicy{
		APIVersion: "cilium.io/v1alpha1",
		Kind:       "TracingPolicy",
		Name:       name,
		Metadata: Metadata{
			Name: name,
			Labels: map[string]string{
				"generated-by":               "qualys-ai-detector",
				"ai.qualys.com/anomaly-type": anomaly.Type,
				"ai.qualys.com/feature":      anomaly.Feature,
				"mitre.attack/technique":     "T1548",
				"policy.qualys.com/priority": "critical",
			},
			Annotations: map[string]string{
				"description":           fmt.Sprintf("AI-detected privilege escalation: %s", anomaly.Description),
				"ai.qualys.com/score":   fmt.Sprintf("%.2f", anomaly.Score),
				"container-id":          anomaly.ContainerID,
			},
		},
		Spec: TracingPolicySpec{
			Kprobes: []Kprobe{
				{
					Call:    "sys_setuid",
					Syscall: true,
					Selectors: []Selector{
						{MatchActions: []MatchAction{{Action: g.action}}},
					},
				},
				{
					Call:    "sys_setgid",
					Syscall: true,
					Selectors: []Selector{
						{MatchActions: []MatchAction{{Action: g.action}}},
					},
				},
				{
					Call:    "sys_capset",
					Syscall: true,
					Selectors: []Selector{
						{MatchActions: []MatchAction{{Action: g.action}}},
					},
				},
			},
		},
	}
}

func (g *Generator) anomalyGenericPolicy(anomaly Anomaly, dateStr string) *TracingPolicy {
	name := fmt.Sprintf("ai-anomaly-generic-%s-%s", anomaly.ContainerName, dateStr)
	return &TracingPolicy{
		APIVersion: "cilium.io/v1alpha1",
		Kind:       "TracingPolicy",
		Name:       name,
		Metadata: Metadata{
			Name: name,
			Labels: map[string]string{
				"generated-by":               "qualys-ai-detector",
				"ai.qualys.com/anomaly-type": anomaly.Type,
				"ai.qualys.com/feature":      anomaly.Feature,
				"policy.qualys.com/priority": "medium",
			},
			Annotations: map[string]string{
				"description":           fmt.Sprintf("AI-detected anomaly: %s", anomaly.Description),
				"ai.qualys.com/score":   fmt.Sprintf("%.2f", anomaly.Score),
				"container-id":          anomaly.ContainerID,
			},
		},
		Spec: TracingPolicySpec{
			Kprobes: []Kprobe{
				{
					Call:    "sys_execve",
					Syscall: true,
					Args:    []Arg{{Index: 0, Type: "string"}},
					Selectors: []Selector{
						{MatchActions: []MatchAction{{Action: "Post"}}},
					},
				},
			},
		},
	}
}
