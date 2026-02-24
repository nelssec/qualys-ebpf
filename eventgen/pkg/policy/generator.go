package policy

import (
	"fmt"
	"strings"
	"time"

	"github.com/qualys/eventgen/pkg/drift"
	"github.com/qualys/eventgen/pkg/events"
)

func GenerateFromEvent(event events.SecurityEvent, action string) *drift.TracingPolicy {
	policy := &drift.TracingPolicy{
		APIVersion: "cilium.io/v1alpha1",
		Kind:       "TracingPolicy",
		Metadata: drift.PolicyMetadata{
			Name: fmt.Sprintf("qcr-%s-%s", strings.ToLower(event.ID), sanitizeName(event.Name)[:25]),
			Labels: map[string]string{
				"qualys.com/event-id":          event.ID,
				"qualys.com/category":          sanitizeName(event.Category),
				"qualys.com/severity":          strings.ToLower(event.Severity),
				"app.kubernetes.io/managed-by": "qualys-crs",
			},
			Annotations: map[string]string{
				"qualys.com/description":       event.Description,
				"qualys.com/mitre-techniques": strings.Join(event.MITRE, ","),
			},
		},
		Spec: drift.PolicySpec{
			KProbes: []drift.KProbe{},
		},
	}

	kprobe := drift.KProbe{
		Call:    "sys_execve",
		Syscall: true,
		Args: []drift.Arg{
			{Index: 0, Type: "string"},
		},
		Selectors: []drift.Selector{
			{
				MatchActions: []drift.MatchAction{{Action: action}},
			},
		},
	}

	policy.Spec.KProbes = append(policy.Spec.KProbes, kprobe)

	return policy
}

func GenerateFromCDRCategory(category string, action string) *drift.TracingPolicy {
	timestamp := time.Now().Format("20060102")

	policy := &drift.TracingPolicy{
		APIVersion: "cilium.io/v1alpha1",
		Kind:       "TracingPolicy",
		Metadata: drift.PolicyMetadata{
			Name: fmt.Sprintf("cdr-%s-%s", sanitizeName(category), timestamp),
			Labels: map[string]string{
				"generated-by":                 "qualys-cdr",
				"threat.qualys.com/category":   sanitizeName(category),
				"app.kubernetes.io/managed-by": "qualys-crs",
			},
		},
		Spec: drift.PolicySpec{
			KProbes: []drift.KProbe{},
		},
	}

	cat := strings.ToLower(category)

	switch {
	case strings.Contains(cat, "bitcoin") || strings.Contains(cat, "mining") || strings.Contains(cat, "crypto"):
		policy.Metadata.Annotations = map[string]string{
			"qualys.com/description":      "Block connections to known mining pool ports",
			"qualys.com/mitre-techniques": "T1496",
		}
		policy.Spec.KProbes = append(policy.Spec.KProbes, drift.KProbe{
			Call:    "sys_connect",
			Syscall: true,
			Args:    []drift.Arg{{Index: 1, Type: "sockaddr"}},
			Selectors: []drift.Selector{{
				MatchArgs: []drift.MatchArg{{
					Index:    1,
					Operator: "DPort",
					Values:   []string{"3333", "3334", "4444", "5555", "7777", "8888", "9999", "14433", "14444", "45560"},
				}},
				MatchActions: []drift.MatchAction{{Action: action}},
			}},
		})

	case strings.Contains(cat, "ssh") && strings.Contains(cat, "password"):
		policy.Metadata.Annotations = map[string]string{
			"qualys.com/description":      "Block SSH brute force by monitoring auth failures",
			"qualys.com/mitre-techniques": "T1110.001",
		}
		policy.Spec.KProbes = append(policy.Spec.KProbes, drift.KProbe{
			Call:    "sys_connect",
			Syscall: true,
			Args:    []drift.Arg{{Index: 1, Type: "sockaddr"}},
			Selectors: []drift.Selector{{
				MatchArgs: []drift.MatchArg{{
					Index:    1,
					Operator: "DPort",
					Values:   []string{"22"},
				}},
				MatchActions: []drift.MatchAction{{Action: action}},
			}},
		})

	case strings.Contains(cat, "rdp"):
		policy.Metadata.Annotations = map[string]string{
			"qualys.com/description":      "Block RDP brute force attempts",
			"qualys.com/mitre-techniques": "T1110.001",
		}
		policy.Spec.KProbes = append(policy.Spec.KProbes, drift.KProbe{
			Call:    "sys_connect",
			Syscall: true,
			Args:    []drift.Arg{{Index: 1, Type: "sockaddr"}},
			Selectors: []drift.Selector{{
				MatchArgs: []drift.MatchArg{{
					Index:    1,
					Operator: "DPort",
					Values:   []string{"3389"},
				}},
				MatchActions: []drift.MatchAction{{Action: action}},
			}},
		})

	case strings.Contains(cat, "scan") || strings.Contains(cat, "port"):
		policy.Metadata.Annotations = map[string]string{
			"qualys.com/description":      "Block network scanning tools",
			"qualys.com/mitre-techniques": "T1046",
		}
		policy.Spec.KProbes = append(policy.Spec.KProbes, drift.KProbe{
			Call:    "sys_execve",
			Syscall: true,
			Args:    []drift.Arg{{Index: 0, Type: "string"}},
			Selectors: []drift.Selector{{
				MatchArgs: []drift.MatchArg{{
					Index:    0,
					Operator: "Postfix",
					Values:   []string{"/nmap", "/masscan", "/zmap", "/netcat", "/nc", "/hping3"},
				}},
				MatchActions: []drift.MatchAction{{Action: action}},
			}},
		})

	case strings.Contains(cat, "trojan") || strings.Contains(cat, "malware") || strings.Contains(cat, "backdoor"):
		policy.Metadata.Annotations = map[string]string{
			"qualys.com/description":      "Block execution from temp/writable directories",
			"qualys.com/mitre-techniques": "T1204",
		}
		policy.Spec.KProbes = append(policy.Spec.KProbes, drift.KProbe{
			Call:    "sys_execve",
			Syscall: true,
			Args:    []drift.Arg{{Index: 0, Type: "string"}},
			Selectors: []drift.Selector{{
				MatchArgs: []drift.MatchArg{{
					Index:    0,
					Operator: "Prefix",
					Values:   []string{"/tmp/", "/var/tmp/", "/dev/shm/", "/run/"},
				}},
				MatchActions: []drift.MatchAction{{Action: action}},
			}},
		})

	case strings.Contains(cat, "container_escape") || strings.Contains(cat, "escape"):
		policy.Metadata.Annotations = map[string]string{
			"qualys.com/description":      "Block container escape via namespace manipulation",
			"qualys.com/mitre-techniques": "T1611",
		}
		policy.Spec.KProbes = append(policy.Spec.KProbes, drift.KProbe{
			Call:    "sys_unshare",
			Syscall: true,
			Args:    []drift.Arg{{Index: 0, Type: "int"}},
			Selectors: []drift.Selector{{
				MatchActions: []drift.MatchAction{{Action: action}},
			}},
		})
		policy.Spec.KProbes = append(policy.Spec.KProbes, drift.KProbe{
			Call:    "sys_setns",
			Syscall: true,
			Args:    []drift.Arg{{Index: 0, Type: "int"}, {Index: 1, Type: "int"}},
			Selectors: []drift.Selector{{
				MatchActions: []drift.MatchAction{{Action: action}},
			}},
		})

	case strings.Contains(cat, "credential"):
		policy.Metadata.Annotations = map[string]string{
			"qualys.com/description":      "Block access to credential files",
			"qualys.com/mitre-techniques": "T1552.001",
		}
		policy.Spec.KProbes = append(policy.Spec.KProbes, drift.KProbe{
			Call:    "sys_openat",
			Syscall: true,
			Args:    []drift.Arg{{Index: 1, Type: "string"}},
			Selectors: []drift.Selector{{
				MatchArgs: []drift.MatchArg{{
					Index:    1,
					Operator: "Postfix",
					Values:   []string{"/etc/shadow", "/.ssh/id_rsa", "/.aws/credentials", "/.kube/config"},
				}},
				MatchActions: []drift.MatchAction{{Action: action}},
			}},
		})

	default:
		policy.Metadata.Annotations = map[string]string{
			"qualys.com/description": fmt.Sprintf("Generic detection for %s", category),
		}
		policy.Spec.KProbes = append(policy.Spec.KProbes, drift.KProbe{
			Call:    "sys_execve",
			Syscall: true,
			Args:    []drift.Arg{{Index: 0, Type: "string"}},
			Selectors: []drift.Selector{{
				MatchActions: []drift.MatchAction{{Action: action}},
			}},
		})
	}

	return policy
}

func sanitizeName(s string) string {
	s = strings.ToLower(s)
	s = strings.ReplaceAll(s, " ", "-")
	s = strings.ReplaceAll(s, "_", "-")

	result := ""
	for _, c := range s {
		if (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' {
			result += string(c)
		}
	}

	for strings.Contains(result, "--") {
		result = strings.ReplaceAll(result, "--", "-")
	}

	result = strings.Trim(result, "-")

	if len(result) > 63 {
		result = result[:63]
	}

	return result
}
