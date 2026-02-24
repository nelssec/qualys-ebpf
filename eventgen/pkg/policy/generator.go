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

	switch {
	case strings.Contains(strings.ToLower(category), "container_escape"):
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
			Args: []drift.Arg{
				{Index: 0, Type: "int"},
				{Index: 1, Type: "int"},
			},
			Selectors: []drift.Selector{{
				MatchActions: []drift.MatchAction{{Action: action}},
			}},
		})

	case strings.Contains(strings.ToLower(category), "crypto_mining"):
		policy.Spec.KProbes = append(policy.Spec.KProbes, drift.KProbe{
			Call:    "sys_connect",
			Syscall: true,
			Args:    []drift.Arg{{Index: 1, Type: "sockaddr"}},
			Selectors: []drift.Selector{{
				MatchArgs: []drift.MatchArg{{
					Index:    1,
					Operator: "DPort",
					Values:   []string{"3333", "4444", "5555", "14433", "14444"},
				}},
				MatchActions: []drift.MatchAction{{Action: action}},
			}},
		})

	case strings.Contains(strings.ToLower(category), "credential"):
		policy.Spec.KProbes = append(policy.Spec.KProbes, drift.KProbe{
			Call:    "sys_openat",
			Syscall: true,
			Args:    []drift.Arg{{Index: 1, Type: "string"}},
			Selectors: []drift.Selector{{
				MatchArgs: []drift.MatchArg{{
					Index:    1,
					Operator: "Postfix",
					Values:   []string{"/etc/shadow", "/etc/passwd", "/.ssh/id_rsa", "/.aws/credentials"},
				}},
				MatchActions: []drift.MatchAction{{Action: action}},
			}},
		})

	case strings.Contains(strings.ToLower(category), "c2") || strings.Contains(strings.ToLower(category), "communication"):
		policy.Spec.KProbes = append(policy.Spec.KProbes, drift.KProbe{
			Call:    "sys_connect",
			Syscall: true,
			Args:    []drift.Arg{{Index: 1, Type: "sockaddr"}},
			Selectors: []drift.Selector{{
				MatchArgs: []drift.MatchArg{{
					Index:    1,
					Operator: "DPort",
					Values:   []string{"4444", "5555", "6666", "8443"},
				}},
				MatchActions: []drift.MatchAction{{Action: action}},
			}},
		})

	case strings.Contains(strings.ToLower(category), "network_scan"):
		policy.Spec.KProbes = append(policy.Spec.KProbes, drift.KProbe{
			Call:    "sys_execve",
			Syscall: true,
			Args:    []drift.Arg{{Index: 0, Type: "string"}},
			Selectors: []drift.Selector{{
				MatchArgs: []drift.MatchArg{{
					Index:    0,
					Operator: "Postfix",
					Values:   []string{"/nmap", "/masscan", "/zmap", "/netcat", "/nc"},
				}},
				MatchActions: []drift.MatchAction{{Action: action}},
			}},
		})

	default:
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
