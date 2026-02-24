package drift

import (
	"fmt"
	"strings"
)

var DefaultMutablePaths = []string{
	"/tmp",
	"/var/tmp",
	"/dev/shm",
	"/run",
	"/var/run",
	"/var/cache",
	"/proc",
	"/sys",
}

var DefaultBlockedWritePaths = []string{
	"/bin",
	"/sbin",
	"/usr/bin",
	"/usr/sbin",
	"/usr/local/bin",
	"/usr/local/sbin",
	"/lib",
	"/lib64",
	"/usr/lib",
	"/usr/lib64",
	"/opt",
}

var RuntimeBlockBinaries = []string{
	"/apt",
	"/apt-get",
	"/yum",
	"/dnf",
	"/apk",
	"/pip",
	"/pip3",
	"/npm",
	"/yarn",
	"/gem",
	"/cargo",
	"/go",
	"/curl",
	"/wget",
}

type TracingPolicy struct {
	APIVersion string                 `yaml:"apiVersion"`
	Kind       string                 `yaml:"kind"`
	Metadata   PolicyMetadata         `yaml:"metadata"`
	Spec       PolicySpec             `yaml:"spec"`
}

type PolicyMetadata struct {
	Name        string            `yaml:"name"`
	Labels      map[string]string `yaml:"labels,omitempty"`
	Annotations map[string]string `yaml:"annotations,omitempty"`
}

type PolicySpec struct {
	KProbes     []KProbe    `yaml:"kprobes,omitempty"`
	PodSelector *PodSelector `yaml:"podSelector,omitempty"`
}

type KProbe struct {
	Call      string     `yaml:"call"`
	Syscall   bool       `yaml:"syscall"`
	Args      []Arg      `yaml:"args,omitempty"`
	Selectors []Selector `yaml:"selectors,omitempty"`
}

type Arg struct {
	Index int    `yaml:"index"`
	Type  string `yaml:"type"`
}

type Selector struct {
	MatchArgs    []MatchArg    `yaml:"matchArgs,omitempty"`
	MatchActions []MatchAction `yaml:"matchActions,omitempty"`
}

type MatchArg struct {
	Index    int      `yaml:"index"`
	Operator string   `yaml:"operator"`
	Values   []string `yaml:"values"`
}

type MatchAction struct {
	Action string `yaml:"action"`
}

type PodSelector struct {
	MatchLabels map[string]string `yaml:"matchLabels,omitempty"`
	Namespace   string            `yaml:"namespace,omitempty"`
}

func GenerateDriftDetectionPolicy(namespace string) *TracingPolicy {
	policy := &TracingPolicy{
		APIVersion: "cilium.io/v1alpha1",
		Kind:       "TracingPolicy",
		Metadata: PolicyMetadata{
			Name: "qcr-drift-detection",
			Labels: map[string]string{
				"qualys.com/policy-type": "drift-detection",
				"qualys.com/category":    "container-immutability",
				"app.kubernetes.io/managed-by": "qualys-crs",
			},
			Annotations: map[string]string{
				"qualys.com/description":       "Detects creation of new executable files in running containers",
				"qualys.com/mitre-techniques": "T1036,T1027",
			},
		},
		Spec: PolicySpec{
			KProbes: []KProbe{
				{
					Call:    "sys_openat",
					Syscall: true,
					Args: []Arg{
						{Index: 1, Type: "string"},
						{Index: 2, Type: "int"},
					},
					Selectors: []Selector{{
						MatchArgs: []MatchArg{
							{Index: 1, Operator: "Prefix", Values: []string{"/tmp/", "/var/tmp/", "/dev/shm/", "/run/"}},
							{Index: 2, Operator: "Mask", Values: []string{"64"}},
						},
						MatchActions: []MatchAction{{Action: "Post"}},
					}},
				},
				{
					Call:    "sys_chmod",
					Syscall: true,
					Args: []Arg{
						{Index: 0, Type: "string"},
						{Index: 1, Type: "int"},
					},
					Selectors: []Selector{{
						MatchArgs:    []MatchArg{{Index: 1, Operator: "Mask", Values: []string{"73"}}},
						MatchActions: []MatchAction{{Action: "Post"}},
					}},
				},
			},
		},
	}

	if namespace != "" {
		policy.Spec.PodSelector = &PodSelector{Namespace: namespace}
	}

	return policy
}

func GenerateDriftEnforcementPolicy(namespace string) *TracingPolicy {
	policy := &TracingPolicy{
		APIVersion: "cilium.io/v1alpha1",
		Kind:       "TracingPolicy",
		Metadata: PolicyMetadata{
			Name: "qcr-drift-enforcement",
			Labels: map[string]string{
				"qualys.com/policy-type": "drift-enforcement",
				"qualys.com/category":    "container-immutability",
				"app.kubernetes.io/managed-by": "qualys-crs",
			},
			Annotations: map[string]string{
				"qualys.com/description":       "Blocks execution of binaries created after container start",
				"qualys.com/mitre-techniques": "T1036,T1027",
			},
		},
		Spec: PolicySpec{
			KProbes: []KProbe{
				{
					Call:    "sys_execve",
					Syscall: true,
					Args:    []Arg{{Index: 0, Type: "string"}},
					Selectors: []Selector{{
						MatchArgs: []MatchArg{
							{Index: 0, Operator: "Prefix", Values: []string{"/tmp/", "/var/tmp/", "/dev/shm/", "/run/user/"}},
						},
						MatchActions: []MatchAction{{Action: "Sigkill"}},
					}},
				},
			},
		},
	}

	if namespace != "" {
		policy.Spec.PodSelector = &PodSelector{Namespace: namespace}
	}

	return policy
}

func GenerateBinaryPathEnforcementPolicy(namespace string) *TracingPolicy {
	policy := &TracingPolicy{
		APIVersion: "cilium.io/v1alpha1",
		Kind:       "TracingPolicy",
		Metadata: PolicyMetadata{
			Name: "qcr-binary-path-enforcement",
			Labels: map[string]string{
				"qualys.com/policy-type": "binary-path-protection",
				"qualys.com/category":    "container-immutability",
				"app.kubernetes.io/managed-by": "qualys-crs",
			},
			Annotations: map[string]string{
				"qualys.com/description":    "Blocks write operations to system binary directories",
				"qualys.com/blocked-paths": strings.Join(DefaultBlockedWritePaths[:5], ","),
			},
		},
		Spec: PolicySpec{
			KProbes: []KProbe{
				{
					Call:    "sys_openat",
					Syscall: true,
					Args: []Arg{
						{Index: 1, Type: "string"},
						{Index: 2, Type: "int"},
					},
					Selectors: []Selector{{
						MatchArgs: []MatchArg{
							{Index: 1, Operator: "Prefix", Values: DefaultBlockedWritePaths},
							{Index: 2, Operator: "Mask", Values: []string{"1", "2", "64"}},
						},
						MatchActions: []MatchAction{{Action: "Sigkill"}},
					}},
				},
				{
					Call:    "sys_unlink",
					Syscall: true,
					Args:    []Arg{{Index: 0, Type: "string"}},
					Selectors: []Selector{{
						MatchArgs:    []MatchArg{{Index: 0, Operator: "Prefix", Values: DefaultBlockedWritePaths}},
						MatchActions: []MatchAction{{Action: "Sigkill"}},
					}},
				},
			},
		},
	}

	return policy
}

func GeneratePackageManagerBlockPolicy(namespace string, enforce bool) *TracingPolicy {
	action := "Post"
	mode := "detect"
	if enforce {
		action = "Sigkill"
		mode = "enforce"
	}

	policy := &TracingPolicy{
		APIVersion: "cilium.io/v1alpha1",
		Kind:       "TracingPolicy",
		Metadata: PolicyMetadata{
			Name: fmt.Sprintf("qcr-block-package-managers-%s", mode),
			Labels: map[string]string{
				"qualys.com/policy-type": "package-manager-block",
				"qualys.com/category":    "container-immutability",
				"qualys.com/mode":        mode,
				"app.kubernetes.io/managed-by": "qualys-crs",
			},
			Annotations: map[string]string{
				"qualys.com/description": "Blocks package manager and download tool execution in production",
			},
		},
		Spec: PolicySpec{
			KProbes: []KProbe{
				{
					Call:    "sys_execve",
					Syscall: true,
					Args: []Arg{
						{Index: 0, Type: "string"},
						{Index: 1, Type: "string"},
					},
					Selectors: []Selector{{
						MatchArgs:    []MatchArg{{Index: 0, Operator: "Postfix", Values: RuntimeBlockBinaries}},
						MatchActions: []MatchAction{{Action: action}},
					}},
				},
			},
		},
	}

	if namespace != "" {
		policy.Spec.PodSelector = &PodSelector{Namespace: namespace}
	}

	return policy
}

func GenerateDownloadToolBlockPolicy(namespace string, enforce bool) *TracingPolicy {
	action := "Post"
	mode := "detect"
	if enforce {
		action = "Sigkill"
		mode = "enforce"
	}

	downloadTools := []string{
		"/curl", "/wget", "/fetch", "/aria2c",
		"/scp", "/sftp", "/rsync", "/ftp",
	}

	policy := &TracingPolicy{
		APIVersion: "cilium.io/v1alpha1",
		Kind:       "TracingPolicy",
		Metadata: PolicyMetadata{
			Name: fmt.Sprintf("qcr-block-download-tools-%s", mode),
			Labels: map[string]string{
				"qualys.com/policy-type": "download-tool-block",
				"qualys.com/category":    "container-immutability",
				"qualys.com/mode":        mode,
				"app.kubernetes.io/managed-by": "qualys-crs",
			},
		},
		Spec: PolicySpec{
			KProbes: []KProbe{
				{
					Call:    "sys_execve",
					Syscall: true,
					Args:    []Arg{{Index: 0, Type: "string"}},
					Selectors: []Selector{{
						MatchArgs:    []MatchArg{{Index: 0, Operator: "Postfix", Values: downloadTools}},
						MatchActions: []MatchAction{{Action: action}},
					}},
				},
			},
		},
	}

	if namespace != "" {
		policy.Spec.PodSelector = &PodSelector{Namespace: namespace}
	}

	return policy
}

func GenerateScriptInterpreterLockdownPolicy(namespace string) *TracingPolicy {
	interpreters := []string{
		"/python", "/python3", "/python2",
		"/perl", "/ruby", "/php",
		"/node", "/nodejs",
	}

	writablePaths := []string{"/tmp/", "/var/tmp/", "/dev/shm/", "/run/"}

	policy := &TracingPolicy{
		APIVersion: "cilium.io/v1alpha1",
		Kind:       "TracingPolicy",
		Metadata: PolicyMetadata{
			Name: "qcr-script-interpreter-lockdown",
			Labels: map[string]string{
				"qualys.com/policy-type":        "script-interpreter-lockdown",
				"qualys.com/category":           "container-immutability",
				"app.kubernetes.io/managed-by":  "qualys-crs",
			},
			Annotations: map[string]string{
				"qualys.com/description": "Blocks script interpreters from executing scripts in writable paths",
			},
		},
		Spec: PolicySpec{
			KProbes: []KProbe{
				{
					Call:    "sys_execve",
					Syscall: true,
					Args: []Arg{
						{Index: 0, Type: "string"},
						{Index: 1, Type: "string"},
					},
					Selectors: []Selector{{
						MatchArgs: []MatchArg{
							{Index: 0, Operator: "Postfix", Values: interpreters},
							{Index: 1, Operator: "Prefix", Values: writablePaths},
						},
						MatchActions: []MatchAction{{Action: "Sigkill"}},
					}},
				},
			},
		},
	}

	if namespace != "" {
		policy.Spec.PodSelector = &PodSelector{Namespace: namespace}
	}

	return policy
}

func GenerateMemoryExecutionBlockPolicy(namespace string) *TracingPolicy {
	policy := &TracingPolicy{
		APIVersion: "cilium.io/v1alpha1",
		Kind:       "TracingPolicy",
		Metadata: PolicyMetadata{
			Name: "qcr-memory-execution-block",
			Labels: map[string]string{
				"qualys.com/policy-type":        "memory-execution-block",
				"qualys.com/category":           "fileless-malware-prevention",
				"app.kubernetes.io/managed-by":  "qualys-crs",
			},
			Annotations: map[string]string{
				"qualys.com/description":       "Blocks fileless malware via memfd_create",
				"qualys.com/mitre-techniques": "T1620",
			},
		},
		Spec: PolicySpec{
			KProbes: []KProbe{
				{
					Call:    "sys_memfd_create",
					Syscall: true,
					Args:    []Arg{{Index: 0, Type: "string"}},
					Selectors: []Selector{{
						MatchActions: []MatchAction{{Action: "Sigkill"}},
					}},
				},
			},
		},
	}

	if namespace != "" {
		policy.Spec.PodSelector = &PodSelector{Namespace: namespace}
	}

	return policy
}

func GenerateChmodBlockPolicy(namespace string) *TracingPolicy {
	policy := &TracingPolicy{
		APIVersion: "cilium.io/v1alpha1",
		Kind:       "TracingPolicy",
		Metadata: PolicyMetadata{
			Name: "qcr-chmod-block",
			Labels: map[string]string{
				"qualys.com/policy-type":        "chmod-block",
				"qualys.com/category":           "container-immutability",
				"app.kubernetes.io/managed-by":  "qualys-crs",
			},
			Annotations: map[string]string{
				"qualys.com/description": "Blocks making files executable at runtime (chmod +x)",
			},
		},
		Spec: PolicySpec{
			KProbes: []KProbe{
				{
					Call:    "sys_chmod",
					Syscall: true,
					Args: []Arg{
						{Index: 0, Type: "string"},
						{Index: 1, Type: "int"},
					},
					Selectors: []Selector{{
						MatchArgs:    []MatchArg{{Index: 1, Operator: "Mask", Values: []string{"73"}}},
						MatchActions: []MatchAction{{Action: "Sigkill"}},
					}},
				},
				{
					Call:    "sys_fchmod",
					Syscall: true,
					Args:    []Arg{{Index: 1, Type: "int"}},
					Selectors: []Selector{{
						MatchArgs:    []MatchArg{{Index: 1, Operator: "Mask", Values: []string{"73"}}},
						MatchActions: []MatchAction{{Action: "Sigkill"}},
					}},
				},
				{
					Call:    "sys_fchmodat",
					Syscall: true,
					Args:    []Arg{{Index: 2, Type: "int"}},
					Selectors: []Selector{{
						MatchArgs:    []MatchArg{{Index: 2, Operator: "Mask", Values: []string{"73"}}},
						MatchActions: []MatchAction{{Action: "Sigkill"}},
					}},
				},
			},
		},
	}

	if namespace != "" {
		policy.Spec.PodSelector = &PodSelector{Namespace: namespace}
	}

	return policy
}

func GenerateReverseShellBlockPolicy(namespace string) *TracingPolicy {
	shells := []string{"/bash", "/sh", "/zsh", "/dash", "/ksh", "/csh"}

	policy := &TracingPolicy{
		APIVersion: "cilium.io/v1alpha1",
		Kind:       "TracingPolicy",
		Metadata: PolicyMetadata{
			Name: "qcr-reverse-shell-block",
			Labels: map[string]string{
				"qualys.com/policy-type":        "reverse-shell-block",
				"qualys.com/category":           "c2-prevention",
				"app.kubernetes.io/managed-by":  "qualys-crs",
			},
			Annotations: map[string]string{
				"qualys.com/description":       "Blocks reverse shell attempts via network-connected shells",
				"qualys.com/mitre-techniques": "T1059.004",
			},
		},
		Spec: PolicySpec{
			KProbes: []KProbe{
				{
					Call:    "sys_connect",
					Syscall: true,
					Args:    []Arg{{Index: 1, Type: "sockaddr"}},
					Selectors: []Selector{{
						MatchArgs: []MatchArg{{
							Index:    1,
							Operator: "DPort",
							Values:   []string{"4444", "4445", "4446", "5555", "6666", "1337", "31337"},
						}},
						MatchActions: []MatchAction{{Action: "Sigkill"}},
					}},
				},
			},
		},
	}

	_ = shells

	if namespace != "" {
		policy.Spec.PodSelector = &PodSelector{Namespace: namespace}
	}

	return policy
}

func ListDriftPolicies() string {
	lines := []string{
		"Qualys CRS Drift Management Policies",
		strings.Repeat("=", 50),
		"",
		"DETECTION MODE (--mode detect):",
		"  - drift-detection: Alerts on new executable creation",
		"  - package-manager-detect: Alerts on package manager usage",
		"",
		"ENFORCEMENT MODE (--mode enforce):",
		"  - drift-enforcement: Blocks execution from temp directories",
		"  - binary-path-enforcement: Blocks writes to /bin, /usr/bin, etc.",
		"  - package-manager-block: Kills package manager processes",
		"  - download-tool-block: Kills download tools (curl, wget)",
		"",
		"LOCKDOWN MODE (--mode lockdown):",
		"  - script-interpreter-lockdown: Blocks interpreters running from /tmp",
		"  - memory-execution-block: Blocks fileless malware (memfd_create)",
		"  - chmod-block: Blocks chmod +x at runtime",
		"  - reverse-shell-block: Blocks reverse shell connections",
		"",
		"PROTECTED PATHS:",
	}

	for _, p := range DefaultBlockedWritePaths {
		lines = append(lines, "  "+p)
	}

	lines = append(lines, "", "BLOCKED BINARIES (runtime):")
	for _, b := range RuntimeBlockBinaries {
		lines = append(lines, "  "+b)
	}

	return strings.Join(lines, "\n")
}
