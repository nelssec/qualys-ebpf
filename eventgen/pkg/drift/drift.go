package drift

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
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

// ExecutableInfo tracks an executable's baseline information.
type ExecutableInfo struct {
	Path      string    `json:"path"`
	Hash      string    `json:"hash"`
	Size      int64     `json:"size"`
	Mode      os.FileMode `json:"mode"`
	FirstSeen time.Time `json:"firstSeen"`
}

// ContainerBaseline represents the known-good state of a container.
type ContainerBaseline struct {
	ContainerID   string                     `json:"containerId"`
	ImageID       string                     `json:"imageId"`
	ImageName     string                     `json:"imageName"`
	CreatedAt     time.Time                  `json:"createdAt"`
	Executables   map[string]*ExecutableInfo `json:"executables"`
	LearnedAt     time.Time                  `json:"learnedAt"`
	LearningMode  bool                       `json:"learningMode"`
}

// DriftEvent represents a detected drift from baseline.
type DriftEvent struct {
	ContainerID   string    `json:"containerId"`
	ContainerName string    `json:"containerName"`
	ImageName     string    `json:"imageName"`
	EventType     string    `json:"eventType"` // "new_executable", "modified_executable", "deleted_executable"
	Path          string    `json:"path"`
	OldHash       string    `json:"oldHash,omitempty"`
	NewHash       string    `json:"newHash,omitempty"`
	DetectedAt    time.Time `json:"detectedAt"`
	Severity      string    `json:"severity"`
	MITRETechnique string   `json:"mitreTechnique"`
}

// DriftDetector monitors containers for drift from their original image.
type DriftDetector struct {
	baselines      map[string]*ContainerBaseline
	mu             sync.RWMutex
	learningPeriod time.Duration
	blockDrift     bool
	eventChan      chan *DriftEvent

	// Callbacks
	onDriftDetected func(*DriftEvent)
}

// NewDriftDetector creates a new drift detector.
func NewDriftDetector(learningPeriod time.Duration, blockDrift bool) *DriftDetector {
	return &DriftDetector{
		baselines:      make(map[string]*ContainerBaseline),
		learningPeriod: learningPeriod,
		blockDrift:     blockDrift,
		eventChan:      make(chan *DriftEvent, 100),
	}
}

// SetDriftCallback sets the callback for drift events.
func (d *DriftDetector) SetDriftCallback(callback func(*DriftEvent)) {
	d.onDriftDetected = callback
}

// Events returns the channel for drift events.
func (d *DriftDetector) Events() <-chan *DriftEvent {
	return d.eventChan
}

// RegisterContainer creates a baseline for a new container.
func (d *DriftDetector) RegisterContainer(containerID, imageID, imageName string) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	if _, exists := d.baselines[containerID]; exists {
		return nil // Already registered
	}

	baseline := &ContainerBaseline{
		ContainerID:  containerID,
		ImageID:      imageID,
		ImageName:    imageName,
		CreatedAt:    time.Now(),
		Executables:  make(map[string]*ExecutableInfo),
		LearningMode: true,
	}

	d.baselines[containerID] = baseline
	fmt.Printf("[Drift] Registered container %s (image: %s), learning mode enabled\n", containerID[:12], imageName)

	// Schedule end of learning period
	go func() {
		time.Sleep(d.learningPeriod)
		d.mu.Lock()
		if b, ok := d.baselines[containerID]; ok {
			b.LearningMode = false
			b.LearnedAt = time.Now()
			fmt.Printf("[Drift] Container %s learning complete, %d executables baselined\n",
				containerID[:12], len(b.Executables))
		}
		d.mu.Unlock()
	}()

	return nil
}

// UnregisterContainer removes a container from tracking.
func (d *DriftDetector) UnregisterContainer(containerID string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	delete(d.baselines, containerID)
}

// CheckExecutable checks if an executable matches the baseline.
func (d *DriftDetector) CheckExecutable(containerID, path string, info os.FileInfo) (*DriftEvent, error) {
	d.mu.Lock()
	defer d.mu.Unlock()

	baseline, exists := d.baselines[containerID]
	if !exists {
		return nil, nil // Container not tracked
	}

	// Calculate hash of executable
	hash, err := hashFile(path)
	if err != nil {
		return nil, err
	}

	execInfo := &ExecutableInfo{
		Path:      path,
		Hash:      hash,
		Size:      info.Size(),
		Mode:      info.Mode(),
		FirstSeen: time.Now(),
	}

	// During learning mode, just record executables
	if baseline.LearningMode {
		baseline.Executables[path] = execInfo
		return nil, nil
	}

	// Check against baseline
	baselineExec, known := baseline.Executables[path]

	if !known {
		// New executable not in baseline - DRIFT DETECTED
		event := &DriftEvent{
			ContainerID:    containerID,
			ImageName:      baseline.ImageName,
			EventType:      "new_executable",
			Path:           path,
			NewHash:        hash,
			DetectedAt:     time.Now(),
			Severity:       "critical",
			MITRETechnique: "T1059.004", // Command and Scripting Interpreter
		}

		d.emitEvent(event)
		return event, nil
	}

	if baselineExec.Hash != hash {
		// Executable modified - DRIFT DETECTED
		event := &DriftEvent{
			ContainerID:    containerID,
			ImageName:      baseline.ImageName,
			EventType:      "modified_executable",
			Path:           path,
			OldHash:        baselineExec.Hash,
			NewHash:        hash,
			DetectedAt:     time.Now(),
			Severity:       "critical",
			MITRETechnique: "T1036", // Masquerading
		}

		d.emitEvent(event)
		return event, nil
	}

	return nil, nil // No drift
}

// ProcessExecEvent handles a process execution event from CDR.
func (d *DriftDetector) ProcessExecEvent(containerID, containerName, imageName, execPath string) *DriftEvent {
	d.mu.Lock()
	defer d.mu.Unlock()

	baseline, exists := d.baselines[containerID]
	if !exists {
		// Auto-register unknown container
		baseline = &ContainerBaseline{
			ContainerID:  containerID,
			ImageName:    imageName,
			CreatedAt:    time.Now(),
			Executables:  make(map[string]*ExecutableInfo),
			LearningMode: true,
		}
		d.baselines[containerID] = baseline

		// Start learning
		go func() {
			time.Sleep(d.learningPeriod)
			d.mu.Lock()
			if b, ok := d.baselines[containerID]; ok {
				b.LearningMode = false
				b.LearnedAt = time.Now()
			}
			d.mu.Unlock()
		}()
	}

	// During learning mode, record the executable
	if baseline.LearningMode {
		if _, known := baseline.Executables[execPath]; !known {
			baseline.Executables[execPath] = &ExecutableInfo{
				Path:      execPath,
				FirstSeen: time.Now(),
			}
		}
		return nil
	}

	// After learning, check for drift
	if _, known := baseline.Executables[execPath]; !known {
		event := &DriftEvent{
			ContainerID:    containerID,
			ContainerName:  containerName,
			ImageName:      imageName,
			EventType:      "new_executable",
			Path:           execPath,
			DetectedAt:     time.Now(),
			Severity:       "critical",
			MITRETechnique: "T1059.004",
		}

		d.emitEvent(event)
		return event
	}

	return nil
}

// GetBaseline returns the baseline for a container.
func (d *DriftDetector) GetBaseline(containerID string) *ContainerBaseline {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.baselines[containerID]
}

// GetAllBaselines returns all tracked baselines.
func (d *DriftDetector) GetAllBaselines() map[string]*ContainerBaseline {
	d.mu.RLock()
	defer d.mu.RUnlock()

	result := make(map[string]*ContainerBaseline)
	for k, v := range d.baselines {
		result[k] = v
	}
	return result
}

// Stats returns drift detector statistics.
func (d *DriftDetector) Stats() map[string]interface{} {
	d.mu.RLock()
	defer d.mu.RUnlock()

	learning := 0
	monitoring := 0
	totalExecutables := 0

	for _, b := range d.baselines {
		if b.LearningMode {
			learning++
		} else {
			monitoring++
		}
		totalExecutables += len(b.Executables)
	}

	return map[string]interface{}{
		"containers_learning":   learning,
		"containers_monitoring": monitoring,
		"total_executables":     totalExecutables,
		"block_drift":           d.blockDrift,
		"learning_period":       d.learningPeriod.String(),
	}
}

func (d *DriftDetector) emitEvent(event *DriftEvent) {
	select {
	case d.eventChan <- event:
	default:
		fmt.Printf("[Drift] Event channel full, dropping event\n")
	}

	if d.onDriftDetected != nil {
		go d.onDriftDetected(event)
	}
}

func hashFile(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}

	hash := sha256.Sum256(data)
	return hex.EncodeToString(hash[:]), nil
}

// ScanContainerFilesystem scans a container's filesystem for executables.
func ScanContainerFilesystem(rootfs string) (map[string]*ExecutableInfo, error) {
	executables := make(map[string]*ExecutableInfo)

	execDirs := []string{
		"/bin", "/sbin", "/usr/bin", "/usr/sbin",
		"/usr/local/bin", "/usr/local/sbin",
	}

	for _, dir := range execDirs {
		fullPath := filepath.Join(rootfs, dir)
		if _, err := os.Stat(fullPath); os.IsNotExist(err) {
			continue
		}

		filepath.Walk(fullPath, func(path string, info os.FileInfo, err error) error {
			if err != nil || info.IsDir() {
				return nil
			}

			// Check if executable
			if info.Mode()&0111 != 0 {
				hash, _ := hashFile(path)
				relPath := path[len(rootfs):]
				executables[relPath] = &ExecutableInfo{
					Path:      relPath,
					Hash:      hash,
					Size:      info.Size(),
					Mode:      info.Mode(),
					FirstSeen: time.Now(),
				}
			}
			return nil
		})
	}

	return executables, nil
}
