package admission

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	admissionv1 "k8s.io/api/admission/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer"
)

// AdmissionPolicy defines what to check during admission.
type AdmissionPolicy struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	Enabled     bool   `json:"enabled"`
	Action      string `json:"action"` // "deny", "warn", "audit"

	// Image policies
	BlockUnscannedImages  bool     `json:"blockUnscannedImages"`
	AllowedRegistries     []string `json:"allowedRegistries"`
	BlockedRegistries     []string `json:"blockedRegistries"`
	RequireImageDigest    bool     `json:"requireImageDigest"`

	// Security context policies
	BlockPrivileged       bool `json:"blockPrivileged"`
	BlockHostNetwork      bool `json:"blockHostNetwork"`
	BlockHostPID          bool `json:"blockHostPID"`
	BlockHostIPC          bool `json:"blockHostIPC"`
	BlockRootUser         bool `json:"blockRootUser"`
	RequireReadOnlyRoot   bool `json:"requireReadOnlyRoot"`

	// Capability policies
	BlockAllCapabilities  bool     `json:"blockAllCapabilities"`
	BlockedCapabilities   []string `json:"blockedCapabilities"`

	// Volume policies
	BlockHostPath         bool     `json:"blockHostPath"`
	AllowedHostPaths      []string `json:"allowedHostPaths"`
	BlockDockerSocket     bool     `json:"blockDockerSocket"`

	// Resource policies
	RequireResourceLimits bool `json:"requireResourceLimits"`

	// Label requirements
	RequiredLabels        []string `json:"requiredLabels"`
}

// AdmissionDecision represents the result of policy evaluation.
type AdmissionDecision struct {
	Allowed  bool     `json:"allowed"`
	Warnings []string `json:"warnings,omitempty"`
	Reason   string   `json:"reason,omitempty"`
	Policy   string   `json:"policy,omitempty"`
}

// AdmissionController handles Kubernetes admission webhooks.
type AdmissionController struct {
	mu       sync.RWMutex
	policies []*AdmissionPolicy
	decoder  runtime.Decoder

	// Statistics
	totalRequests int64
	allowedCount  int64
	deniedCount   int64
	warningCount  int64

	// Callbacks
	onDeny func(namespace, name, reason string)
}

// NewAdmissionController creates a new admission controller.
func NewAdmissionController() *AdmissionController {
	scheme := runtime.NewScheme()
	corev1.AddToScheme(scheme)

	return &AdmissionController{
		policies: make([]*AdmissionPolicy, 0),
		decoder:  serializer.NewCodecFactory(scheme).UniversalDeserializer(),
	}
}

// AddPolicy adds an admission policy.
func (c *AdmissionController) AddPolicy(policy *AdmissionPolicy) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.policies = append(c.policies, policy)
}

// SetDenyCallback sets the callback for denied requests.
func (c *AdmissionController) SetDenyCallback(callback func(namespace, name, reason string)) {
	c.onDeny = callback
}

// LoadDefaultPolicies loads a set of security-focused default policies.
func (c *AdmissionController) LoadDefaultPolicies() {
	defaultPolicy := &AdmissionPolicy{
		Name:        "default-security",
		Description: "Default security policy for container workloads",
		Enabled:     true,
		Action:      "deny",

		// Image security
		BlockUnscannedImages: false, // Would require integration with scanner
		RequireImageDigest:   false,

		// Block privileged containers
		BlockPrivileged:  true,
		BlockHostNetwork: true,
		BlockHostPID:     true,
		BlockHostIPC:     true,

		// Block root user
		BlockRootUser:       false, // Many images run as root by default
		RequireReadOnlyRoot: false,

		// Block dangerous capabilities
		BlockAllCapabilities: false,
		BlockedCapabilities: []string{
			"SYS_ADMIN",
			"SYS_PTRACE",
			"SYS_MODULE",
			"NET_ADMIN",
			"NET_RAW",
		},

		// Block host path mounts
		BlockHostPath:     true,
		BlockDockerSocket: true,
		AllowedHostPaths:  []string{"/var/log"}, // Allow log access

		// Resource requirements
		RequireResourceLimits: false,
	}

	c.AddPolicy(defaultPolicy)
}

// HandleAdmission handles a Kubernetes admission request.
func (c *AdmissionController) HandleAdmission(w http.ResponseWriter, r *http.Request) {
	c.mu.Lock()
	c.totalRequests++
	c.mu.Unlock()

	// Read request body
	body, err := io.ReadAll(r.Body)
	if err != nil {
		c.writeError(w, "Failed to read request body", http.StatusBadRequest)
		return
	}

	// Parse admission review
	var admissionReview admissionv1.AdmissionReview
	if _, _, err := c.decoder.Decode(body, nil, &admissionReview); err != nil {
		// Try direct JSON unmarshal
		if err := json.Unmarshal(body, &admissionReview); err != nil {
			c.writeError(w, "Failed to decode admission review", http.StatusBadRequest)
			return
		}
	}

	// Process the request
	response := c.processAdmission(admissionReview.Request)

	// Build response
	admissionReview.Response = response
	admissionReview.Response.UID = admissionReview.Request.UID

	// Send response
	respBytes, err := json.Marshal(admissionReview)
	if err != nil {
		c.writeError(w, "Failed to encode response", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Write(respBytes)
}

func (c *AdmissionController) processAdmission(req *admissionv1.AdmissionRequest) *admissionv1.AdmissionResponse {
	// Only handle pod creation/updates
	if req.Kind.Kind != "Pod" {
		return &admissionv1.AdmissionResponse{Allowed: true}
	}

	// Parse the pod
	var pod corev1.Pod
	if err := json.Unmarshal(req.Object.Raw, &pod); err != nil {
		return &admissionv1.AdmissionResponse{
			Allowed: false,
			Result: &metav1.Status{
				Message: fmt.Sprintf("Failed to parse pod: %v", err),
			},
		}
	}

	// Evaluate all policies
	decision := c.evaluatePolicies(&pod)

	c.mu.Lock()
	if decision.Allowed {
		c.allowedCount++
		if len(decision.Warnings) > 0 {
			c.warningCount++
		}
	} else {
		c.deniedCount++
		if c.onDeny != nil {
			go c.onDeny(pod.Namespace, pod.Name, decision.Reason)
		}
	}
	c.mu.Unlock()

	response := &admissionv1.AdmissionResponse{
		Allowed: decision.Allowed,
	}

	if !decision.Allowed {
		response.Result = &metav1.Status{
			Message: decision.Reason,
			Code:    403,
		}
	}

	if len(decision.Warnings) > 0 {
		response.Warnings = decision.Warnings
	}

	return response
}

func (c *AdmissionController) evaluatePolicies(pod *corev1.Pod) *AdmissionDecision {
	c.mu.RLock()
	defer c.mu.RUnlock()

	decision := &AdmissionDecision{
		Allowed:  true,
		Warnings: []string{},
	}

	for _, policy := range c.policies {
		if !policy.Enabled {
			continue
		}

		violations := c.checkPolicy(pod, policy)

		for _, violation := range violations {
			switch policy.Action {
			case "deny":
				decision.Allowed = false
				decision.Reason = violation
				decision.Policy = policy.Name
				return decision
			case "warn":
				decision.Warnings = append(decision.Warnings, violation)
			case "audit":
				// Log only, don't affect decision
				fmt.Printf("[Admission] Audit: %s - %s\n", policy.Name, violation)
			}
		}
	}

	return decision
}

func (c *AdmissionController) checkPolicy(pod *corev1.Pod, policy *AdmissionPolicy) []string {
	violations := []string{}

	// Check pod-level security context
	if pod.Spec.SecurityContext != nil {
		sc := pod.Spec.SecurityContext

		if policy.BlockHostNetwork && pod.Spec.HostNetwork {
			violations = append(violations, "Pod uses host network (blocked by policy)")
		}

		if policy.BlockHostPID && pod.Spec.HostPID {
			violations = append(violations, "Pod uses host PID namespace (blocked by policy)")
		}

		if policy.BlockHostIPC && pod.Spec.HostIPC {
			violations = append(violations, "Pod uses host IPC namespace (blocked by policy)")
		}

		if policy.BlockRootUser && sc.RunAsUser != nil && *sc.RunAsUser == 0 {
			violations = append(violations, "Pod runs as root user (blocked by policy)")
		}
	}

	// Check containers
	allContainers := append(pod.Spec.Containers, pod.Spec.InitContainers...)

	for _, container := range allContainers {
		// Check image
		violations = append(violations, c.checkImage(container.Image, policy)...)

		// Check security context
		if container.SecurityContext != nil {
			sc := container.SecurityContext

			if policy.BlockPrivileged && sc.Privileged != nil && *sc.Privileged {
				violations = append(violations,
					fmt.Sprintf("Container %s is privileged (blocked by policy)", container.Name))
			}

			if policy.RequireReadOnlyRoot && (sc.ReadOnlyRootFilesystem == nil || !*sc.ReadOnlyRootFilesystem) {
				violations = append(violations,
					fmt.Sprintf("Container %s does not have read-only root filesystem", container.Name))
			}

			if policy.BlockRootUser && sc.RunAsUser != nil && *sc.RunAsUser == 0 {
				violations = append(violations,
					fmt.Sprintf("Container %s runs as root (blocked by policy)", container.Name))
			}

			// Check capabilities
			if sc.Capabilities != nil {
				for _, cap := range sc.Capabilities.Add {
					if policy.BlockAllCapabilities {
						violations = append(violations,
							fmt.Sprintf("Container %s adds capability %s (all capabilities blocked)", container.Name, cap))
					} else if contains(policy.BlockedCapabilities, string(cap)) {
						violations = append(violations,
							fmt.Sprintf("Container %s adds blocked capability: %s", container.Name, cap))
					}
				}
			}
		}

		// Check volume mounts
		for _, mount := range container.VolumeMounts {
			if policy.BlockDockerSocket && strings.Contains(mount.MountPath, "docker.sock") {
				violations = append(violations,
					fmt.Sprintf("Container %s mounts Docker socket (blocked by policy)", container.Name))
			}
		}

		// Check resource limits
		if policy.RequireResourceLimits {
			if container.Resources.Limits.Cpu().IsZero() || container.Resources.Limits.Memory().IsZero() {
				violations = append(violations,
					fmt.Sprintf("Container %s does not have resource limits", container.Name))
			}
		}
	}

	// Check volumes
	for _, volume := range pod.Spec.Volumes {
		if volume.HostPath != nil {
			if policy.BlockHostPath {
				allowed := false
				for _, allowedPath := range policy.AllowedHostPaths {
					if strings.HasPrefix(volume.HostPath.Path, allowedPath) {
						allowed = true
						break
					}
				}
				if !allowed {
					violations = append(violations,
						fmt.Sprintf("Volume %s uses host path %s (blocked by policy)", volume.Name, volume.HostPath.Path))
				}
			}

			if policy.BlockDockerSocket && strings.Contains(volume.HostPath.Path, "docker.sock") {
				violations = append(violations,
					fmt.Sprintf("Volume %s mounts Docker socket (blocked by policy)", volume.Name))
			}
		}
	}

	// Check required labels
	for _, requiredLabel := range policy.RequiredLabels {
		if _, exists := pod.Labels[requiredLabel]; !exists {
			violations = append(violations,
				fmt.Sprintf("Pod missing required label: %s", requiredLabel))
		}
	}

	return violations
}

func (c *AdmissionController) checkImage(image string, policy *AdmissionPolicy) []string {
	violations := []string{}

	// Check allowed registries
	if len(policy.AllowedRegistries) > 0 {
		allowed := false
		for _, registry := range policy.AllowedRegistries {
			if strings.HasPrefix(image, registry) {
				allowed = true
				break
			}
		}
		if !allowed {
			violations = append(violations,
				fmt.Sprintf("Image %s is not from an allowed registry", image))
		}
	}

	// Check blocked registries
	for _, registry := range policy.BlockedRegistries {
		if strings.HasPrefix(image, registry) {
			violations = append(violations,
				fmt.Sprintf("Image %s is from a blocked registry", image))
		}
	}

	// Check for digest requirement
	if policy.RequireImageDigest && !strings.Contains(image, "@sha256:") {
		violations = append(violations,
			fmt.Sprintf("Image %s does not use digest (tag-based images blocked)", image))
	}

	return violations
}

func (c *AdmissionController) writeError(w http.ResponseWriter, message string, status int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]string{"error": message})
}

// StartServer starts the admission webhook server.
func (c *AdmissionController) StartServer(ctx context.Context, addr, certFile, keyFile string) error {
	mux := http.NewServeMux()
	mux.HandleFunc("/validate", c.HandleAdmission)
	mux.HandleFunc("/mutate", c.HandleAdmission) // Same handler for now
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	})
	mux.HandleFunc("/metrics", c.handleMetrics)

	server := &http.Server{
		Addr:    addr,
		Handler: mux,
		TLSConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
		},
	}

	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		server.Shutdown(shutdownCtx)
	}()

	fmt.Printf("Admission controller starting on %s\n", addr)
	fmt.Printf("Endpoints:\n")
	fmt.Printf("  POST /validate  - Validating webhook\n")
	fmt.Printf("  POST /mutate    - Mutating webhook\n")
	fmt.Printf("  GET  /health    - Health check\n")
	fmt.Printf("  GET  /metrics   - Prometheus metrics\n")

	if certFile != "" && keyFile != "" {
		return server.ListenAndServeTLS(certFile, keyFile)
	}
	return server.ListenAndServe()
}

func (c *AdmissionController) handleMetrics(w http.ResponseWriter, r *http.Request) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	metrics := fmt.Sprintf(`# HELP qualys_admission_total Total admission requests
# TYPE qualys_admission_total counter
qualys_admission_total %d

# HELP qualys_admission_allowed Total allowed requests
# TYPE qualys_admission_allowed counter
qualys_admission_allowed %d

# HELP qualys_admission_denied Total denied requests
# TYPE qualys_admission_denied counter
qualys_admission_denied %d

# HELP qualys_admission_warnings Total requests with warnings
# TYPE qualys_admission_warnings counter
qualys_admission_warnings %d

# HELP qualys_admission_policies_active Active admission policies
# TYPE qualys_admission_policies_active gauge
qualys_admission_policies_active %d
`,
		c.totalRequests,
		c.allowedCount,
		c.deniedCount,
		c.warningCount,
		len(c.policies),
	)

	w.Header().Set("Content-Type", "text/plain")
	w.Write([]byte(metrics))
}

// Stats returns admission controller statistics.
func (c *AdmissionController) Stats() map[string]interface{} {
	c.mu.RLock()
	defer c.mu.RUnlock()

	return map[string]interface{}{
		"total_requests":  c.totalRequests,
		"allowed":         c.allowedCount,
		"denied":          c.deniedCount,
		"warnings":        c.warningCount,
		"active_policies": len(c.policies),
	}
}

func contains(slice []string, item string) bool {
	for _, s := range slice {
		if strings.EqualFold(s, item) {
			return true
		}
	}
	return false
}
