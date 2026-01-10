package response

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

var (
	containerIDPattern    = regexp.MustCompile(`^[a-f0-9]{12,64}$`)
	kubernetesNamePattern = regexp.MustCompile(`^[a-z0-9]([-a-z0-9]*[a-z0-9])?$`)
	unsafeCharsPattern    = regexp.MustCompile(`[;&|$\x60\\]`)
)

func validateContainerID(containerID string) error {
	if containerID == "" {
		return fmt.Errorf("container ID is required")
	}
	if len(containerID) > 64 {
		return fmt.Errorf("container ID too long")
	}
	if !containerIDPattern.MatchString(containerID) {
		return fmt.Errorf("invalid container ID format")
	}
	return nil
}

func validateKubernetesName(name string) error {
	if name == "" {
		return fmt.Errorf("name is required")
	}
	if len(name) > 253 {
		return fmt.Errorf("name too long")
	}
	if !kubernetesNamePattern.MatchString(name) {
		return fmt.Errorf("invalid kubernetes name format")
	}
	return nil
}

func validateFilePath(path string) error {
	if path == "" {
		return fmt.Errorf("file path is required")
	}
	if unsafeCharsPattern.MatchString(path) {
		return fmt.Errorf("file path contains unsafe characters")
	}
	cleanPath := filepath.Clean(path)
	if strings.Contains(cleanPath, "..") {
		return fmt.Errorf("path traversal not allowed")
	}
	return nil
}

type ActionType string

const (
	ActionAlert         ActionType = "alert"
	ActionKillProcess   ActionType = "kill_process"
	ActionKillContainer ActionType = "kill_container"
	ActionStopContainer ActionType = "stop_container"
	ActionPauseContainer ActionType = "pause_container"
	ActionQuarantine    ActionType = "quarantine"
	ActionCapture       ActionType = "capture"
	ActionNetworkIsolate ActionType = "network_isolate"
	ActionLabelPod       ActionType = "label_pod"
)

type ActionRequest struct {
	Type          ActionType        `json:"type"`
	ContainerID   string            `json:"containerId,omitempty"`
	ContainerName string            `json:"containerName,omitempty"`
	PodName       string            `json:"podName,omitempty"`
	Namespace     string            `json:"namespace,omitempty"`
	ProcessID     int               `json:"processId,omitempty"`
	FilePath      string            `json:"filePath,omitempty"`
	Reason        string            `json:"reason"`
	Severity      string            `json:"severity"`
	EventID       string            `json:"eventId"`
	Labels        map[string]string `json:"labels,omitempty"`
}

type ActionResult struct {
	Success   bool      `json:"success"`
	Action    ActionType `json:"action"`
	Message   string    `json:"message"`
	Timestamp time.Time `json:"timestamp"`
	Duration  time.Duration `json:"duration"`
	Details   map[string]interface{} `json:"details,omitempty"`
}

type ResponseEngine struct {
	quarantineDir string
	captureDir    string
	kubectlPath   string
	crictlPath    string
	webhookURLs   []string
}

func NewResponseEngine(quarantineDir, captureDir string) *ResponseEngine {
	return &ResponseEngine{
		quarantineDir: quarantineDir,
		captureDir:    captureDir,
		kubectlPath:   findBinary("kubectl"),
		crictlPath:    findBinary("crictl"),
	}
}

func (r *ResponseEngine) AddWebhook(url string) {
	r.webhookURLs = append(r.webhookURLs, url)
}

func (r *ResponseEngine) Execute(ctx context.Context, req *ActionRequest) *ActionResult {
	start := time.Now()

	result := &ActionResult{
		Action:    req.Type,
		Timestamp: start,
		Details:   make(map[string]interface{}),
	}

	var err error
	switch req.Type {
	case ActionAlert:
		err = r.sendAlert(ctx, req)
	case ActionKillProcess:
		err = r.killProcess(ctx, req)
	case ActionKillContainer:
		err = r.killContainer(ctx, req)
	case ActionStopContainer:
		err = r.stopContainer(ctx, req)
	case ActionPauseContainer:
		err = r.pauseContainer(ctx, req)
	case ActionQuarantine:
		err = r.quarantineFile(ctx, req, result)
	case ActionCapture:
		err = r.captureForensics(ctx, req, result)
	case ActionNetworkIsolate:
		err = r.networkIsolate(ctx, req)
	case ActionLabelPod:
		err = r.labelPod(ctx, req)
	default:
		err = fmt.Errorf("unknown action type: %s", req.Type)
	}

	result.Duration = time.Since(start)

	if err != nil {
		result.Success = false
		result.Message = err.Error()
	} else {
		result.Success = true
		result.Message = fmt.Sprintf("%s completed successfully", req.Type)
	}

	r.notifyWebhooks(req, result)
	return result
}

func (r *ResponseEngine) killProcess(ctx context.Context, req *ActionRequest) error {
	if req.ProcessID <= 0 {
		return fmt.Errorf("invalid process ID: %d", req.ProcessID)
	}

	cmd := exec.CommandContext(ctx, "kill", "-9", fmt.Sprintf("%d", req.ProcessID))
	return cmd.Run()
}

func (r *ResponseEngine) killContainer(ctx context.Context, req *ActionRequest) error {
	containerID := req.ContainerID
	if err := validateContainerID(containerID); err != nil {
		return fmt.Errorf("invalid container ID: %w", err)
	}

	if r.crictlPath != "" {
		cmd := exec.CommandContext(ctx, r.crictlPath, "rm", "-f", containerID)
		if err := cmd.Run(); err == nil {
			return nil
		}
	}

	cmd := exec.CommandContext(ctx, "docker", "rm", "-f", containerID)
	return cmd.Run()
}

func (r *ResponseEngine) stopContainer(ctx context.Context, req *ActionRequest) error {
	containerID := req.ContainerID
	if err := validateContainerID(containerID); err != nil {
		return fmt.Errorf("invalid container ID: %w", err)
	}

	if r.crictlPath != "" {
		cmd := exec.CommandContext(ctx, r.crictlPath, "stop", containerID)
		if err := cmd.Run(); err == nil {
			return nil
		}
	}

	cmd := exec.CommandContext(ctx, "docker", "stop", containerID)
	return cmd.Run()
}

func (r *ResponseEngine) pauseContainer(ctx context.Context, req *ActionRequest) error {
	containerID := req.ContainerID
	if err := validateContainerID(containerID); err != nil {
		return fmt.Errorf("invalid container ID: %w", err)
	}

	cmd := exec.CommandContext(ctx, "docker", "pause", containerID)
	return cmd.Run()
}

func (r *ResponseEngine) quarantineFile(ctx context.Context, req *ActionRequest, result *ActionResult) error {
	if err := validateFilePath(req.FilePath); err != nil {
		return fmt.Errorf("invalid file path: %w", err)
	}

	if r.quarantineDir == "" {
		return fmt.Errorf("quarantine directory not configured")
	}

	if err := os.MkdirAll(r.quarantineDir, 0700); err != nil {
		return fmt.Errorf("failed to create quarantine dir: %w", err)
	}

	timestamp := time.Now().Format("20060102-150405")
	basename := filepath.Base(req.FilePath)
	quarantinePath := filepath.Join(r.quarantineDir, fmt.Sprintf("%s_%s.quarantine", timestamp, basename))

	cmd := exec.CommandContext(ctx, "gzip", "-c", req.FilePath)
	output, err := os.Create(quarantinePath + ".gz")
	if err != nil {
		return err
	}
	defer output.Close()

	cmd.Stdout = output
	if err := cmd.Run(); err != nil {
		return err
	}

	os.Chmod(req.FilePath, 0000)

	result.Details["quarantine_path"] = quarantinePath + ".gz"
	result.Details["original_path"] = req.FilePath

	return nil
}

func (r *ResponseEngine) captureForensics(ctx context.Context, req *ActionRequest, result *ActionResult) error {
	if r.captureDir == "" {
		return fmt.Errorf("capture directory not configured")
	}

	timestamp := time.Now().Format("20060102-150405")
	captureSubdir := filepath.Join(r.captureDir, fmt.Sprintf("%s_%s", timestamp, req.EventID))
	if err := os.MkdirAll(captureSubdir, 0700); err != nil {
		return err
	}

	captured := []string{}

	if req.ProcessID > 0 {
		procDir := fmt.Sprintf("/proc/%d", req.ProcessID)

		cmdline, _ := os.ReadFile(filepath.Join(procDir, "cmdline"))
		os.WriteFile(filepath.Join(captureSubdir, "cmdline"), cmdline, 0600)

		environ, _ := os.ReadFile(filepath.Join(procDir, "environ"))
		os.WriteFile(filepath.Join(captureSubdir, "environ"), environ, 0600)

		maps, _ := os.ReadFile(filepath.Join(procDir, "maps"))
		os.WriteFile(filepath.Join(captureSubdir, "maps"), maps, 0600)

		fds, _ := os.ReadDir(filepath.Join(procDir, "fd"))
		fdInfo := []string{}
		for _, fd := range fds {
			link, _ := os.Readlink(filepath.Join(procDir, "fd", fd.Name()))
			fdInfo = append(fdInfo, fmt.Sprintf("%s -> %s", fd.Name(), link))
		}
		os.WriteFile(filepath.Join(captureSubdir, "fds"), []byte(strings.Join(fdInfo, "\n")), 0600)

		captured = append(captured, "process_info")
	}

	if req.ContainerID != "" {
		logsFile := filepath.Join(captureSubdir, "container_logs.txt")

		if r.crictlPath != "" {
			cmd := exec.CommandContext(ctx, r.crictlPath, "logs", "--tail=1000", req.ContainerID)
			logs, _ := cmd.Output()
			os.WriteFile(logsFile, logs, 0600)
		} else {
			cmd := exec.CommandContext(ctx, "docker", "logs", "--tail=1000", req.ContainerID)
			logs, _ := cmd.Output()
			os.WriteFile(logsFile, logs, 0600)
		}

		captured = append(captured, "container_logs")
	}

	if req.FilePath != "" && fileExists(req.FilePath) {
		destFile := filepath.Join(captureSubdir, "captured_file")
		copyFile(req.FilePath, destFile)
		captured = append(captured, "suspicious_file")
	}

	metadata := map[string]interface{}{
		"event_id":       req.EventID,
		"container_id":   req.ContainerID,
		"container_name": req.ContainerName,
		"pod_name":       req.PodName,
		"namespace":      req.Namespace,
		"process_id":     req.ProcessID,
		"file_path":      req.FilePath,
		"reason":         req.Reason,
		"severity":       req.Severity,
		"captured_at":    time.Now().Format(time.RFC3339),
		"captured_items": captured,
	}

	metadataJSON, _ := json.MarshalIndent(metadata, "", "  ")
	os.WriteFile(filepath.Join(captureSubdir, "metadata.json"), metadataJSON, 0600)

	result.Details["capture_dir"] = captureSubdir
	result.Details["captured_items"] = captured

	return nil
}

func (r *ResponseEngine) networkIsolate(ctx context.Context, req *ActionRequest) error {
	if err := validateKubernetesName(req.PodName); err != nil {
		return fmt.Errorf("invalid pod name: %w", err)
	}
	if err := validateKubernetesName(req.Namespace); err != nil {
		return fmt.Errorf("invalid namespace: %w", err)
	}

	if r.kubectlPath == "" {
		return fmt.Errorf("kubectl not found")
	}

	policy := fmt.Sprintf(`apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: isolate-%s
  namespace: %s
  labels:
    qualys.com/isolation: "true"
    qualys.com/event-id: "%s"
spec:
  podSelector:
    matchLabels:
      app: %s
  policyTypes:
  - Egress
  egress: []  # Deny all egress
`, req.PodName, req.Namespace, req.EventID, req.PodName)

	cmd := exec.CommandContext(ctx, r.kubectlPath, "apply", "-f", "-")
	cmd.Stdin = strings.NewReader(policy)
	return cmd.Run()
}

func (r *ResponseEngine) labelPod(ctx context.Context, req *ActionRequest) error {
	if err := validateKubernetesName(req.PodName); err != nil {
		return fmt.Errorf("invalid pod name: %w", err)
	}
	if err := validateKubernetesName(req.Namespace); err != nil {
		return fmt.Errorf("invalid namespace: %w", err)
	}

	if r.kubectlPath == "" {
		return fmt.Errorf("kubectl not found")
	}

	labels := req.Labels
	if labels == nil {
		labels = map[string]string{
			"qualys.com/compromised": "true",
			"qualys.com/event-id":    req.EventID,
		}
	}

	labelArgs := []string{"label", "pod", req.PodName, "-n", req.Namespace, "--overwrite"}
	for k, v := range labels {
		labelArgs = append(labelArgs, fmt.Sprintf("%s=%s", k, v))
	}

	cmd := exec.CommandContext(ctx, r.kubectlPath, labelArgs...)
	return cmd.Run()
}

func (r *ResponseEngine) sendAlert(ctx context.Context, req *ActionRequest) error {
	// Alert-only action - notifications are sent via notifyWebhooks after Execute
	return nil
}

func (r *ResponseEngine) notifyWebhooks(req *ActionRequest, result *ActionResult) {
	if len(r.webhookURLs) == 0 {
		return
	}

	payload := map[string]interface{}{
		"action":  req,
		"result":  result,
		"version": "1.0",
	}

	data, _ := json.Marshal(payload)

	for _, url := range r.webhookURLs {
		go func(webhookURL string) {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()

			httpReq, _ := http.NewRequestWithContext(ctx, "POST", webhookURL, bytes.NewReader(data))
			httpReq.Header.Set("Content-Type", "application/json")
			httpReq.Header.Set("X-Qualys-Event-Type", "response_action")

			client := &http.Client{Timeout: 10 * time.Second}
			resp, err := client.Do(httpReq)
			if err != nil {
				fmt.Printf("[Response] Webhook failed: %v\n", err)
				return
			}
			resp.Body.Close()
		}(url)
	}
}

func findBinary(name string) string {
	paths := []string{
		"/usr/local/bin/" + name,
		"/usr/bin/" + name,
		"/bin/" + name,
	}

	for _, p := range paths {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}

	if path, err := exec.LookPath(name); err == nil {
		return path
	}

	return ""
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func copyFile(src, dst string) error {
	source, err := os.Open(src)
	if err != nil {
		return err
	}
	defer source.Close()

	dest, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer dest.Close()

	_, err = io.Copy(dest, source)
	return err
}
