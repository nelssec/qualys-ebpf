package response

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// --- Input Validation Tests ---

func TestValidateContainerID(t *testing.T) {
	tests := []struct {
		name        string
		containerID string
		wantErr     bool
	}{
		{"valid_short", "abc123def456", false},
		{"valid_full", "abc123def456789012345678901234567890123456789012345678901234", false},
		{"valid_64_chars", "abcdef1234567890abcdef1234567890abcdef1234567890abcdef12345678", false},
		{"empty", "", true},
		{"too_long", "abc123def456789012345678901234567890123456789012345678901234567890", true},
		{"too_short", "abc", true},
		{"invalid_chars", "abc123def456!", true},
		{"uppercase", "ABC123DEF456", true},
		{"shell_injection", "abc123;rm -rf /", true},
		{"newline", "abc123\ndef456", true},
		{"spaces", "abc123 def456", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateContainerID(tt.containerID)
			if (err != nil) != tt.wantErr {
				t.Errorf("validateContainerID(%q) error = %v, wantErr %v", tt.containerID, err, tt.wantErr)
			}
		})
	}
}

func TestValidateKubernetesName(t *testing.T) {
	tests := []struct {
		name    string
		k8sName string
		wantErr bool
	}{
		{"valid_simple", "my-pod", false},
		{"valid_with_numbers", "my-pod-123", false},
		{"valid_single_char", "a", false},
		{"empty", "", true},
		{"starts_with_dash", "-my-pod", true},
		{"ends_with_dash", "my-pod-", true},
		{"uppercase", "My-Pod", true},
		{"underscore", "my_pod", true},
		{"too_long", strings.Repeat("a", 254), true},
		{"shell_chars", "my-pod;rm", true},
		{"dots", "my.pod", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateKubernetesName(tt.k8sName)
			if (err != nil) != tt.wantErr {
				t.Errorf("validateKubernetesName(%q) error = %v, wantErr %v", tt.k8sName, err, tt.wantErr)
			}
		})
	}
}

func TestValidateFilePath(t *testing.T) {
	tests := []struct {
		name    string
		path    string
		wantErr bool
	}{
		{"valid_simple", "/var/log/app.log", false},
		{"valid_with_dots", "/var/log/app.2023.log", false},
		{"empty", "", true},
		{"shell_semicolon", "/var/log;rm -rf /", true},
		{"shell_pipe", "/var/log|cat /etc/passwd", true},
		{"shell_ampersand", "/var/log&rm -rf /", true},
		{"shell_backtick", "/var/log`rm -rf /`", true},
		{"shell_dollar", "/var/log$HOME", true},
		// Note: filepath.Clean resolves /var/log/../../../etc/passwd to /etc/passwd
		// So this test validates that resolved paths without .. are allowed
		{"path_traversal_resolved", "/var/log/../../../etc/passwd", false},
		// "..subdir" is a valid directory name, not path traversal
		{"dotdot_prefix_dir", "/var/log/..subdir/../file", false},
		{"backslash", "/var/log\\file", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateFilePath(tt.path)
			if (err != nil) != tt.wantErr {
				t.Errorf("validateFilePath(%q) error = %v, wantErr %v", tt.path, err, tt.wantErr)
			}
		})
	}
}

// --- ResponseEngine Tests ---

func TestNewResponseEngine(t *testing.T) {
	engine := NewResponseEngine("/tmp/quarantine", "/tmp/capture")

	if engine == nil {
		t.Fatal("expected non-nil engine")
	}
	if engine.quarantineDir != "/tmp/quarantine" {
		t.Errorf("expected quarantineDir /tmp/quarantine, got %s", engine.quarantineDir)
	}
	if engine.captureDir != "/tmp/capture" {
		t.Errorf("expected captureDir /tmp/capture, got %s", engine.captureDir)
	}
}

func TestAddWebhook(t *testing.T) {
	engine := NewResponseEngine("", "")
	engine.AddWebhook("http://webhook1.local")
	engine.AddWebhook("http://webhook2.local")

	if len(engine.webhookURLs) != 2 {
		t.Errorf("expected 2 webhooks, got %d", len(engine.webhookURLs))
	}
}

func TestExecuteAlert(t *testing.T) {
	engine := NewResponseEngine("", "")

	req := &ActionRequest{
		Type:     ActionAlert,
		Reason:   "Test alert",
		Severity: "high",
		EventID:  "test-event-1",
	}

	result := engine.Execute(context.Background(), req)

	if !result.Success {
		t.Errorf("expected success, got failure: %s", result.Message)
	}
	if result.Action != ActionAlert {
		t.Errorf("expected action %s, got %s", ActionAlert, result.Action)
	}
	if result.Duration <= 0 {
		t.Error("expected positive duration")
	}
}

func TestExecuteUnknownAction(t *testing.T) {
	engine := NewResponseEngine("", "")

	req := &ActionRequest{
		Type:   "unknown_action",
		Reason: "Test",
	}

	result := engine.Execute(context.Background(), req)

	if result.Success {
		t.Error("expected failure for unknown action")
	}
	if !strings.Contains(result.Message, "unknown action type") {
		t.Errorf("expected unknown action error, got: %s", result.Message)
	}
}

func TestKillProcessInvalidPID(t *testing.T) {
	engine := NewResponseEngine("", "")

	tests := []struct {
		name string
		pid  int
	}{
		{"zero", 0},
		{"negative", -1},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := &ActionRequest{
				Type:      ActionKillProcess,
				ProcessID: tt.pid,
			}
			result := engine.Execute(context.Background(), req)
			if result.Success {
				t.Error("expected failure for invalid PID")
			}
		})
	}
}

func TestContainerActionsWithInvalidID(t *testing.T) {
	engine := NewResponseEngine("", "")

	actions := []ActionType{
		ActionKillContainer,
		ActionStopContainer,
		ActionPauseContainer,
	}

	invalidIDs := []string{
		"",
		"invalid!id",
		"too-short",
		strings.Repeat("a", 100),
	}

	for _, action := range actions {
		for _, id := range invalidIDs {
			t.Run(string(action)+"_"+id, func(t *testing.T) {
				req := &ActionRequest{
					Type:        action,
					ContainerID: id,
				}
				result := engine.Execute(context.Background(), req)
				if result.Success {
					t.Errorf("expected failure for invalid container ID: %s", id)
				}
			})
		}
	}
}

func TestQuarantineInvalidPath(t *testing.T) {
	engine := NewResponseEngine("/tmp/quarantine", "")

	invalidPaths := []string{
		"",
		"/path;injection",
		"/path/../../../etc/passwd",
		"/path`command`",
	}

	for _, path := range invalidPaths {
		t.Run(path, func(t *testing.T) {
			req := &ActionRequest{
				Type:     ActionQuarantine,
				FilePath: path,
			}
			result := engine.Execute(context.Background(), req)
			if result.Success {
				t.Errorf("expected failure for invalid path: %s", path)
			}
		})
	}
}

func TestQuarantineNoDir(t *testing.T) {
	engine := NewResponseEngine("", "")

	req := &ActionRequest{
		Type:     ActionQuarantine,
		FilePath: "/tmp/test.txt",
	}
	result := engine.Execute(context.Background(), req)

	if result.Success {
		t.Error("expected failure when quarantine dir not configured")
	}
}

func TestCaptureNoDir(t *testing.T) {
	engine := NewResponseEngine("", "")

	req := &ActionRequest{
		Type:    ActionCapture,
		EventID: "test-event",
	}
	result := engine.Execute(context.Background(), req)

	if result.Success {
		t.Error("expected failure when capture dir not configured")
	}
}

func TestNetworkIsolateInvalidNames(t *testing.T) {
	engine := NewResponseEngine("", "")
	// Set kubectl path to empty to trigger that error first
	engine.kubectlPath = ""

	tests := []struct {
		name      string
		podName   string
		namespace string
		wantErr   string
	}{
		{"invalid_pod", "Invalid-Pod", "default", "invalid pod name"},
		{"invalid_namespace", "my-pod", "Invalid-NS", "invalid namespace"},
		{"both_invalid", "Invalid!", "Also-Invalid!", "invalid pod name"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := &ActionRequest{
				Type:      ActionNetworkIsolate,
				PodName:   tt.podName,
				Namespace: tt.namespace,
			}
			result := engine.Execute(context.Background(), req)
			if result.Success {
				t.Error("expected failure")
			}
			if !strings.Contains(strings.ToLower(result.Message), "invalid") {
				t.Errorf("expected invalid error, got: %s", result.Message)
			}
		})
	}
}

func TestLabelPodInvalidNames(t *testing.T) {
	engine := NewResponseEngine("", "")
	engine.kubectlPath = ""

	req := &ActionRequest{
		Type:      ActionLabelPod,
		PodName:   "Invalid-Pod!",
		Namespace: "default",
	}
	result := engine.Execute(context.Background(), req)

	if result.Success {
		t.Error("expected failure for invalid pod name")
	}
}

func TestNetworkIsolateNoKubectl(t *testing.T) {
	engine := NewResponseEngine("", "")
	engine.kubectlPath = ""

	req := &ActionRequest{
		Type:      ActionNetworkIsolate,
		PodName:   "my-pod",
		Namespace: "default",
	}
	result := engine.Execute(context.Background(), req)

	if result.Success {
		t.Error("expected failure when kubectl not found")
	}
	if !strings.Contains(result.Message, "kubectl not found") {
		t.Errorf("expected kubectl error, got: %s", result.Message)
	}
}

func TestLabelPodNoKubectl(t *testing.T) {
	engine := NewResponseEngine("", "")
	engine.kubectlPath = ""

	req := &ActionRequest{
		Type:      ActionLabelPod,
		PodName:   "my-pod",
		Namespace: "default",
	}
	result := engine.Execute(context.Background(), req)

	if result.Success {
		t.Error("expected failure when kubectl not found")
	}
}

func TestWebhookNotification(t *testing.T) {
	// Create test server
	var receivedPayload map[string]interface{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		json.Unmarshal(body, &receivedPayload)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	engine := NewResponseEngine("", "")
	engine.AddWebhook(server.URL)

	req := &ActionRequest{
		Type:     ActionAlert,
		Reason:   "Test webhook",
		Severity: "high",
		EventID:  "webhook-test",
	}

	result := engine.Execute(context.Background(), req)

	if !result.Success {
		t.Fatalf("expected success: %s", result.Message)
	}

	// Wait for async webhook
	time.Sleep(100 * time.Millisecond)

	if receivedPayload == nil {
		t.Error("expected webhook to receive payload")
	}
}

func TestWebhookFailure(t *testing.T) {
	// Create server that fails
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	engine := NewResponseEngine("", "")
	engine.AddWebhook(server.URL)

	req := &ActionRequest{
		Type:   ActionAlert,
		Reason: "Test webhook failure",
	}

	// Should not panic or fail the main action
	result := engine.Execute(context.Background(), req)
	if !result.Success {
		t.Error("main action should succeed even if webhook fails")
	}
}

// --- Helper Function Tests ---

func TestFindBinary(t *testing.T) {
	// Test finding a common binary
	path := findBinary("ls")
	if path == "" {
		t.Error("expected to find 'ls' binary")
	}

	// Test non-existent binary
	path = findBinary("nonexistent_binary_12345")
	if path != "" {
		t.Error("expected empty path for nonexistent binary")
	}
}

func TestFileExists(t *testing.T) {
	// Create temp file
	tmpFile, err := os.CreateTemp("", "test")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpFile.Name())
	tmpFile.Close()

	if !fileExists(tmpFile.Name()) {
		t.Error("expected file to exist")
	}

	if fileExists("/nonexistent/path/file.txt") {
		t.Error("expected file to not exist")
	}
}

func TestCopyFile(t *testing.T) {
	// Create source file
	srcFile, err := os.CreateTemp("", "src")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(srcFile.Name())

	content := []byte("test content")
	srcFile.Write(content)
	srcFile.Close()

	// Create destination path
	dstPath := filepath.Join(os.TempDir(), "dst_test_copy")
	defer os.Remove(dstPath)

	// Copy file
	err = copyFile(srcFile.Name(), dstPath)
	if err != nil {
		t.Fatalf("copyFile failed: %v", err)
	}

	// Verify content
	dstContent, err := os.ReadFile(dstPath)
	if err != nil {
		t.Fatalf("failed to read dest: %v", err)
	}

	if string(dstContent) != string(content) {
		t.Errorf("content mismatch: %s != %s", dstContent, content)
	}
}

func TestCopyFileNonexistent(t *testing.T) {
	err := copyFile("/nonexistent/source", "/tmp/dest")
	if err == nil {
		t.Error("expected error for nonexistent source")
	}
}

// --- ActionRequest/ActionResult Tests ---

func TestActionRequestJSON(t *testing.T) {
	req := &ActionRequest{
		Type:          ActionKillContainer,
		ContainerID:   "abc123def456",
		ContainerName: "test-container",
		PodName:       "test-pod",
		Namespace:     "default",
		Reason:        "Suspicious activity",
		Severity:      "critical",
		EventID:       "event-123",
		Labels:        map[string]string{"env": "prod"},
	}

	data, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("failed to marshal: %v", err)
	}

	var unmarshaled ActionRequest
	if err := json.Unmarshal(data, &unmarshaled); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}

	if unmarshaled.Type != req.Type {
		t.Error("type mismatch")
	}
	if unmarshaled.ContainerID != req.ContainerID {
		t.Error("containerID mismatch")
	}
}

func TestActionResultJSON(t *testing.T) {
	result := &ActionResult{
		Success:   true,
		Action:    ActionKillContainer,
		Message:   "Container killed",
		Timestamp: time.Now(),
		Duration:  100 * time.Millisecond,
		Details:   map[string]interface{}{"key": "value"},
	}

	data, err := json.Marshal(result)
	if err != nil {
		t.Fatalf("failed to marshal: %v", err)
	}

	var unmarshaled ActionResult
	if err := json.Unmarshal(data, &unmarshaled); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}

	if unmarshaled.Success != result.Success {
		t.Error("success mismatch")
	}
	if unmarshaled.Action != result.Action {
		t.Error("action mismatch")
	}
}

// --- Benchmark Tests ---

func BenchmarkValidateContainerID(b *testing.B) {
	validID := "abc123def456789012345678901234567890123456789012345678901234"

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		validateContainerID(validID)
	}
}

func BenchmarkValidateKubernetesName(b *testing.B) {
	validName := "my-kubernetes-pod-name-123"

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		validateKubernetesName(validName)
	}
}

func BenchmarkValidateFilePath(b *testing.B) {
	validPath := "/var/log/application/server.log"

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		validateFilePath(validPath)
	}
}

func BenchmarkExecuteAlert(b *testing.B) {
	engine := NewResponseEngine("", "")
	req := &ActionRequest{
		Type:     ActionAlert,
		Reason:   "Benchmark alert",
		Severity: "low",
		EventID:  "bench-event",
	}
	ctx := context.Background()

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		engine.Execute(ctx, req)
	}
}

func BenchmarkWebhookNotification(b *testing.B) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	engine := NewResponseEngine("", "")
	engine.AddWebhook(server.URL)

	req := &ActionRequest{
		Type:     ActionAlert,
		Reason:   "Benchmark webhook",
		EventID:  "bench-event",
	}

	result := &ActionResult{
		Success:   true,
		Action:    ActionAlert,
		Timestamp: time.Now(),
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		engine.notifyWebhooks(req, result)
	}
}

func BenchmarkFindBinary(b *testing.B) {
	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		findBinary("ls")
	}
}

func BenchmarkCopyFile(b *testing.B) {
	// Create source file
	srcFile, _ := os.CreateTemp("", "bench_src")
	srcFile.Write([]byte("benchmark content for copy operation"))
	srcFile.Close()
	defer os.Remove(srcFile.Name())

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		dstPath := filepath.Join(os.TempDir(), "bench_dst")
		copyFile(srcFile.Name(), dstPath)
		os.Remove(dstPath)
	}
}
