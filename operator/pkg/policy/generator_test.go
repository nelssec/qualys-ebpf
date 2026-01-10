package policy

import (
	"encoding/json"
	"strings"
	"testing"

	"qualys-policy-operator/pkg/cdr"
	"sigs.k8s.io/yaml"
)

func TestNewGenerator(t *testing.T) {
	g := NewGenerator("Sigkill")
	if g == nil {
		t.Fatal("NewGenerator returned nil")
	}
	if g.action != "Sigkill" {
		t.Errorf("Expected action 'Sigkill', got '%s'", g.action)
	}
}

func TestFromEventsCloudCredentials(t *testing.T) {
	g := NewGenerator("Sigkill")
	events := []cdr.Event{
		{ThreatCategory: "Cloud_Credentials_Accessed_By_Network_Utility", ProcessName: "curl"},
		{ThreatCategory: "Cloud_Credentials_Accessed_By_Network_Utility", ProcessName: "wget"},
	}

	policies := g.FromEvents(events)
	if len(policies) != 1 {
		t.Fatalf("Expected 1 policy, got %d", len(policies))
	}

	policy := policies[0]
	if policy.APIVersion != "cilium.io/v1alpha1" {
		t.Errorf("Expected APIVersion 'cilium.io/v1alpha1', got '%s'", policy.APIVersion)
	}
	if policy.Kind != "TracingPolicy" {
		t.Errorf("Expected Kind 'TracingPolicy', got '%s'", policy.Kind)
	}
	if !strings.Contains(policy.Metadata.Name, "cdr-block-cloud-creds") {
		t.Errorf("Expected name containing 'cdr-block-cloud-creds', got '%s'", policy.Metadata.Name)
	}
	if policy.Metadata.Labels["mitre.attack/technique"] != "T1552.005" {
		t.Errorf("Expected MITRE technique 'T1552.005', got '%s'", policy.Metadata.Labels["mitre.attack/technique"])
	}
}

func TestFromEventsNetworkScanning(t *testing.T) {
	g := NewGenerator("Post")
	events := []cdr.Event{
		{ThreatCategory: "Network_Scanning_Utility", ProcessName: "nmap"},
	}

	policies := g.FromEvents(events)
	if len(policies) != 1 {
		t.Fatalf("Expected 1 policy, got %d", len(policies))
	}

	policy := policies[0]
	if policy.Metadata.Labels["mitre.attack/technique"] != "T1046" {
		t.Errorf("Expected MITRE technique 'T1046', got '%s'", policy.Metadata.Labels["mitre.attack/technique"])
	}

	// Verify it has both sys_execve and sys_socket kprobes
	if len(policy.Spec.Kprobes) != 2 {
		t.Errorf("Expected 2 kprobes, got %d", len(policy.Spec.Kprobes))
	}
}

func TestFromEventsContainerEscape(t *testing.T) {
	g := NewGenerator("Sigkill")
	events := []cdr.Event{
		{ThreatCategory: "Container_Escape_Attempt"},
	}

	policies := g.FromEvents(events)
	if len(policies) != 1 {
		t.Fatalf("Expected 1 policy, got %d", len(policies))
	}

	policy := policies[0]
	if policy.Metadata.Labels["mitre.attack/technique"] != "T1611" {
		t.Errorf("Expected MITRE technique 'T1611', got '%s'", policy.Metadata.Labels["mitre.attack/technique"])
	}

	// Should have unshare and setns kprobes
	if len(policy.Spec.Kprobes) != 2 {
		t.Errorf("Expected 2 kprobes for container escape, got %d", len(policy.Spec.Kprobes))
	}
}

func TestFromEventsCryptoMining(t *testing.T) {
	g := NewGenerator("Sigkill")
	events := []cdr.Event{
		{ThreatCategory: "Crypto_Mining_Activity"},
	}

	policies := g.FromEvents(events)
	if len(policies) != 1 {
		t.Fatalf("Expected 1 policy, got %d", len(policies))
	}

	policy := policies[0]
	if policy.Metadata.Labels["mitre.attack/technique"] != "T1496" {
		t.Errorf("Expected MITRE technique 'T1496', got '%s'", policy.Metadata.Labels["mitre.attack/technique"])
	}
}

func TestFromEventsReverseShell(t *testing.T) {
	g := NewGenerator("Sigkill")
	events := []cdr.Event{
		{ThreatCategory: "Reverse_Shell_Execution"},
	}

	policies := g.FromEvents(events)
	if len(policies) != 1 {
		t.Fatalf("Expected 1 policy, got %d", len(policies))
	}

	policy := policies[0]
	if policy.Metadata.Labels["mitre.attack/technique"] != "T1059.004" {
		t.Errorf("Expected MITRE technique 'T1059.004', got '%s'", policy.Metadata.Labels["mitre.attack/technique"])
	}
}

func TestFromEventsSensitiveFileAccess(t *testing.T) {
	g := NewGenerator("Post")
	events := []cdr.Event{
		{ThreatCategory: "Sensitive_File_Access"},
	}

	policies := g.FromEvents(events)
	if len(policies) != 1 {
		t.Fatalf("Expected 1 policy, got %d", len(policies))
	}

	policy := policies[0]
	if policy.Metadata.Labels["mitre.attack/technique"] != "T1552.001" {
		t.Errorf("Expected MITRE technique 'T1552.001', got '%s'", policy.Metadata.Labels["mitre.attack/technique"])
	}
	if policy.Spec.Kprobes[0].Call != "sys_openat" {
		t.Errorf("Expected kprobe 'sys_openat', got '%s'", policy.Spec.Kprobes[0].Call)
	}
}

func TestFromEventsPersistence(t *testing.T) {
	g := NewGenerator("Sigkill")
	events := []cdr.Event{
		{ThreatCategory: "Persistence_Cron_Job"},
	}

	policies := g.FromEvents(events)
	if len(policies) != 1 {
		t.Fatalf("Expected 1 policy, got %d", len(policies))
	}

	policy := policies[0]
	if policy.Metadata.Labels["mitre.attack/technique"] != "T1053.003" {
		t.Errorf("Expected MITRE technique 'T1053.003', got '%s'", policy.Metadata.Labels["mitre.attack/technique"])
	}
}

func TestFromEventsDefenseEvasion(t *testing.T) {
	g := NewGenerator("Sigkill")
	events := []cdr.Event{
		{ThreatCategory: "Log_Tampering_Defense_Evasion"},
	}

	policies := g.FromEvents(events)
	if len(policies) != 1 {
		t.Fatalf("Expected 1 policy, got %d", len(policies))
	}

	policy := policies[0]
	if policy.Metadata.Labels["mitre.attack/technique"] != "T1070.002" {
		t.Errorf("Expected MITRE technique 'T1070.002', got '%s'", policy.Metadata.Labels["mitre.attack/technique"])
	}
	// Should have unlinkat and truncate kprobes
	if len(policy.Spec.Kprobes) != 2 {
		t.Errorf("Expected 2 kprobes for defense evasion, got %d", len(policy.Spec.Kprobes))
	}
}

func TestFromEventsLateralMovement(t *testing.T) {
	g := NewGenerator("Post")
	events := []cdr.Event{
		{ThreatCategory: "Lateral_Movement_SSH"},
	}

	policies := g.FromEvents(events)
	if len(policies) != 1 {
		t.Fatalf("Expected 1 policy, got %d", len(policies))
	}

	policy := policies[0]
	if policy.Metadata.Labels["mitre.attack/technique"] != "T1021.004" {
		t.Errorf("Expected MITRE technique 'T1021.004', got '%s'", policy.Metadata.Labels["mitre.attack/technique"])
	}
}

func TestFromEventsExfiltration(t *testing.T) {
	g := NewGenerator("Sigkill")
	events := []cdr.Event{
		{ThreatCategory: "Data_Exfiltration_Staging"},
	}

	policies := g.FromEvents(events)
	if len(policies) != 1 {
		t.Fatalf("Expected 1 policy, got %d", len(policies))
	}

	policy := policies[0]
	if policy.Metadata.Labels["mitre.attack/technique"] != "T1041" {
		t.Errorf("Expected MITRE technique 'T1041', got '%s'", policy.Metadata.Labels["mitre.attack/technique"])
	}
	// Should have execve and connect kprobes
	if len(policy.Spec.Kprobes) != 2 {
		t.Errorf("Expected 2 kprobes for exfiltration, got %d", len(policy.Spec.Kprobes))
	}
}

func TestFromEventsWebshell(t *testing.T) {
	g := NewGenerator("Sigkill")
	events := []cdr.Event{
		{ThreatCategory: "Webshell_Execution"},
	}

	policies := g.FromEvents(events)
	if len(policies) != 1 {
		t.Fatalf("Expected 1 policy, got %d", len(policies))
	}

	policy := policies[0]
	if policy.Metadata.Labels["mitre.attack/technique"] != "T1505.003" {
		t.Errorf("Expected MITRE technique 'T1505.003', got '%s'", policy.Metadata.Labels["mitre.attack/technique"])
	}
}

func TestFromEventsKernelModule(t *testing.T) {
	g := NewGenerator("Sigkill")
	events := []cdr.Event{
		{ThreatCategory: "Kernel_Module_Loading"},
	}

	policies := g.FromEvents(events)
	if len(policies) != 1 {
		t.Fatalf("Expected 1 policy, got %d", len(policies))
	}

	policy := policies[0]
	if policy.Metadata.Labels["mitre.attack/technique"] != "T1547.006" {
		t.Errorf("Expected MITRE technique 'T1547.006', got '%s'", policy.Metadata.Labels["mitre.attack/technique"])
	}
	// Should have init_module, finit_module, and execve kprobes
	if len(policy.Spec.Kprobes) != 3 {
		t.Errorf("Expected 3 kprobes for kernel module, got %d", len(policy.Spec.Kprobes))
	}
}

func TestFromEventsUnknownCategory(t *testing.T) {
	g := NewGenerator("Post")
	events := []cdr.Event{
		{ThreatCategory: "Unknown_Category_XYZ"},
	}

	policies := g.FromEvents(events)
	if len(policies) != 0 {
		t.Errorf("Expected 0 policies for unknown category, got %d", len(policies))
	}
}

func TestFromEventsMultipleCategories(t *testing.T) {
	g := NewGenerator("Sigkill")
	events := []cdr.Event{
		{ThreatCategory: "Cloud_Credentials_Accessed_By_Network_Utility", ProcessName: "curl"},
		{ThreatCategory: "Network_Scanning_Utility", ProcessName: "nmap"},
		{ThreatCategory: "Container_Escape_Attempt"},
	}

	policies := g.FromEvents(events)
	if len(policies) != 3 {
		t.Errorf("Expected 3 policies for 3 categories, got %d", len(policies))
	}
}

func TestPolicyYAMLOutput(t *testing.T) {
	g := NewGenerator("Sigkill")
	events := []cdr.Event{
		{ThreatCategory: "Cloud_Credentials_Accessed_By_Network_Utility", ProcessName: "curl"},
	}

	policies := g.FromEvents(events)
	if len(policies) != 1 {
		t.Fatalf("Expected 1 policy, got %d", len(policies))
	}

	yamlData, err := yaml.Marshal(policies[0])
	if err != nil {
		t.Fatalf("Failed to marshal policy to YAML: %v", err)
	}

	yamlStr := string(yamlData)

	// Validate YAML structure
	if !strings.Contains(yamlStr, "apiVersion: cilium.io/v1alpha1") {
		t.Error("YAML missing apiVersion")
	}
	if !strings.Contains(yamlStr, "kind: TracingPolicy") {
		t.Error("YAML missing kind")
	}
	if !strings.Contains(yamlStr, "kprobes:") {
		t.Error("YAML missing kprobes")
	}
	if !strings.Contains(yamlStr, "sys_connect") {
		t.Error("YAML missing sys_connect kprobe")
	}
	if !strings.Contains(yamlStr, "169.254.169.254") {
		t.Error("YAML missing IMDS IP address")
	}
	if !strings.Contains(yamlStr, "action: Sigkill") {
		t.Error("YAML missing Sigkill action")
	}
}

func TestPolicyJSONOutput(t *testing.T) {
	g := NewGenerator("Post")
	events := []cdr.Event{
		{ThreatCategory: "Network_Scanning_Utility", ProcessName: "nmap"},
	}

	policies := g.FromEvents(events)
	if len(policies) != 1 {
		t.Fatalf("Expected 1 policy, got %d", len(policies))
	}

	jsonData, err := json.MarshalIndent(policies[0], "", "  ")
	if err != nil {
		t.Fatalf("Failed to marshal policy to JSON: %v", err)
	}

	jsonStr := string(jsonData)

	// Validate JSON structure
	if !strings.Contains(jsonStr, "\"apiVersion\": \"cilium.io/v1alpha1\"") {
		t.Error("JSON missing apiVersion")
	}
	if !strings.Contains(jsonStr, "\"kind\": \"TracingPolicy\"") {
		t.Error("JSON missing kind")
	}
	if !strings.Contains(jsonStr, "\"call\": \"sys_execve\"") {
		t.Error("JSON missing sys_execve kprobe")
	}
}

func TestExtractProcesses(t *testing.T) {
	events := []cdr.Event{
		{ProcessName: "curl"},
		{ProcessName: "wget"},
		{ProcessName: "curl"}, // duplicate
		{ProcessName: ""},     // empty
	}

	processes := extractProcesses(events)
	if len(processes) != 2 {
		t.Errorf("Expected 2 unique processes, got %d", len(processes))
	}

	seen := make(map[string]bool)
	for _, p := range processes {
		if seen[p] {
			t.Errorf("Duplicate process found: %s", p)
		}
		seen[p] = true
	}

	if !seen["curl"] || !seen["wget"] {
		t.Error("Missing expected processes curl and wget")
	}
}

func TestValidKprobeArgs(t *testing.T) {
	testCases := []struct {
		name         string
		category     string
		expectedCall string
		expectedArgs int
	}{
		{"cloud_credentials", "Cloud_Credentials_Accessed", "sys_connect", 2},
		{"network_scanning", "Network_Scanning_Utility", "sys_execve", 1},
		{"kernel_module", "Kernel_Module_Loading", "sys_init_module", 0},
	}

	g := NewGenerator("Post")

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			events := []cdr.Event{{ThreatCategory: tc.category}}
			policies := g.FromEvents(events)
			if len(policies) == 0 {
				t.Fatalf("Expected policy for category %s", tc.category)
			}

			found := false
			for _, kprobe := range policies[0].Spec.Kprobes {
				if kprobe.Call == tc.expectedCall {
					found = true
					if len(kprobe.Args) != tc.expectedArgs {
						t.Errorf("Expected %d args for %s, got %d",
							tc.expectedArgs, tc.expectedCall, len(kprobe.Args))
					}
				}
			}
			if !found {
				t.Errorf("Expected to find kprobe %s", tc.expectedCall)
			}
		})
	}
}

func TestValidOperators(t *testing.T) {
	validOperators := map[string]bool{
		"Equal":   true,
		"NotEqual": true,
		"Prefix":  true,
		"Postfix": true,
		"In":      true,
		"NotIn":   true,
		"SAddr":   true,
		"DAddr":   true,
		"DPort":   true,
		"Mask":    true,
	}

	g := NewGenerator("Post")
	categories := []string{
		"Cloud_Credentials_Accessed",
		"Network_Scanning_Utility",
		"Container_Escape_Attempt",
		"Crypto_Mining_Activity",
		"Reverse_Shell_Execution",
		"Sensitive_File_Access",
		"Persistence_Cron",
		"Log_Tampering_Defense_Evasion",
		"Lateral_Movement_SSH",
		"Data_Exfiltration_Staging",
		"Webshell_Execution",
		"Kernel_Module_Loading",
	}

	for _, category := range categories {
		events := []cdr.Event{{ThreatCategory: category}}
		policies := g.FromEvents(events)
		if len(policies) == 0 {
			continue
		}

		for _, kprobe := range policies[0].Spec.Kprobes {
			for _, selector := range kprobe.Selectors {
				for _, matchArg := range selector.MatchArgs {
					if !validOperators[matchArg.Operator] {
						t.Errorf("Invalid operator '%s' in category %s", matchArg.Operator, category)
					}
				}
				for _, matchBinary := range selector.MatchBinaries {
					if !validOperators[matchBinary.Operator] {
						t.Errorf("Invalid binary operator '%s' in category %s", matchBinary.Operator, category)
					}
				}
			}
		}
	}
}

func TestValidActions(t *testing.T) {
	validActions := map[string]bool{
		"Post":     true,
		"Sigkill":  true,
		"Override": true,
	}

	for action := range validActions {
		g := NewGenerator(action)
		events := []cdr.Event{
			{ThreatCategory: "Cloud_Credentials_Accessed"},
		}

		policies := g.FromEvents(events)
		if len(policies) == 0 {
			t.Fatalf("Expected policy for action %s", action)
		}

		for _, kprobe := range policies[0].Spec.Kprobes {
			for _, selector := range kprobe.Selectors {
				for _, matchAction := range selector.MatchActions {
					if matchAction.Action != action {
						t.Errorf("Expected action %s, got %s", action, matchAction.Action)
					}
				}
			}
		}
	}
}

// Benchmark tests
func BenchmarkFromEvents(b *testing.B) {
	g := NewGenerator("Post")
	events := []cdr.Event{
		{ThreatCategory: "Cloud_Credentials_Accessed", ProcessName: "curl"},
		{ThreatCategory: "Network_Scanning_Utility", ProcessName: "nmap"},
		{ThreatCategory: "Container_Escape_Attempt"},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		g.FromEvents(events)
	}
}

func BenchmarkPolicyToYAML(b *testing.B) {
	g := NewGenerator("Sigkill")
	events := []cdr.Event{
		{ThreatCategory: "Cloud_Credentials_Accessed", ProcessName: "curl"},
	}
	policies := g.FromEvents(events)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		yaml.Marshal(policies[0])
	}
}

// AI Anomaly Policy Tests
func TestFromAnomalyExecRate(t *testing.T) {
	g := NewGenerator("Sigkill")
	anomaly := Anomaly{
		Type:          "statistical",
		Feature:       "exec_rate",
		ContainerID:   "abc123",
		ContainerName: "nginx-pod",
		Namespace:     "default",
		Score:         85.5,
		Description:   "Unusual execution rate detected",
	}

	policy := g.FromAnomaly(anomaly)
	if policy == nil {
		t.Fatal("FromAnomaly returned nil")
	}

	if policy.APIVersion != "cilium.io/v1alpha1" {
		t.Errorf("Expected APIVersion 'cilium.io/v1alpha1', got '%s'", policy.APIVersion)
	}
	if policy.Kind != "TracingPolicy" {
		t.Errorf("Expected Kind 'TracingPolicy', got '%s'", policy.Kind)
	}
	if !strings.Contains(policy.Metadata.Name, "ai-anomaly-exec") {
		t.Errorf("Expected name containing 'ai-anomaly-exec', got '%s'", policy.Metadata.Name)
	}
	if policy.Metadata.Labels["generated-by"] != "qualys-ai-detector" {
		t.Errorf("Expected generated-by 'qualys-ai-detector', got '%s'", policy.Metadata.Labels["generated-by"])
	}
	if policy.Metadata.Labels["ai.qualys.com/feature"] != "exec_rate" {
		t.Errorf("Expected feature label 'exec_rate', got '%s'", policy.Metadata.Labels["ai.qualys.com/feature"])
	}

	// Validate kprobe
	if len(policy.Spec.Kprobes) == 0 {
		t.Fatal("Expected at least 1 kprobe")
	}
	if policy.Spec.Kprobes[0].Call != "sys_execve" {
		t.Errorf("Expected sys_execve kprobe, got '%s'", policy.Spec.Kprobes[0].Call)
	}
}

func TestFromAnomalyNetworkConnections(t *testing.T) {
	g := NewGenerator("Post")
	anomaly := Anomaly{
		Type:          "time_series",
		Feature:       "network_connections",
		ContainerID:   "def456",
		ContainerName: "api-server",
		Namespace:     "production",
		Score:         72.3,
		NetworkPort:   8443,
		Description:   "Unusual outbound connections",
	}

	policy := g.FromAnomaly(anomaly)
	if policy == nil {
		t.Fatal("FromAnomaly returned nil")
	}

	if !strings.Contains(policy.Metadata.Name, "ai-anomaly-network") {
		t.Errorf("Expected name containing 'ai-anomaly-network', got '%s'", policy.Metadata.Name)
	}
	if policy.Metadata.Labels["mitre.attack/technique"] != "T1071" {
		t.Errorf("Expected MITRE technique 'T1071', got '%s'", policy.Metadata.Labels["mitre.attack/technique"])
	}

	// Validate kprobe
	if len(policy.Spec.Kprobes) == 0 {
		t.Fatal("Expected at least 1 kprobe")
	}
	if policy.Spec.Kprobes[0].Call != "sys_connect" {
		t.Errorf("Expected sys_connect kprobe, got '%s'", policy.Spec.Kprobes[0].Call)
	}

	// Validate port is included
	foundPort := false
	for _, sel := range policy.Spec.Kprobes[0].Selectors {
		for _, arg := range sel.MatchArgs {
			for _, v := range arg.Values {
				if v == "8443" {
					foundPort = true
				}
			}
		}
	}
	if !foundPort {
		t.Error("Expected port 8443 in selector")
	}
}

func TestFromAnomalyFileAccess(t *testing.T) {
	g := NewGenerator("Sigkill")
	anomaly := Anomaly{
		Type:          "behavioral",
		Feature:       "file_access",
		ContainerID:   "ghi789",
		ContainerName: "worker",
		Namespace:     "jobs",
		Score:         91.2,
		FilePath:      "/etc/shadow",
		Description:   "Sensitive file access detected",
	}

	policy := g.FromAnomaly(anomaly)
	if policy == nil {
		t.Fatal("FromAnomaly returned nil")
	}

	if !strings.Contains(policy.Metadata.Name, "ai-anomaly-file") {
		t.Errorf("Expected name containing 'ai-anomaly-file', got '%s'", policy.Metadata.Name)
	}
	if policy.Metadata.Labels["mitre.attack/technique"] != "T1083" {
		t.Errorf("Expected MITRE technique 'T1083', got '%s'", policy.Metadata.Labels["mitre.attack/technique"])
	}

	// Validate kprobe
	if len(policy.Spec.Kprobes) == 0 {
		t.Fatal("Expected at least 1 kprobe")
	}
	if policy.Spec.Kprobes[0].Call != "sys_openat" {
		t.Errorf("Expected sys_openat kprobe, got '%s'", policy.Spec.Kprobes[0].Call)
	}

	// Validate file path is included
	foundPath := false
	for _, sel := range policy.Spec.Kprobes[0].Selectors {
		for _, arg := range sel.MatchArgs {
			for _, v := range arg.Values {
				if v == "/etc/shadow" {
					foundPath = true
				}
			}
		}
	}
	if !foundPath {
		t.Error("Expected file path '/etc/shadow' in selector")
	}
}

func TestFromAnomalyPrivilegeEscalation(t *testing.T) {
	g := NewGenerator("Sigkill")
	anomaly := Anomaly{
		Type:          "isolation",
		Feature:       "privilege_escalation",
		ContainerID:   "jkl012",
		ContainerName: "compromised",
		Namespace:     "default",
		Score:         99.1,
		Description:   "Privilege escalation attempt detected",
	}

	policy := g.FromAnomaly(anomaly)
	if policy == nil {
		t.Fatal("FromAnomaly returned nil")
	}

	if !strings.Contains(policy.Metadata.Name, "ai-anomaly-privesc") {
		t.Errorf("Expected name containing 'ai-anomaly-privesc', got '%s'", policy.Metadata.Name)
	}
	if policy.Metadata.Labels["mitre.attack/technique"] != "T1548" {
		t.Errorf("Expected MITRE technique 'T1548', got '%s'", policy.Metadata.Labels["mitre.attack/technique"])
	}
	if policy.Metadata.Labels["policy.qualys.com/priority"] != "critical" {
		t.Errorf("Expected priority 'critical', got '%s'", policy.Metadata.Labels["policy.qualys.com/priority"])
	}

	// Validate kprobes - should have sys_setuid, sys_setgid, sys_capset
	expectedCalls := map[string]bool{"sys_setuid": false, "sys_setgid": false, "sys_capset": false}
	for _, kprobe := range policy.Spec.Kprobes {
		if _, ok := expectedCalls[kprobe.Call]; ok {
			expectedCalls[kprobe.Call] = true
		}
	}
	for call, found := range expectedCalls {
		if !found {
			t.Errorf("Expected kprobe '%s' not found", call)
		}
	}
}

func TestFromAnomalyGeneric(t *testing.T) {
	g := NewGenerator("Post")
	anomaly := Anomaly{
		Type:          "clustering",
		Feature:       "unknown_feature",
		ContainerID:   "mno345",
		ContainerName: "mystery",
		Namespace:     "test",
		Score:         65.0,
		Description:   "Unknown anomaly type",
	}

	policy := g.FromAnomaly(anomaly)
	if policy == nil {
		t.Fatal("FromAnomaly returned nil")
	}

	if !strings.Contains(policy.Metadata.Name, "ai-anomaly-generic") {
		t.Errorf("Expected name containing 'ai-anomaly-generic', got '%s'", policy.Metadata.Name)
	}
	if policy.Metadata.Labels["policy.qualys.com/priority"] != "medium" {
		t.Errorf("Expected priority 'medium', got '%s'", policy.Metadata.Labels["policy.qualys.com/priority"])
	}
}

func TestAnomalyPolicyYAMLOutput(t *testing.T) {
	g := NewGenerator("Sigkill")
	anomaly := Anomaly{
		Type:          "statistical",
		Feature:       "privilege_escalation",
		ContainerID:   "test123",
		ContainerName: "test-container",
		Namespace:     "test-ns",
		Score:         95.5,
		Description:   "Critical privilege escalation",
	}

	policy := g.FromAnomaly(anomaly)
	yamlData, err := yaml.Marshal(policy)
	if err != nil {
		t.Fatalf("Failed to marshal policy to YAML: %v", err)
	}

	yamlStr := string(yamlData)

	// Validate YAML structure
	requiredFields := []string{
		"apiVersion: cilium.io/v1alpha1",
		"kind: TracingPolicy",
		"generated-by: qualys-ai-detector",
		"ai.qualys.com/feature: privilege_escalation",
		"mitre.attack/technique: T1548",
		"kprobes:",
		"sys_setuid",
		"sys_capset",
		"action: Sigkill",
	}

	for _, field := range requiredFields {
		if !strings.Contains(yamlStr, field) {
			t.Errorf("YAML missing required field: %s", field)
		}
	}
}

func TestAnomalyPolicyJSONOutput(t *testing.T) {
	g := NewGenerator("Post")
	anomaly := Anomaly{
		Type:          "time_series",
		Feature:       "network_connections",
		ContainerID:   "json123",
		ContainerName: "json-container",
		Namespace:     "json-ns",
		Score:         78.3,
		NetworkPort:   443,
		Description:   "Unusual HTTPS connections",
	}

	policy := g.FromAnomaly(anomaly)
	jsonData, err := json.MarshalIndent(policy, "", "  ")
	if err != nil {
		t.Fatalf("Failed to marshal policy to JSON: %v", err)
	}

	jsonStr := string(jsonData)

	// Validate JSON structure
	requiredFields := []string{
		`"apiVersion": "cilium.io/v1alpha1"`,
		`"kind": "TracingPolicy"`,
		`"generated-by": "qualys-ai-detector"`,
		`"call": "sys_connect"`,
		`"443"`,
	}

	for _, field := range requiredFields {
		if !strings.Contains(jsonStr, field) {
			t.Errorf("JSON missing required field: %s", field)
		}
	}
}

func TestAnomalyScoreAnnotation(t *testing.T) {
	testCases := []struct {
		score    float64
		expected string
	}{
		{85.5, "85.50"},
		{100.0, "100.00"},
		{0.0, "0.00"},
		{33.333, "33.33"},
	}

	g := NewGenerator("Post")
	for _, tc := range testCases {
		anomaly := Anomaly{
			Feature:       "exec_rate",
			ContainerName: "test",
			Score:         tc.score,
		}
		policy := g.FromAnomaly(anomaly)
		actual := policy.Metadata.Annotations["ai.qualys.com/score"]
		if actual != tc.expected {
			t.Errorf("Score %.3f: expected '%s', got '%s'", tc.score, tc.expected, actual)
		}
	}
}

func TestAllAnomalyFeatures(t *testing.T) {
	features := []struct {
		feature      string
		expectedCall string
	}{
		{"syscall_rate", "sys_execve"},
		{"exec_rate", "sys_execve"},
		{"network_connections", "sys_connect"},
		{"outbound_bytes", "sys_connect"},
		{"file_access", "sys_openat"},
		{"file_writes", "sys_openat"},
		{"privilege_escalation", "sys_setuid"},
		{"unknown", "sys_execve"}, // generic fallback
	}

	g := NewGenerator("Sigkill")
	for _, tc := range features {
		t.Run(tc.feature, func(t *testing.T) {
			anomaly := Anomaly{
				Feature:       tc.feature,
				ContainerName: "test",
				Score:         50.0,
			}
			policy := g.FromAnomaly(anomaly)
			if policy == nil {
				t.Fatal("Policy is nil")
			}
			if len(policy.Spec.Kprobes) == 0 {
				t.Fatal("No kprobes in policy")
			}
			if policy.Spec.Kprobes[0].Call != tc.expectedCall {
				t.Errorf("Expected call '%s', got '%s'", tc.expectedCall, policy.Spec.Kprobes[0].Call)
			}
		})
	}
}

func BenchmarkFromAnomaly(b *testing.B) {
	g := NewGenerator("Sigkill")
	anomaly := Anomaly{
		Type:          "statistical",
		Feature:       "privilege_escalation",
		ContainerID:   "bench123",
		ContainerName: "bench-container",
		Score:         95.0,
		Description:   "Benchmark test",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		g.FromAnomaly(anomaly)
	}
}

func BenchmarkAnomalyPolicyToYAML(b *testing.B) {
	g := NewGenerator("Sigkill")
	anomaly := Anomaly{
		Feature:       "network_connections",
		ContainerName: "bench",
		NetworkPort:   8080,
	}
	policy := g.FromAnomaly(anomaly)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		yaml.Marshal(policy)
	}
}
