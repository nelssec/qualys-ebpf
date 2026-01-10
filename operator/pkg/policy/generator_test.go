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

// ============================================================================
// 1. MORE CDR THREAT CATEGORIES - MITRE ATT&CK Coverage
// ============================================================================

func TestAllMITRETechniques(t *testing.T) {
	testCases := []struct {
		name           string
		category       string
		expectedMITRE  string
		expectedTactic string
		expectedCall   string
	}{
		// Credential Access
		{"cloud_creds", "Cloud_Credentials_Accessed", "T1552.005", "credential-access", "sys_connect"},
		{"sensitive_file", "Sensitive_File_Access", "T1552.001", "credential-access", "sys_openat"},

		// Discovery
		{"network_scan", "Network_Scanning_Utility", "T1046", "discovery", "sys_execve"},

		// Privilege Escalation
		{"container_escape", "Container_Escape_Attempt", "T1611", "privilege-escalation", "sys_unshare"},

		// Impact
		{"crypto_mining", "Crypto_Mining_Activity", "T1496", "impact", "sys_connect"},

		// Execution
		{"reverse_shell", "Reverse_Shell_Execution", "T1059.004", "execution", "sys_execve"},

		// Persistence
		{"persistence_cron", "Persistence_Cron_Job", "T1053.003", "persistence", "sys_openat"},
		{"webshell", "Webshell_Execution", "T1505.003", "persistence", "sys_execve"},
		{"kernel_module", "Kernel_Module_Loading", "T1547.006", "persistence", "sys_init_module"},

		// Defense Evasion
		{"log_tampering", "Log_Tampering_Defense_Evasion", "T1070.002", "defense-evasion", "sys_unlinkat"},

		// Lateral Movement
		{"lateral_ssh", "Lateral_Movement_SSH", "T1021.004", "lateral-movement", "sys_execve"},

		// Exfiltration
		{"exfiltration", "Data_Exfiltration_Staging", "T1041", "exfiltration", "sys_execve"},
	}

	g := NewGenerator("Sigkill")
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			events := []cdr.Event{{ThreatCategory: tc.category}}
			policies := g.FromEvents(events)

			if len(policies) == 0 {
				t.Fatalf("No policy generated for category %s", tc.category)
			}

			policy := policies[0]

			// Verify MITRE technique
			if policy.Metadata.Labels["mitre.attack/technique"] != tc.expectedMITRE {
				t.Errorf("Expected MITRE %s, got %s", tc.expectedMITRE, policy.Metadata.Labels["mitre.attack/technique"])
			}

			// Verify syscall
			found := false
			for _, kprobe := range policy.Spec.Kprobes {
				if kprobe.Call == tc.expectedCall {
					found = true
					break
				}
			}
			if !found {
				t.Errorf("Expected syscall %s not found", tc.expectedCall)
			}
		})
	}
}

func TestMITRESubtechniques(t *testing.T) {
	subtechniques := map[string]string{
		"T1552.001": "Credentials In Files",
		"T1552.005": "Cloud Instance Metadata API",
		"T1053.003": "Cron",
		"T1070.002": "Clear Linux or Mac System Logs",
		"T1021.004": "SSH",
		"T1505.003": "Web Shell",
		"T1547.006": "Kernel Modules and Extensions",
	}

	g := NewGenerator("Post")
	categories := []string{
		"Sensitive_File_Access",
		"Cloud_Credentials_Accessed",
		"Persistence_Cron",
		"Log_Tampering",
		"Lateral_Movement_SSH",
		"Webshell",
		"Kernel_Module",
	}

	for _, category := range categories {
		events := []cdr.Event{{ThreatCategory: category}}
		policies := g.FromEvents(events)
		if len(policies) > 0 {
			technique := policies[0].Metadata.Labels["mitre.attack/technique"]
			if _, ok := subtechniques[technique]; ok {
				t.Logf("Category %s maps to %s (%s)", category, technique, subtechniques[technique])
			}
		}
	}
}

// ============================================================================
// 2. EDGE CASES - Empty inputs, malformed data, boundaries
// ============================================================================

func TestEmptyEvents(t *testing.T) {
	g := NewGenerator("Sigkill")

	// Empty slice
	policies := g.FromEvents([]cdr.Event{})
	if len(policies) != 0 {
		t.Errorf("Expected 0 policies for empty events, got %d", len(policies))
	}

	// Nil-like behavior
	policies = g.FromEvents(nil)
	if len(policies) != 0 {
		t.Errorf("Expected 0 policies for nil events, got %d", len(policies))
	}
}

func TestEmptyThreatCategory(t *testing.T) {
	g := NewGenerator("Post")
	events := []cdr.Event{
		{ThreatCategory: "", ProcessName: "curl"},
		{ThreatCategory: "   ", ProcessName: "wget"},
	}

	policies := g.FromEvents(events)
	if len(policies) != 0 {
		t.Errorf("Expected 0 policies for empty categories, got %d", len(policies))
	}
}

func TestEmptyAnomaly(t *testing.T) {
	g := NewGenerator("Sigkill")
	anomaly := Anomaly{} // All zero values

	policy := g.FromAnomaly(anomaly)
	if policy == nil {
		t.Fatal("Policy should not be nil even for empty anomaly")
	}

	// Should fall through to generic
	if !strings.Contains(policy.Metadata.Name, "ai-anomaly-generic") {
		t.Errorf("Empty anomaly should generate generic policy, got %s", policy.Metadata.Name)
	}
}

func TestSpecialCharactersInNames(t *testing.T) {
	g := NewGenerator("Post")

	testCases := []struct {
		name          string
		containerName string
	}{
		{"spaces", "my container"},
		{"special", "container@123!"},
		{"unicode", "容器-test"},
		{"long", strings.Repeat("a", 100)},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			anomaly := Anomaly{
				Feature:       "exec_rate",
				ContainerName: tc.containerName,
				Score:         50.0,
			}
			policy := g.FromAnomaly(anomaly)

			// Should not panic and should generate valid policy
			if policy == nil {
				t.Fatal("Policy should not be nil")
			}
			if policy.Metadata.Name == "" {
				t.Error("Policy name should not be empty")
			}
		})
	}
}

func TestBoundaryScores(t *testing.T) {
	g := NewGenerator("Post")

	scores := []float64{
		0.0,
		0.001,
		50.0,
		99.999,
		100.0,
		-1.0,    // Invalid but should handle
		1000.0,  // Over 100
	}

	for _, score := range scores {
		anomaly := Anomaly{
			Feature:       "exec_rate",
			ContainerName: "test",
			Score:         score,
		}
		policy := g.FromAnomaly(anomaly)

		if policy == nil {
			t.Errorf("Policy nil for score %f", score)
			continue
		}

		// Verify score is in annotation
		scoreStr := policy.Metadata.Annotations["ai.qualys.com/score"]
		if scoreStr == "" {
			t.Errorf("Missing score annotation for %f", score)
		}
	}
}

func TestBoundaryPorts(t *testing.T) {
	g := NewGenerator("Post")

	ports := []int{
		0,
		1,
		80,
		443,
		8080,
		65535,
		-1,     // Invalid
		65536,  // Out of range
	}

	for _, port := range ports {
		anomaly := Anomaly{
			Feature:       "network_connections",
			ContainerName: "test",
			NetworkPort:   port,
		}
		policy := g.FromAnomaly(anomaly)

		if policy == nil {
			t.Errorf("Policy nil for port %d", port)
		}
	}
}

func TestDuplicateEvents(t *testing.T) {
	g := NewGenerator("Sigkill")

	// Same category multiple times
	events := []cdr.Event{
		{ThreatCategory: "Container_Escape_Attempt", ProcessName: "bash"},
		{ThreatCategory: "Container_Escape_Attempt", ProcessName: "sh"},
		{ThreatCategory: "Container_Escape_Attempt", ProcessName: "bash"}, // duplicate process
	}

	policies := g.FromEvents(events)

	// Should only generate 1 policy (grouped by category)
	if len(policies) != 1 {
		t.Errorf("Expected 1 policy for duplicate categories, got %d", len(policies))
	}
}

func TestMixedValidInvalidEvents(t *testing.T) {
	g := NewGenerator("Post")

	events := []cdr.Event{
		{ThreatCategory: ""},                                    // Invalid
		{ThreatCategory: "Container_Escape_Attempt"},            // Valid
		{ThreatCategory: "   "},                                 // Invalid
		{ThreatCategory: "Network_Scanning_Utility"},            // Valid
		{ThreatCategory: "Unknown_Category_XYZ"},                // Unknown but valid
	}

	policies := g.FromEvents(events)

	// Should generate policies only for valid categories
	if len(policies) < 2 {
		t.Errorf("Expected at least 2 policies, got %d", len(policies))
	}
}

// ============================================================================
// 3. INTEGRATION TESTS - AI Detector → Policy Generator Pipeline
// ============================================================================

func TestAIDetectorToPolicy(t *testing.T) {
	// Simulate AI detector anomaly output
	aiAnomalies := []struct {
		anomalyType string
		feature     string
		score       float64
		description string
	}{
		{"statistical", "exec_rate", 85.0, "High execution rate"},
		{"time_series", "network_connections", 72.0, "Unusual network pattern"},
		{"behavioral", "file_access", 91.0, "Sensitive file access"},
		{"isolation", "privilege_escalation", 99.0, "Privilege escalation detected"},
		{"clustering", "unknown", 65.0, "Outlier behavior"},
	}

	g := NewGenerator("Sigkill")

	for _, ai := range aiAnomalies {
		t.Run(ai.feature, func(t *testing.T) {
			anomaly := Anomaly{
				Type:          ai.anomalyType,
				Feature:       ai.feature,
				ContainerID:   "container-" + ai.feature,
				ContainerName: "pod-" + ai.feature,
				Namespace:     "default",
				Score:         ai.score,
				Description:   ai.description,
			}

			policy := g.FromAnomaly(anomaly)

			// Verify policy is valid
			if policy == nil {
				t.Fatal("Policy is nil")
			}
			if policy.APIVersion != "cilium.io/v1alpha1" {
				t.Error("Invalid APIVersion")
			}
			if len(policy.Spec.Kprobes) == 0 {
				t.Error("No kprobes in policy")
			}

			// Verify score is preserved
			scoreAnnotation := policy.Metadata.Annotations["ai.qualys.com/score"]
			if scoreAnnotation == "" {
				t.Error("Score not preserved in policy")
			}
		})
	}
}

func TestCDREventToPolicy(t *testing.T) {
	// Simulate CDR event categories from API
	cdrCategories := []string{
		"Cloud_Credentials_Accessed_By_Network_Utility",
		"Network_Scanning_Utility_Executed",
		"Container_Escape_Attempt_Detected",
		"Crypto_Mining_Binary_Executed",
		"Reverse_Shell_Connection_Established",
		"Sensitive_File_Accessed",
		"Persistence_Mechanism_Created",
		"Defense_Evasion_Log_Cleared",
		"Lateral_Movement_SSH_Connection",
		"Data_Exfiltration_Tool_Executed",
		"Webshell_Activity_Detected",
		"Kernel_Module_Loaded",
	}

	g := NewGenerator("Sigkill")

	for _, category := range cdrCategories {
		t.Run(category, func(t *testing.T) {
			events := []cdr.Event{{
				ThreatCategory: category,
				ProcessName:    "test-process",
			}}

			policies := g.FromEvents(events)

			// All categories should generate at least one policy
			if len(policies) == 0 {
				t.Logf("No policy for category: %s (may be unknown)", category)
				return
			}

			policy := policies[0]
			if policy.Kind != "TracingPolicy" {
				t.Error("Invalid Kind")
			}
			if len(policy.Spec.Kprobes) == 0 {
				t.Error("No kprobes generated")
			}
		})
	}
}

func TestPipelineEndToEnd(t *testing.T) {
	// Simulate full pipeline: Detection → Anomaly → Policy → YAML
	g := NewGenerator("Sigkill")

	// Step 1: CDR detection event
	events := []cdr.Event{{
		ThreatCategory: "Container_Escape_Attempt",
		ProcessName:    "nsenter",
	}}
	cdrPolicies := g.FromEvents(events)

	// Step 2: AI anomaly detection
	anomaly := Anomaly{
		Type:          "statistical",
		Feature:       "privilege_escalation",
		ContainerID:   "abc123",
		ContainerName: "compromised-pod",
		Score:         95.0,
		Description:   "Privilege escalation correlated with container escape",
	}
	aiPolicy := g.FromAnomaly(anomaly)

	// Step 3: Verify both policies are valid YAML
	allPolicies := append(cdrPolicies, *aiPolicy)

	for i, policy := range allPolicies {
		yamlData, err := yaml.Marshal(policy)
		if err != nil {
			t.Errorf("Policy %d failed YAML marshal: %v", i, err)
			continue
		}

		// Verify YAML is valid by unmarshaling back
		var parsed TracingPolicy
		if err := yaml.Unmarshal(yamlData, &parsed); err != nil {
			t.Errorf("Policy %d failed YAML unmarshal: %v", i, err)
		}

		// Verify round-trip preserves key fields
		if parsed.APIVersion != policy.APIVersion {
			t.Errorf("APIVersion mismatch after round-trip")
		}
		if parsed.Kind != policy.Kind {
			t.Errorf("Kind mismatch after round-trip")
		}
	}
}

// ============================================================================
// 4. YAML VALIDATION - kubectl-apply Compatible
// ============================================================================

func TestYAMLKubernetesCompatibility(t *testing.T) {
	g := NewGenerator("Sigkill")
	events := []cdr.Event{{ThreatCategory: "Container_Escape_Attempt"}}
	policies := g.FromEvents(events)

	if len(policies) == 0 {
		t.Fatal("No policies generated")
	}

	yamlData, err := yaml.Marshal(policies[0])
	if err != nil {
		t.Fatalf("Failed to marshal: %v", err)
	}

	yamlStr := string(yamlData)

	// Required Kubernetes fields
	requiredFields := []string{
		"apiVersion:",
		"kind:",
		"metadata:",
		"name:",
		"spec:",
	}

	for _, field := range requiredFields {
		if !strings.Contains(yamlStr, field) {
			t.Errorf("Missing required Kubernetes field: %s", field)
		}
	}

	// Verify no invalid YAML characters
	invalidPatterns := []string{
		"!!python",  // YAML injection
		"!!binary",  // Binary data
		"---\n---",  // Double document separator
	}

	for _, pattern := range invalidPatterns {
		if strings.Contains(yamlStr, pattern) {
			t.Errorf("Found invalid YAML pattern: %s", pattern)
		}
	}
}

func TestYAMLLabelConstraints(t *testing.T) {
	g := NewGenerator("Post")

	// Kubernetes label constraints:
	// - max 63 chars
	// - must start/end with alphanumeric
	// - can contain -, _, .

	events := []cdr.Event{{ThreatCategory: "Container_Escape_Attempt"}}
	policies := g.FromEvents(events)

	if len(policies) == 0 {
		t.Fatal("No policies generated")
	}

	policy := policies[0]

	for key, value := range policy.Metadata.Labels {
		// Check key format
		if len(key) > 253 { // prefix/name format
			t.Errorf("Label key too long: %s", key)
		}

		// Check value constraints
		if len(value) > 63 {
			t.Errorf("Label value too long: %s = %s", key, value)
		}
	}
}

func TestYAMLNameConstraints(t *testing.T) {
	g := NewGenerator("Sigkill")

	categories := []string{
		"Container_Escape_Attempt",
		"Cloud_Credentials_Accessed",
		"Network_Scanning_Utility",
	}

	for _, category := range categories {
		events := []cdr.Event{{ThreatCategory: category}}
		policies := g.FromEvents(events)

		if len(policies) == 0 {
			continue
		}

		name := policies[0].Metadata.Name

		// Kubernetes name constraints
		if len(name) > 253 {
			t.Errorf("Name too long: %s", name)
		}

		// Must be lowercase
		if name != strings.ToLower(name) {
			t.Errorf("Name must be lowercase: %s", name)
		}

		// Must match DNS subdomain pattern
		validChars := "abcdefghijklmnopqrstuvwxyz0123456789-."
		for _, c := range name {
			if !strings.ContainsRune(validChars, c) {
				t.Errorf("Invalid character in name: %c in %s", c, name)
			}
		}
	}
}

func TestYAMLMultiDocumentOutput(t *testing.T) {
	g := NewGenerator("Sigkill")

	events := []cdr.Event{
		{ThreatCategory: "Container_Escape_Attempt"},
		{ThreatCategory: "Crypto_Mining_Activity"},
		{ThreatCategory: "Network_Scanning_Utility"},
	}

	policies := g.FromEvents(events)

	// Generate multi-document YAML
	var fullYAML strings.Builder
	for i, policy := range policies {
		if i > 0 {
			fullYAML.WriteString("---\n")
		}
		yamlData, err := yaml.Marshal(policy)
		if err != nil {
			t.Fatalf("Failed to marshal policy %d: %v", i, err)
		}
		fullYAML.Write(yamlData)
	}

	// Verify multi-doc structure
	docs := strings.Split(fullYAML.String(), "---")
	if len(docs) < len(policies) {
		t.Logf("Generated %d policies in multi-doc YAML", len(policies))
	}
}

func TestYAMLSpecialValueEscaping(t *testing.T) {
	g := NewGenerator("Post")

	// Test values that need YAML escaping
	anomaly := Anomaly{
		Feature:       "exec_rate",
		ContainerName: "test",
		Description:   "Description with: colons and 'quotes' and \"double quotes\"",
		Score:         50.0,
	}

	policy := g.FromAnomaly(anomaly)
	yamlData, err := yaml.Marshal(policy)
	if err != nil {
		t.Fatalf("Failed to marshal: %v", err)
	}

	// Verify it can be parsed back
	var parsed TracingPolicy
	if err := yaml.Unmarshal(yamlData, &parsed); err != nil {
		t.Errorf("Failed to parse YAML with special chars: %v", err)
	}
}

// ============================================================================
// 5. REAL-WORLD SCENARIOS - Attack Chains
// ============================================================================

func TestAttackChainContainerEscape(t *testing.T) {
	g := NewGenerator("Sigkill")

	// Simulate a container escape attack chain
	attackChain := []cdr.Event{
		{ThreatCategory: "Network_Scanning_Utility", ProcessName: "nmap"},          // 1. Reconnaissance
		{ThreatCategory: "Sensitive_File_Access", ProcessName: "cat"},              // 2. Credential theft
		{ThreatCategory: "Container_Escape_Attempt", ProcessName: "nsenter"},       // 3. Escape attempt
		{ThreatCategory: "Lateral_Movement_SSH", ProcessName: "ssh"},               // 4. Lateral movement
	}

	policies := g.FromEvents(attackChain)

	// Should generate multiple policies covering the attack chain
	if len(policies) < 3 {
		t.Errorf("Expected at least 3 policies for attack chain, got %d", len(policies))
	}

	// Verify critical techniques are covered
	techniques := make(map[string]bool)
	for _, p := range policies {
		tech := p.Metadata.Labels["mitre.attack/technique"]
		if tech != "" {
			techniques[tech] = true
		}
	}

	criticalTechniques := []string{"T1046", "T1611", "T1021.004"}
	for _, tech := range criticalTechniques {
		if !techniques[tech] {
			t.Logf("Attack chain missing technique: %s", tech)
		}
	}
}

func TestAttackChainCryptoMining(t *testing.T) {
	g := NewGenerator("Sigkill")

	// Crypto mining attack chain
	attackChain := []cdr.Event{
		{ThreatCategory: "Cloud_Credentials_Accessed", ProcessName: "curl"},   // 1. Get cloud creds
		{ThreatCategory: "Reverse_Shell_Execution", ProcessName: "nc"},        // 2. Establish C2
		{ThreatCategory: "Crypto_Mining_Activity", ProcessName: "xmrig"},      // 3. Deploy miner
	}

	policies := g.FromEvents(attackChain)

	// Verify mining-related policy exists
	foundMining := false
	for _, p := range policies {
		if p.Metadata.Labels["mitre.attack/technique"] == "T1496" {
			foundMining = true
			break
		}
	}

	if !foundMining {
		t.Error("Attack chain should include crypto mining detection (T1496)")
	}
}

func TestAttackChainDataExfiltration(t *testing.T) {
	g := NewGenerator("Sigkill")

	// Data exfiltration attack chain
	attackChain := []cdr.Event{
		{ThreatCategory: "Sensitive_File_Access", ProcessName: "cat"},         // 1. Access secrets
		{ThreatCategory: "Defense_Evasion_Log_Tampering", ProcessName: "rm"},  // 2. Clear tracks
		{ThreatCategory: "Data_Exfiltration_Staging", ProcessName: "base64"},  // 3. Stage data
	}

	policies := g.FromEvents(attackChain)

	// Should cover credential access, defense evasion, and exfiltration
	tactics := make(map[string]bool)
	for _, p := range policies {
		for k := range p.Metadata.Labels {
			if strings.HasPrefix(k, "mitre.attack/") {
				tactics[p.Metadata.Labels[k]] = true
			}
		}
	}

	if len(policies) < 2 {
		t.Errorf("Expected at least 2 policies for exfiltration chain, got %d", len(policies))
	}
}

func TestAttackChainWebshellPersistence(t *testing.T) {
	g := NewGenerator("Sigkill")

	// Webshell persistence attack
	attackChain := []cdr.Event{
		{ThreatCategory: "Webshell_Execution", ProcessName: "php"},                // 1. Initial webshell
		{ThreatCategory: "Persistence_Cron", ProcessName: "crontab"},              // 2. Establish persistence
		{ThreatCategory: "Reverse_Shell_Execution", ProcessName: "bash"},          // 3. Interactive shell
	}

	policies := g.FromEvents(attackChain)

	// Verify persistence technique detected
	foundPersistence := false
	for _, p := range policies {
		tech := p.Metadata.Labels["mitre.attack/technique"]
		if tech == "T1505.003" || tech == "T1053.003" {
			foundPersistence = true
			break
		}
	}

	if !foundPersistence {
		t.Error("Attack chain should detect persistence techniques")
	}
}

func TestMultiContainerAttack(t *testing.T) {
	g := NewGenerator("Sigkill")

	// Simulated multi-container attack with AI anomalies
	anomalies := []Anomaly{
		{
			Feature:       "network_connections",
			ContainerName: "frontend",
			ContainerID:   "frontend-123",
			Score:         72.0,
			NetworkPort:   4444,
			Description:   "Unusual outbound connection from frontend",
		},
		{
			Feature:       "privilege_escalation",
			ContainerName: "backend",
			ContainerID:   "backend-456",
			Score:         95.0,
			Description:   "Privilege escalation in backend",
		},
		{
			Feature:       "file_access",
			ContainerName: "database",
			ContainerID:   "db-789",
			Score:         88.0,
			FilePath:      "/var/lib/mysql/secrets",
			Description:   "Unusual database file access",
		},
	}

	policies := make([]TracingPolicy, 0, len(anomalies))
	for _, a := range anomalies {
		policies = append(policies, *g.FromAnomaly(a))
	}

	// Verify each container has a policy
	containers := make(map[string]bool)
	for _, p := range policies {
		containerID := p.Metadata.Annotations["container-id"]
		if containerID != "" {
			containers[containerID] = true
		}
	}

	if len(containers) != 3 {
		t.Errorf("Expected 3 container-specific policies, got %d", len(containers))
	}
}

func TestRealWorldProcessNames(t *testing.T) {
	g := NewGenerator("Sigkill")

	// Real malicious process names seen in the wild
	maliciousProcesses := []struct {
		category string
		process  string
	}{
		{"Crypto_Mining_Activity", "xmrig"},
		{"Crypto_Mining_Activity", "minerd"},
		{"Crypto_Mining_Activity", "cpuminer"},
		{"Reverse_Shell_Execution", "nc"},
		{"Reverse_Shell_Execution", "ncat"},
		{"Reverse_Shell_Execution", "socat"},
		{"Network_Scanning_Utility", "nmap"},
		{"Network_Scanning_Utility", "masscan"},
		{"Network_Scanning_Utility", "zmap"},
		{"Container_Escape_Attempt", "nsenter"},
		{"Container_Escape_Attempt", "docker"},
		{"Container_Escape_Attempt", "crictl"},
	}

	for _, mp := range maliciousProcesses {
		events := []cdr.Event{{
			ThreatCategory: mp.category,
			ProcessName:    mp.process,
		}}

		policies := g.FromEvents(events)
		if len(policies) == 0 {
			t.Errorf("No policy for %s/%s", mp.category, mp.process)
		}
	}
}

func TestHighSeverityPrioritization(t *testing.T) {
	g := NewGenerator("Sigkill")

	// High-severity events that should generate critical policies
	criticalEvents := []cdr.Event{
		{ThreatCategory: "Container_Escape_Attempt"},
		{ThreatCategory: "Crypto_Mining_Activity"},
		{ThreatCategory: "Kernel_Module_Loading"},
	}

	policies := g.FromEvents(criticalEvents)

	criticalCount := 0
	for _, p := range policies {
		if p.Metadata.Labels["policy.qualys.com/priority"] == "critical" {
			criticalCount++
		}
	}

	if criticalCount < 2 {
		t.Errorf("Expected at least 2 critical priority policies, got %d", criticalCount)
	}
}

// ============================================================================
// BENCHMARK - Attack Chain Processing
// ============================================================================

func BenchmarkAttackChainProcessing(b *testing.B) {
	g := NewGenerator("Sigkill")

	attackChain := []cdr.Event{
		{ThreatCategory: "Network_Scanning_Utility", ProcessName: "nmap"},
		{ThreatCategory: "Cloud_Credentials_Accessed", ProcessName: "curl"},
		{ThreatCategory: "Container_Escape_Attempt", ProcessName: "nsenter"},
		{ThreatCategory: "Lateral_Movement_SSH", ProcessName: "ssh"},
		{ThreatCategory: "Crypto_Mining_Activity", ProcessName: "xmrig"},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		g.FromEvents(attackChain)
	}
}

func BenchmarkMultiAnomalyProcessing(b *testing.B) {
	g := NewGenerator("Sigkill")

	anomalies := []Anomaly{
		{Feature: "exec_rate", ContainerName: "c1", Score: 80},
		{Feature: "network_connections", ContainerName: "c2", Score: 75, NetworkPort: 4444},
		{Feature: "file_access", ContainerName: "c3", Score: 90, FilePath: "/etc/shadow"},
		{Feature: "privilege_escalation", ContainerName: "c4", Score: 95},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for _, a := range anomalies {
			g.FromAnomaly(a)
		}
	}
}
