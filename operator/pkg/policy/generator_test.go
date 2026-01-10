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
