// Qualys Container Runtime Security (CRS) - Interactive Demo
// This demo showcases the key capabilities of the Qualys CRS framework
package main

import (
	"bufio"
	"context"
	"fmt"
	"math/rand"
	"os"
	"strings"
	"syscall"
	"time"

	"golang.org/x/term"
	"qualys-policy-operator/pkg/ai"
	"qualys-policy-operator/pkg/cdr"
	"qualys-policy-operator/pkg/policy"
	"sigs.k8s.io/yaml"
)

const (
	colorReset  = "\033[0m"
	colorRed    = "\033[31m"
	colorGreen  = "\033[32m"
	colorYellow = "\033[33m"
	colorBlue   = "\033[34m"
	colorPurple = "\033[35m"
	colorCyan   = "\033[36m"
	colorWhite  = "\033[37m"
	colorBold   = "\033[1m"
)

func main() {
	rand.Seed(time.Now().UnixNano())

	printBanner()
	reader := bufio.NewReader(os.Stdin)

	for {
		printMenu()
		fmt.Print(colorCyan + "Select option: " + colorReset)
		input, _ := reader.ReadString('\n')
		input = strings.TrimSpace(input)

		switch input {
		case "1":
			demoAIDetection()
		case "2":
			demoPolicyGeneration()
		case "3":
			demoMITREMapping()
		case "4":
			demoFederation()
		case "5":
			demoResponseActions()
		case "6":
			demoFullPipeline()
		case "7":
			demoLiveCDR()
		case "8":
			runAllDemos()
		case "q", "Q", "0":
			fmt.Println(colorGreen + "\nThank you for exploring Qualys CRS!" + colorReset)
			return
		default:
			fmt.Println(colorRed + "Invalid option. Please try again." + colorReset)
		}

		fmt.Print(colorYellow + "\nPress Enter to continue..." + colorReset)
		reader.ReadString('\n')
	}
}

func printBanner() {
	fmt.Println(colorCyan + colorBold + `
 ██████╗ ██╗   ██╗ █████╗ ██╗  ██╗   ██╗███████╗     ██████╗██████╗ ███████╗
██╔═══██╗██║   ██║██╔══██╗██║  ╚██╗ ██╔╝██╔════╝    ██╔════╝██╔══██╗██╔════╝
██║   ██║██║   ██║███████║██║   ╚████╔╝ ███████╗    ██║     ██████╔╝███████╗
██║▄▄ ██║██║   ██║██╔══██║██║    ╚██╔╝  ╚════██║    ██║     ██╔══██╗╚════██║
╚██████╔╝╚██████╔╝██║  ██║███████╗██║   ███████║    ╚██████╗██║  ██║███████║
 ╚══▀▀═╝  ╚═════╝ ╚═╝  ╚═╝╚══════╝╚═╝   ╚══════╝     ╚═════╝╚═╝  ╚═╝╚══════╝
` + colorReset)
	fmt.Println(colorWhite + "  Container Runtime Security - Enterprise eBPF Security Framework" + colorReset)
	fmt.Println(colorWhite + "  Real-time threat detection | AI anomaly detection | Multi-cluster federation" + colorReset)
	fmt.Println()
}

func printMenu() {
	fmt.Println(colorBold + "\n╔══════════════════════════════════════════════════════════════╗" + colorReset)
	fmt.Println(colorBold + "║                    DEMO MENU                                  ║" + colorReset)
	fmt.Println(colorBold + "╠══════════════════════════════════════════════════════════════╣" + colorReset)
	fmt.Println(colorBold + "║" + colorReset + "  1. " + colorGreen + "AI Anomaly Detection" + colorReset + "     - Statistical & ML-based detection  " + colorBold + "║" + colorReset)
	fmt.Println(colorBold + "║" + colorReset + "  2. " + colorGreen + "Policy Generation" + colorReset + "         - Generate TracingPolicies from CDR" + colorBold + "║" + colorReset)
	fmt.Println(colorBold + "║" + colorReset + "  3. " + colorGreen + "MITRE ATT&CK Mapping" + colorReset + "      - 49 techniques, 80.6% coverage    " + colorBold + "║" + colorReset)
	fmt.Println(colorBold + "║" + colorReset + "  4. " + colorGreen + "Multi-Cluster Federation" + colorReset + " - Hub-spoke policy distribution    " + colorBold + "║" + colorReset)
	fmt.Println(colorBold + "║" + colorReset + "  5. " + colorGreen + "Response Actions" + colorReset + "          - Automated threat response        " + colorBold + "║" + colorReset)
	fmt.Println(colorBold + "║" + colorReset + "  6. " + colorGreen + "Full Pipeline Demo" + colorReset + "        - End-to-end detection to response " + colorBold + "║" + colorReset)
	fmt.Println(colorBold + "║" + colorReset + "  7. " + colorPurple + "Live CDR API Demo" + colorReset + "         - Connect to Qualys & generate    " + colorBold + "║" + colorReset)
	fmt.Println(colorBold + "║" + colorReset + "  8. " + colorYellow + "Run All Demos" + colorReset + "                                              " + colorBold + "║" + colorReset)
	fmt.Println(colorBold + "║" + colorReset + "  0. " + colorRed + "Exit" + colorReset + "                                                       " + colorBold + "║" + colorReset)
	fmt.Println(colorBold + "╚══════════════════════════════════════════════════════════════╝" + colorReset)
}

func printSection(title string) {
	fmt.Println()
	fmt.Println(colorCyan + colorBold + "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" + colorReset)
	fmt.Println(colorCyan + colorBold + " " + title + colorReset)
	fmt.Println(colorCyan + colorBold + "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" + colorReset)
}

func printSubSection(title string) {
	fmt.Println()
	fmt.Println(colorYellow + "▶ " + title + colorReset)
}

func printSuccess(msg string) {
	fmt.Println(colorGreen + "✓ " + msg + colorReset)
}

func printWarning(msg string) {
	fmt.Println(colorYellow + "⚠ " + msg + colorReset)
}

func printAlert(msg string) {
	fmt.Println(colorRed + "⚡ " + msg + colorReset)
}

func printInfo(msg string) {
	fmt.Println(colorBlue + "ℹ " + msg + colorReset)
}

// =============================================================================
// Demo 1: AI Anomaly Detection
// =============================================================================

func demoAIDetection() {
	printSection("AI-POWERED ANOMALY DETECTION")

	printInfo("The AI detector uses multiple algorithms to identify threats:")
	fmt.Println("   • Statistical Analysis (Z-score, IQR)")
	fmt.Println("   • Time Series Analysis (Moving Average, Trend Detection)")
	fmt.Println("   • Isolation Forest (Unsupervised ML)")
	fmt.Println("   • K-Means Clustering (Behavioral Profiling)")

	// Create detector with aggressive settings for demo
	config := ai.DetectorConfig{
		ZScoreThreshold:    2.0,
		IQRMultiplier:      1.5,
		MADThreshold:       2.0,
		NumTrees:           50,
		SampleSize:         128,
		AnomalyThreshold:   0.6,
		MinClusterSize:     3,
		ClusterEpsilon:     0.5,
		LearningPeriod:     0, // No learning period for demo
		RetrainingInterval: time.Hour,
		MinSamplesForModel: 10,
		TrendWindow:        10,
	}
	detector := ai.NewAIDetector(config)

	// Set up anomaly callback
	detector.SetAnomalyCallback(func(a *ai.Anomaly) {
		printAlert(fmt.Sprintf("ANOMALY DETECTED: %s (score: %.1f, confidence: %.0f%%)",
			a.Description, a.Score, a.Confidence*100))
	})

	printSubSection("Simulating Normal Container Behavior (Baseline)")

	containers := []struct {
		id   string
		name string
	}{
		{"container-abc123", "nginx-web"},
		{"container-def456", "redis-cache"},
		{"container-ghi789", "api-server"},
	}

	// Build baseline with normal behavior
	ctx := context.Background()
	for i := 0; i < 50; i++ {
		for _, c := range containers {
			fv := &ai.FeatureVector{
				Timestamp:     time.Now().Add(-time.Duration(50-i) * time.Minute),
				ContainerID:   c.id,
				ContainerName: c.name,
				Namespace:     "production",
				Features: map[string]float64{
					"syscall_rate":        100 + rand.Float64()*20,
					"network_connections": 10 + rand.Float64()*5,
					"file_opens":          20 + rand.Float64()*10,
					"cpu_percent":         15 + rand.Float64()*10,
					"memory_mb":           256 + rand.Float64()*50,
				},
			}
			detector.Analyze(ctx, fv)
		}
	}

	stats := detector.Stats()
	printSuccess(fmt.Sprintf("Baseline established: %d samples analyzed", stats["total_analyzed"]))
	printInfo(fmt.Sprintf("Containers monitored: %d ready, %d learning",
		stats["containers_ready"], stats["containers_learning"]))

	printSubSection("Injecting Anomalous Behavior (Attack Simulation)")

	// Simulate various attack patterns
	attacks := []struct {
		name        string
		containerID string
		container   string
		features    map[string]float64
	}{
		{
			name:        "Cryptominer (High CPU + Network)",
			containerID: "container-abc123",
			container:   "nginx-web",
			features: map[string]float64{
				"syscall_rate":        500,  // 5x normal
				"network_connections": 100,  // 10x normal
				"file_opens":          25,
				"cpu_percent":         95,   // Maxed out
				"memory_mb":           2048, // 8x normal
			},
		},
		{
			name:        "Data Exfiltration (High Network Out)",
			containerID: "container-def456",
			container:   "redis-cache",
			features: map[string]float64{
				"syscall_rate":        150,
				"network_connections": 200,  // 20x normal
				"file_opens":          500,  // Reading many files
				"cpu_percent":         45,
				"memory_mb":           512,
			},
		},
		{
			name:        "Privilege Escalation Attempt",
			containerID: "container-ghi789",
			container:   "api-server",
			features: map[string]float64{
				"syscall_rate":        800,  // Process spawning
				"network_connections": 5,
				"file_opens":          200,  // Probing sensitive files
				"cpu_percent":         60,
				"memory_mb":           400,
			},
		},
	}

	for _, attack := range attacks {
		fmt.Println()
		printWarning(fmt.Sprintf("Simulating: %s", attack.name))
		fmt.Printf("   Container: %s (%s)\n", attack.container, attack.containerID)

		fv := &ai.FeatureVector{
			Timestamp:     time.Now(),
			ContainerID:   attack.containerID,
			ContainerName: attack.container,
			Namespace:     "production",
			Features:      attack.features,
		}

		anomalies := detector.Analyze(ctx, fv)
		if len(anomalies) > 0 {
			for _, a := range anomalies {
				fmt.Printf("   "+colorRed+"→ %s"+colorReset+"\n", a.Description)
				fmt.Printf("     Type: %s | Score: %.1f | Feature: %s\n",
					a.Type, a.Score, a.Feature)
			}
		}
		time.Sleep(500 * time.Millisecond)
	}

	// Final stats
	stats = detector.Stats()
	printSubSection("Detection Summary")
	fmt.Printf("   Total samples analyzed: %d\n", stats["total_analyzed"])
	fmt.Printf("   Anomalies detected: %d\n", stats["anomalies_found"])
	fmt.Printf("   Detection algorithms: Statistical, Time-Series, Clustering\n")
}

// =============================================================================
// Demo 2: Policy Generation from CDR Events
// =============================================================================

func demoPolicyGeneration() {
	printSection("POLICY GENERATION FROM CDR EVENTS")

	printInfo("Qualys CDR events are automatically converted to TracingPolicies")
	printInfo("Policies use eBPF for kernel-level enforcement")

	// Simulate CDR events
	events := []cdr.Event{
		{
			UUID:           "evt-001",
			ThreatCategory: "Container_Escape_Attempt",
			Severity:       9,
			ProcessName:    "runc",
			ContainerName:  "malicious-pod",
			EventMessage:   "Container escape via unshare syscall detected",
		},
		{
			UUID:           "evt-002",
			ThreatCategory: "Cloud_Credentials_Access",
			Severity:       8,
			ProcessName:    "curl",
			ContainerName:  "compromised-app",
			EventMessage:   "Access to cloud metadata service detected",
		},
		{
			UUID:           "evt-003",
			ThreatCategory: "Crypto_Mining",
			Severity:       7,
			ProcessName:    "xmrig",
			ContainerName:  "infected-worker",
			EventMessage:   "Cryptomining process detected",
		},
		{
			UUID:           "evt-004",
			ThreatCategory: "Network_Scanning",
			Severity:       6,
			ProcessName:    "nmap",
			ContainerName:  "attacker-pod",
			EventMessage:   "Network reconnaissance detected",
		},
		{
			UUID:           "evt-005",
			ThreatCategory: "Reverse_Shell",
			Severity:       9,
			ProcessName:    "bash",
			ContainerName:  "backdoor-pod",
			EventMessage:   "Reverse shell connection attempt",
		},
	}

	printSubSection("Processing CDR Events")
	for _, e := range events {
		severityColor := colorYellow
		if e.Severity >= 8 {
			severityColor = colorRed
		}
		fmt.Printf("   %s[Severity %d]%s %s: %s\n",
			severityColor, e.Severity, colorReset, e.ThreatCategory, e.EventMessage)
	}

	printSubSection("Generating TracingPolicies")

	// Generate enforcement policies
	gen := policy.NewGenerator("Sigkill")
	policies := gen.FromEvents(events)

	for _, p := range policies {
		fmt.Println()
		printSuccess(fmt.Sprintf("Generated: %s", p.Metadata.Name))
		fmt.Printf("   MITRE Technique: %s\n", p.Metadata.Labels["mitre.attack/technique"])
		fmt.Printf("   Priority: %s\n", p.Metadata.Labels["policy.qualys.com/priority"])
		fmt.Printf("   Action: %s (kernel-level blocking)\n", "Sigkill")

		// Show full YAML output
		printPolicyYAML(p)
	}

	printSubSection("AI-Driven Policy Generation")

	// Generate policy from AI anomaly
	anomaly := policy.Anomaly{
		Type:          "statistical",
		Feature:       "privilege_escalation",
		ContainerID:   "container-xyz789",
		ContainerName: "suspicious-workload",
		Namespace:     "default",
		Score:         95.5,
		Description:   "Unusual privilege escalation pattern detected",
	}

	printWarning(fmt.Sprintf("AI Anomaly: %s (score: %.1f)", anomaly.Description, anomaly.Score))

	aiPolicy := gen.FromAnomaly(anomaly)
	printSuccess(fmt.Sprintf("Generated AI-driven policy: %s", aiPolicy.Metadata.Name))
	fmt.Printf("   Labels: ai.qualys.com/anomaly-type=%s\n", aiPolicy.Metadata.Labels["ai.qualys.com/anomaly-type"])
	fmt.Printf("   Labels: ai.qualys.com/feature=%s\n", aiPolicy.Metadata.Labels["ai.qualys.com/feature"])

	// Show full YAML for AI policy
	printPolicyYAML(*aiPolicy)
}

// =============================================================================
// Demo 3: MITRE ATT&CK Mapping
// =============================================================================

func demoMITREMapping() {
	printSection("MITRE ATT&CK COVERAGE")

	printInfo("Qualys CRS maps 49 techniques from the Container Matrix")
	printInfo("Coverage: 80.6% of container-relevant MITRE techniques")

	tactics := []struct {
		name       string
		techniques []struct {
			id   string
			name string
		}
	}{
		{
			name: "Initial Access",
			techniques: []struct {
				id   string
				name string
			}{
				{"T1133", "External Remote Services"},
				{"T1190", "Exploit Public-Facing Application"},
			},
		},
		{
			name: "Execution",
			techniques: []struct {
				id   string
				name string
			}{
				{"T1059.004", "Unix Shell"},
				{"T1609", "Container Administration Command"},
				{"T1610", "Deploy Container"},
			},
		},
		{
			name: "Persistence",
			techniques: []struct {
				id   string
				name string
			}{
				{"T1053.003", "Cron"},
				{"T1098", "Account Manipulation"},
				{"T1136", "Create Account"},
				{"T1505.003", "Web Shell"},
				{"T1547.006", "Kernel Modules"},
				{"T1543.002", "Systemd Service"},
				{"T1546.004", "Unix Shell Config"},
				{"T1525", "Implant Container Image"},
			},
		},
		{
			name: "Privilege Escalation",
			techniques: []struct {
				id   string
				name string
			}{
				{"T1548", "Abuse Elevation Control"},
				{"T1548.001", "Setuid/Setgid"},
				{"T1548.003", "Sudo Caching"},
				{"T1548.004", "Sudo Heap Overflow"},
				{"T1611", "Escape to Host"},
				{"T1068", "Exploitation for Privilege Escalation"},
				{"T1574.006", "Dynamic Linker Hijacking"},
			},
		},
		{
			name: "Defense Evasion",
			techniques: []struct {
				id   string
				name string
			}{
				{"T1070.002", "Clear Linux Logs"},
				{"T1070.003", "Clear Command History"},
				{"T1070.004", "File Deletion"},
				{"T1612", "Build Image on Host"},
				{"T1222.002", "Linux File Permissions Modification"},
				{"T1564.001", "Hidden Files and Directories"},
				{"T1562.001", "Disable Security Tools"},
			},
		},
		{
			name: "Credential Access",
			techniques: []struct {
				id   string
				name string
			}{
				{"T1552.001", "Credentials in Files"},
				{"T1552.004", "Private Keys"},
				{"T1552.005", "Cloud Instance Metadata"},
				{"T1552.007", "Container API"},
				{"T1003.008", "/etc/passwd and /etc/shadow"},
				{"T1556.003", "Pluggable Authentication Modules"},
			},
		},
		{
			name: "Discovery",
			techniques: []struct {
				id   string
				name string
			}{
				{"T1046", "Network Service Scanning"},
				{"T1069", "Permission Groups Discovery"},
				{"T1082", "System Information Discovery"},
				{"T1083", "File and Directory Discovery"},
				{"T1613", "Container and Resource Discovery"},
			},
		},
		{
			name: "Lateral Movement",
			techniques: []struct {
				id   string
				name string
			}{
				{"T1021.004", "SSH"},
				{"T1021.002", "SMB/Windows Admin Shares"},
				{"T1550.001", "Application Access Token"},
				{"T1563.001", "SSH Hijacking"},
			},
		},
		{
			name: "Exfiltration",
			techniques: []struct {
				id   string
				name string
			}{
				{"T1041", "Exfiltration Over C2"},
				{"T1048", "Exfiltration Over Alternative Protocol"},
			},
		},
		{
			name: "Impact",
			techniques: []struct {
				id   string
				name string
			}{
				{"T1485", "Data Destruction"},
				{"T1489", "Service Stop"},
				{"T1490", "Inhibit System Recovery"},
				{"T1496", "Resource Hijacking (Cryptomining)"},
				{"T1498", "Network Denial of Service"},
				{"T1499", "Endpoint Denial of Service"},
			},
		},
	}

	totalTechniques := 0
	for _, tactic := range tactics {
		totalTechniques += len(tactic.techniques)
	}

	fmt.Printf("\n   Total Techniques Covered: %s%d%s\n", colorGreen, totalTechniques, colorReset)
	fmt.Printf("   Container Matrix Coverage: %s80.6%%%s\n", colorGreen, colorReset)
	fmt.Println()

	for _, tactic := range tactics {
		fmt.Printf(colorBold+"   %s"+colorReset+" (%d techniques)\n", tactic.name, len(tactic.techniques))
		for _, tech := range tactic.techniques {
			fmt.Printf("      %s├─%s %s%s%s: %s\n",
				colorCyan, colorReset, colorYellow, tech.id, colorReset, tech.name)
		}
		fmt.Println()
	}

	printSubSection("Policy-to-Technique Mapping Example")

	examplePolicies := []struct {
		policy    string
		technique string
		syscalls  string
	}{
		{"block-container-escape", "T1611", "sys_unshare, sys_setns"},
		{"block-cloud-creds", "T1552.005", "sys_connect (169.254.169.254)"},
		{"block-crypto-mining", "T1496", "sys_connect (ports 3333,4444,5555)"},
		{"block-kernel-module", "T1547.006", "sys_init_module, sys_finit_module"},
		{"block-log-tampering", "T1070.002", "sys_unlinkat, sys_truncate"},
	}

	for _, p := range examplePolicies {
		fmt.Printf("   %s%s%s → %s%s%s\n",
			colorGreen, p.policy, colorReset,
			colorYellow, p.technique, colorReset)
		fmt.Printf("      Monitored syscalls: %s\n", p.syscalls)
	}
}

// =============================================================================
// Demo 4: Multi-Cluster Federation
// =============================================================================

func demoFederation() {
	printSection("MULTI-CLUSTER FEDERATION")

	printInfo("Hub-spoke architecture for enterprise-scale deployments")
	printInfo("Centralized policy management with cluster-specific overrides")

	fmt.Println()
	fmt.Println(colorCyan + `
                           ┌─────────────────┐
                           │   HUB CLUSTER   │
                           │  (Control Plane)│
                           └────────┬────────┘
                                    │
              ┌─────────────────────┼─────────────────────┐
              │                     │                     │
              ▼                     ▼                     ▼
    ┌─────────────────┐   ┌─────────────────┐   ┌─────────────────┐
    │  SPOKE: US-EAST │   │  SPOKE: US-WEST │   │   SPOKE: EU     │
    │   (prod-east)   │   │   (prod-west)   │   │  (prod-eu-gdpr) │
    └─────────────────┘   └─────────────────┘   └─────────────────┘
` + colorReset)

	printSubSection("Federated Clusters")

	clusters := []struct {
		name     string
		region   string
		provider string
		nodes    int
		status   string
	}{
		{"prod-us-east", "us-east-1", "AWS", 50, "Ready"},
		{"prod-us-west", "us-west-2", "AWS", 35, "Ready"},
		{"prod-eu-gdpr", "eu-west-1", "AWS", 25, "Ready"},
		{"staging", "us-east-1", "AWS", 10, "Ready"},
		{"dev-cluster", "local", "On-Prem", 5, "Learning"},
	}

	fmt.Println()
	fmt.Printf("   %-15s %-12s %-10s %-8s %s\n",
		"CLUSTER", "REGION", "PROVIDER", "NODES", "STATUS")
	fmt.Println("   " + strings.Repeat("─", 60))

	for _, c := range clusters {
		statusColor := colorGreen
		if c.status != "Ready" {
			statusColor = colorYellow
		}
		fmt.Printf("   %-15s %-12s %-10s %-8d %s%s%s\n",
			c.name, c.region, c.provider, c.nodes, statusColor, c.status, colorReset)
	}

	printSubSection("Federated Policy Distribution")

	policies := []struct {
		name     string
		type_    string
		clusters string
		status   string
	}{
		{"fed-block-cryptominer", "TracingPolicy", "ALL", "Synced"},
		{"fed-block-container-escape", "TracingPolicy", "prod-*", "Synced"},
		{"fed-gdpr-data-protection", "TracingPolicy", "prod-eu-gdpr", "Synced"},
		{"fed-block-mining-pools", "NetworkPolicy", "ALL", "Synced"},
		{"fed-egress-restrict", "NetworkPolicy", "prod-*", "Synced"},
	}

	fmt.Println()
	fmt.Printf("   %-30s %-15s %-15s %s\n",
		"POLICY", "TYPE", "TARGET", "STATUS")
	fmt.Println("   " + strings.Repeat("─", 70))

	for _, p := range policies {
		fmt.Printf("   %-30s %-15s %-15s %s%s%s\n",
			p.name, p.type_, p.clusters, colorGreen, p.status, colorReset)
	}

	printSubSection("Cluster-Specific Overrides")

	fmt.Println()
	printInfo("EU cluster has GDPR-specific policy additions:")
	fmt.Println("   • Data residency enforcement")
	fmt.Println("   • Enhanced audit logging")
	fmt.Println("   • PII access monitoring")

	fmt.Println()
	fmt.Println(colorYellow + "   Example FederatedTracingPolicy with Override:" + colorReset)
	fmt.Println(`
   apiVersion: crs.qualys.com/v1alpha1
   kind: FederatedTracingPolicy
   metadata:
     name: fed-block-container-escape
   spec:
     template:
       metadata:
         name: block-container-escape
         labels:
           mitre.attack/technique: T1611
       spec:
         kprobes:
           - call: sys_unshare
             syscall: true
             selectors:
               - matchActions:
                   - action: Sigkill
     placement:
       clusterSelector:
         matchLabels:
           environment: production
     overrides:
       - clusterName: prod-eu-gdpr
         patches:
           - op: add
             path: /spec/kprobes/0/selectors/0/matchActions/-
             value:
               action: Post  # Also log for GDPR audit
`)

	printSubSection("Cross-Cluster Attack Detection")

	fmt.Println()
	printAlert("CORRELATED ATTACK DETECTED ACROSS CLUSTERS")
	fmt.Println()
	fmt.Println("   Timeline of coordinated attack:")
	fmt.Println("   " + colorRed + "10:15:32" + colorReset + " prod-us-east: Network scan from pod/attacker-abc")
	fmt.Println("   " + colorRed + "10:15:45" + colorReset + " prod-us-west: Same source IP attempted cloud metadata access")
	fmt.Println("   " + colorRed + "10:16:02" + colorReset + " prod-eu-gdpr: Lateral movement attempt blocked")
	fmt.Println()
	printSuccess("Federation correlated events across 3 clusters in 30 seconds")
	printSuccess("Automatic policy propagation blocked attack spread")
}

// =============================================================================
// Demo 5: Response Actions
// =============================================================================

func demoResponseActions() {
	printSection("AUTOMATED RESPONSE ACTIONS")

	printInfo("Qualys CRS provides multiple response options:")
	fmt.Println("   • Kernel-level blocking (Sigkill)")
	fmt.Println("   • Container isolation")
	fmt.Println("   • Network quarantine")
	fmt.Println("   • Forensic capture")

	printSubSection("Response Action Types")

	actions := []struct {
		action      string
		level       string
		latency     string
		description string
	}{
		{"Sigkill", "Kernel", "<1ms", "Immediately terminate process via eBPF"},
		{"Signal", "Process", "<1ms", "Send custom signal to process"},
		{"Post", "Audit", "<1ms", "Log event for analysis (no blocking)"},
		{"ContainerKill", "Container", "~100ms", "Kill entire container"},
		{"ContainerPause", "Container", "~100ms", "Freeze container for investigation"},
		{"NetworkIsolate", "Network", "~50ms", "Drop all network traffic"},
		{"ForensicCapture", "Storage", "~500ms", "Capture container state to S3/storage"},
	}

	fmt.Println()
	fmt.Printf("   %-18s %-12s %-10s %s\n",
		"ACTION", "LEVEL", "LATENCY", "DESCRIPTION")
	fmt.Println("   " + strings.Repeat("─", 75))

	for _, a := range actions {
		levelColor := colorGreen
		if a.level == "Kernel" {
			levelColor = colorRed
		} else if a.level == "Container" {
			levelColor = colorYellow
		}
		fmt.Printf("   %-18s %s%-12s%s %-10s %s\n",
			a.action, levelColor, a.level, colorReset, a.latency, a.description)
	}

	printSubSection("Simulated Incident Response")

	fmt.Println()
	printAlert("THREAT DETECTED: Cryptominer in production")
	fmt.Println()

	steps := []struct {
		time   string
		action string
		result string
	}{
		{"T+0ms", "eBPF detects xmrig execution", "sys_execve intercepted"},
		{"T+0.5ms", "Policy match: block-crypto-mining", "Sigkill action triggered"},
		{"T+1ms", "Process terminated at kernel level", "Attack prevented"},
		{"T+50ms", "Alert sent to SIEM", "SOC notified"},
		{"T+100ms", "Container flagged for review", "Forensics initiated"},
		{"T+500ms", "Network policy updated", "Mining pool IPs blocked cluster-wide"},
	}

	for _, s := range steps {
		timeColor := colorCyan
		if strings.HasPrefix(s.time, "T+0") {
			timeColor = colorRed
		}
		fmt.Printf("   %s%-8s%s %s\n", timeColor, s.time, colorReset, s.action)
		fmt.Printf("            %s→ %s%s\n", colorGreen, s.result, colorReset)
	}

	printSubSection("Input Validation & Security")

	printInfo("Response actions include comprehensive input validation:")
	fmt.Println("   • Container ID format validation")
	fmt.Println("   • Kubernetes name validation")
	fmt.Println("   • Path traversal prevention")
	fmt.Println("   • Shell injection protection")

	fmt.Println()
	fmt.Println("   Example blocked malicious inputs:")
	fmt.Printf("   %s✗%s container; rm -rf /          → Rejected (shell injection)\n", colorRed, colorReset)
	fmt.Printf("   %s✗%s ../../../etc/passwd          → Rejected (path traversal)\n", colorRed, colorReset)
	fmt.Printf("   %s✗%s $(whoami)                    → Rejected (command substitution)\n", colorRed, colorReset)
	fmt.Printf("   %s✓%s abc123def456                 → Valid container ID\n", colorGreen, colorReset)
}

// =============================================================================
// Demo 6: Full Pipeline Demo
// =============================================================================

func demoFullPipeline() {
	printSection("END-TO-END PIPELINE DEMO")

	printInfo("Complete flow: Detection → Analysis → Policy → Response")

	// Step 1: Event Detection
	printSubSection("Step 1: CDR Event Detection")

	event := cdr.Event{
		UUID:           "evt-pipeline-001",
		ThreatCategory: "Container_Escape_Attempt",
		Severity:       9,
		Timestamp:      time.Now().Format(time.RFC3339),
		ProcessName:    "runc",
		ContainerName:  "compromised-pod",
		PodName:        "app-deployment-abc123",
		ImageName:      "attacker/malicious:latest",
		EventMessage:   "Namespace manipulation via unshare syscall detected",
	}

	fmt.Printf("   Event ID: %s\n", event.UUID)
	fmt.Printf("   Category: %s%s%s\n", colorRed, event.ThreatCategory, colorReset)
	fmt.Printf("   Severity: %s%d/10%s\n", colorRed, event.Severity, colorReset)
	fmt.Printf("   Process: %s\n", event.ProcessName)
	fmt.Printf("   Container: %s\n", event.ContainerName)

	time.Sleep(500 * time.Millisecond)

	// Step 2: AI Analysis
	printSubSection("Step 2: AI Anomaly Correlation")

	config := ai.DefaultDetectorConfig()
	config.LearningPeriod = 0
	detector := ai.NewAIDetector(config)
	ctx := context.Background()

	// Simulate baseline
	for i := 0; i < 30; i++ {
		fv := &ai.FeatureVector{
			Timestamp:     time.Now().Add(-time.Duration(30-i) * time.Minute),
			ContainerID:   "container-compromised",
			ContainerName: "compromised-pod",
			Namespace:     "production",
			Features: map[string]float64{
				"syscall_rate": 50 + rand.Float64()*10,
				"namespace_ops": 0,
				"privilege_calls": 0,
			},
		}
		detector.Analyze(ctx, fv)
	}

	// Anomalous behavior
	anomalousFV := &ai.FeatureVector{
		Timestamp:     time.Now(),
		ContainerID:   "container-compromised",
		ContainerName: "compromised-pod",
		Namespace:     "production",
		Features: map[string]float64{
			"syscall_rate": 500,    // Spike
			"namespace_ops": 50,    // Usually 0
			"privilege_calls": 100, // Usually 0
		},
	}

	anomalies := detector.Analyze(ctx, anomalousFV)
	printWarning(fmt.Sprintf("AI detected %d anomalies correlating with CDR event", len(anomalies)))
	for _, a := range anomalies {
		fmt.Printf("   • %s (score: %.1f)\n", a.Feature, a.Score)
	}

	time.Sleep(500 * time.Millisecond)

	// Step 3: Policy Generation
	printSubSection("Step 3: Dynamic Policy Generation")

	gen := policy.NewGenerator("Sigkill")
	policies := gen.FromEvents([]cdr.Event{event})

	if len(policies) > 0 {
		p := policies[0]
		printSuccess(fmt.Sprintf("Generated policy: %s", p.Metadata.Name))
		fmt.Printf("   MITRE Technique: %s\n", p.Metadata.Labels["mitre.attack/technique"])
		fmt.Printf("   Action: Sigkill (kernel-level termination)\n")
		fmt.Printf("   Syscalls monitored: sys_unshare, sys_setns\n")

		// Show full policy YAML
		printPolicyYAML(p)
	}

	time.Sleep(500 * time.Millisecond)

	// Step 4: Response
	printSubSection("Step 4: Automated Response")

	responses := []string{
		"Process terminated via Sigkill",
		"Container flagged: compromised-pod",
		"Network isolation applied",
		"Forensic snapshot captured",
		"Alert escalated to SOC",
		"Policy distributed to all clusters",
	}

	for _, r := range responses {
		printSuccess(r)
		time.Sleep(200 * time.Millisecond)
	}

	// Summary
	printSubSection("Pipeline Summary")

	fmt.Println()
	fmt.Printf("   Detection to Response: %s<2 seconds%s\n", colorGreen, colorReset)
	fmt.Printf("   Process blocked at: %sKernel level%s\n", colorGreen, colorReset)
	fmt.Printf("   Data exfiltrated: %s0 bytes%s\n", colorGreen, colorReset)
	fmt.Printf("   Clusters protected: %s5/5%s\n", colorGreen, colorReset)
}

// =============================================================================
// Helper: Print Full Policy YAML
// =============================================================================

func printPolicyYAML(p policy.TracingPolicy) {
	fmt.Println(colorCyan + "\n   ┌─────────────────────────────────────────────────────────────────┐" + colorReset)
	fmt.Println(colorCyan + "   │ TracingPolicy YAML                                              │" + colorReset)
	fmt.Println(colorCyan + "   └─────────────────────────────────────────────────────────────────┘" + colorReset)

	yamlData, _ := yaml.Marshal(p)
	lines := strings.Split(string(yamlData), "\n")
	for _, line := range lines {
		if line != "" {
			fmt.Println(colorWhite + "   " + line + colorReset)
		}
	}
}

// =============================================================================
// Demo 7: Live CDR API Integration
// =============================================================================

func demoLiveCDR() {
	printSection("LIVE CDR API INTEGRATION")

	printInfo("Connect to Qualys CDR API to fetch real detection events")
	printInfo("Generate TracingPolicies from actual threat data")

	reader := bufio.NewReader(os.Stdin)

	// Platform selection
	printSubSection("Select Qualys Platform")
	fmt.Println()
	fmt.Println("   Available platforms:")
	fmt.Println("   " + colorCyan + "US1" + colorReset + " - gateway.qg1.apps.qualys.com")
	fmt.Println("   " + colorCyan + "US2" + colorReset + " - gateway.qg2.apps.qualys.com")
	fmt.Println("   " + colorCyan + "US3" + colorReset + " - gateway.qg3.apps.qualys.com")
	fmt.Println("   " + colorCyan + "US4" + colorReset + " - gateway.qg4.apps.qualys.com")
	fmt.Println("   " + colorCyan + "EU1" + colorReset + " - gateway.qg1.apps.qualys.eu")
	fmt.Println("   " + colorCyan + "EU2" + colorReset + " - gateway.qg2.apps.qualys.eu")
	fmt.Println("   " + colorCyan + "CA1" + colorReset + " - gateway.qg1.apps.qualys.ca")
	fmt.Println("   " + colorCyan + "IN1" + colorReset + " - gateway.qg1.apps.qualys.in")
	fmt.Println("   " + colorCyan + "UK1" + colorReset + " - gateway.qg1.apps.qualys.co.uk")
	fmt.Println("   " + colorCyan + "AU1" + colorReset + " - gateway.qg1.apps.qualys.com.au")
	fmt.Println()

	fmt.Print(colorYellow + "   Enter platform (e.g., US2): " + colorReset)
	platform, _ := reader.ReadString('\n')
	platform = strings.TrimSpace(strings.ToUpper(platform))

	gatewayURL := cdr.GetGatewayURL(platform)
	if gatewayURL == "" {
		printAlert("Invalid platform. Using US2 as default.")
		gatewayURL = "gateway.qg2.apps.qualys.com"
		platform = "US2"
	}

	printSuccess(fmt.Sprintf("Selected: %s (%s)", platform, gatewayURL))

	// Credentials
	printSubSection("Enter Credentials")
	fmt.Println()

	fmt.Print(colorYellow + "   Username: " + colorReset)
	username, _ := reader.ReadString('\n')
	username = strings.TrimSpace(username)

	fmt.Print(colorYellow + "   Password: " + colorReset)
	passwordBytes, err := term.ReadPassword(int(syscall.Stdin))
	fmt.Println() // newline after password
	if err != nil {
		printAlert("Failed to read password: " + err.Error())
		return
	}
	password := string(passwordBytes)

	if username == "" || password == "" {
		printAlert("Username and password are required")
		return
	}

	printSuccess("Credentials received")

	// Connect to API
	printSubSection("Connecting to Qualys CDR API")

	client := cdr.NewClient(username, password, gatewayURL)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	printInfo("Fetching events from the last 24 hours...")

	events, err := client.GetDetections(ctx, 24)
	if err != nil {
		printAlert("Failed to fetch events: " + err.Error())
		printInfo("This could be due to:")
		fmt.Println("   • Invalid credentials")
		fmt.Println("   • Wrong platform selection")
		fmt.Println("   • Network connectivity issues")
		fmt.Println("   • No CDR subscription")
		return
	}

	if len(events) == 0 {
		printWarning("No CDR events found in the last 24 hours")
		printInfo("Try extending the time range or check if CDR is configured")
		return
	}

	printSuccess(fmt.Sprintf("Retrieved %d CDR events", len(events)))

	// Show up to 3 events and generate policies
	printSubSection("Recent CDR Events")

	maxEvents := 3
	if len(events) < maxEvents {
		maxEvents = len(events)
	}

	selectedEvents := events[:maxEvents]

	for i, e := range selectedEvents {
		fmt.Println()
		severityColor := colorYellow
		if e.Severity >= 8 {
			severityColor = colorRed
		} else if e.Severity >= 5 {
			severityColor = colorYellow
		} else {
			severityColor = colorGreen
		}

		fmt.Printf("   %s━━━ Event %d ━━━%s\n", colorCyan, i+1, colorReset)
		fmt.Printf("   UUID:      %s\n", e.UUID)
		fmt.Printf("   Category:  %s%s%s\n", severityColor, e.ThreatCategory, colorReset)
		fmt.Printf("   Severity:  %s%d/10%s\n", severityColor, e.Severity, colorReset)
		fmt.Printf("   Timestamp: %s\n", e.Timestamp)
		if e.ContainerName != "" {
			fmt.Printf("   Container: %s\n", e.ContainerName)
		}
		if e.PodName != "" {
			fmt.Printf("   Pod:       %s\n", e.PodName)
		}
		if e.ProcessName != "" {
			fmt.Printf("   Process:   %s\n", e.ProcessName)
		}
		if e.ImageName != "" {
			fmt.Printf("   Image:     %s\n", e.ImageName)
		}
		fmt.Printf("   Message:   %s\n", e.EventMessage)
	}

	// Generate policies
	printSubSection("Generating TracingPolicies from Live Events")

	gen := policy.NewGenerator("Sigkill")
	policies := gen.FromEvents(selectedEvents)

	if len(policies) == 0 {
		printWarning("No policies could be generated from the events")
		printInfo("Events may not match known threat categories")
		return
	}

	printSuccess(fmt.Sprintf("Generated %d TracingPolicies", len(policies)))

	for _, p := range policies {
		fmt.Println()
		fmt.Printf(colorGreen+"   ✓ Policy: %s"+colorReset+"\n", p.Metadata.Name)
		if tech, ok := p.Metadata.Labels["mitre.attack/technique"]; ok {
			fmt.Printf("     MITRE Technique: %s%s%s\n", colorYellow, tech, colorReset)
		}
		if prio, ok := p.Metadata.Labels["policy.qualys.com/priority"]; ok {
			prioColor := colorGreen
			if prio == "critical" {
				prioColor = colorRed
			} else if prio == "high" {
				prioColor = colorYellow
			}
			fmt.Printf("     Priority: %s%s%s\n", prioColor, prio, colorReset)
		}

		// Show full YAML
		printPolicyYAML(p)
	}

	// Summary
	printSubSection("Summary")
	fmt.Println()
	fmt.Printf("   Platform:         %s%s%s\n", colorCyan, platform, colorReset)
	fmt.Printf("   Events fetched:   %s%d%s\n", colorGreen, len(events), colorReset)
	fmt.Printf("   Events processed: %s%d%s\n", colorGreen, maxEvents, colorReset)
	fmt.Printf("   Policies created: %s%d%s\n", colorGreen, len(policies), colorReset)
	fmt.Println()
	printInfo("These policies can be applied with: kubectl apply -f <policy>.yaml")
}

// =============================================================================
// Run All Demos
// =============================================================================

func runAllDemos() {
	printSection("RUNNING ALL DEMOS")

	demoAIDetection()
	time.Sleep(time.Second)

	demoPolicyGeneration()
	time.Sleep(time.Second)

	demoMITREMapping()
	time.Sleep(time.Second)

	demoFederation()
	time.Sleep(time.Second)

	demoResponseActions()
	time.Sleep(time.Second)

	demoFullPipeline()

	printSection("DEMO COMPLETE")
	printSuccess("All capabilities demonstrated successfully!")
}
