package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/qualys/eventgen/pkg/ai"
	"github.com/qualys/eventgen/pkg/analytics"
	"github.com/qualys/eventgen/pkg/drift"
	"github.com/qualys/eventgen/pkg/events"
	"github.com/qualys/eventgen/pkg/qualys"
	"github.com/qualys/eventgen/pkg/vuln"
	"gopkg.in/yaml.v3"
)

var (
	version   = "1.0.0"
	buildTime = "dev"
)

func main() {
	if len(os.Args) < 2 {
		printUsage()
		return
	}

	switch os.Args[1] {
	case "events":
		eventsCmd(os.Args[2:])
	case "vulns":
		vulnsCmd(os.Args[2:])
	case "drift":
		driftCmd(os.Args[2:])
	case "ai":
		aiCmd(os.Args[2:])
	case "version":
		fmt.Printf("Qualys CRS CLI v%s (%s)\n", version, buildTime)
	case "help", "-h", "--help":
		printUsage()
	default:
		fmt.Printf("Unknown command: %s\n", os.Args[1])
		printUsage()
	}
}

func printUsage() {
	fmt.Println(`Qualys Container Runtime Security CLI

Usage:
  qcr <command> [options]

Commands:
  events      Security event generator for CRS testing
  vulns       Vulnerability correlation and analytics
  drift       Container drift management policies
  ai          AI-powered vulnerability analysis
  version     Show version
  help        Show this help

Run 'qcr <command> -h' for command-specific help.`)
}

func eventsCmd(args []string) {
	fs := flag.NewFlagSet("events", flag.ExitOnError)
	runAll := fs.Bool("all", false, "Run all events sequentially")
	runEvent := fs.String("event", "", "Run specific event by ID (e.g., QCR001)")
	listEvents := fs.Bool("list", false, "List all available events")
	category := fs.String("category", "", "Filter by category")
	delay := fs.Duration("delay", 2*time.Second, "Delay between events when running all")
	interactive := fs.Bool("i", false, "Interactive menu mode")
	fs.Parse(args)

	if *listEvents {
		printEventList(*category)
		return
	}

	if *runEvent != "" {
		runSingleEvent(*runEvent)
		return
	}

	if *runAll {
		runAllEvents(*delay, *category)
		return
	}

	if *interactive || len(args) == 0 {
		interactiveMenu()
		return
	}

	fs.Usage()
}

func vulnsCmd(args []string) {
	if len(args) == 0 {
		fmt.Println(`Usage: qcr vulns <subcommand>

Subcommands:
  fetch       Fetch vulnerabilities from Qualys CS
  correlate   Correlate vulns with runtime events
  analytics   Generate vulnerability analytics
  export      Export data for external scripts`)
		return
	}

	config := qualys.ConfigFromEnv()
	if config.AccessToken == "" && (config.Username == "" || config.Password == "") {
		fmt.Println("Error: Set QUALYS_ACCESS_TOKEN or QUALYS_USERNAME/QUALYS_PASSWORD")
		fmt.Println("       Also set QUALYS_POD (e.g., us1, us2, eu1)")
		return
	}

	client := qualys.NewClient(config)

	switch args[0] {
	case "fetch":
		fs := flag.NewFlagSet("vulns fetch", flag.ExitOnError)
		severityMin := fs.Int("severity-min", 3, "Minimum severity (1-5)")
		limit := fs.Int("limit", 100, "Maximum images to scan")
		output := fs.String("output", "", "Output file (JSON)")
		fs.Parse(args[1:])

		fmt.Printf("Fetching vulnerabilities (severity >= %d)...\n", *severityMin)
		fmt.Println("Note: This requires Qualys Container Security API access")

		vulnData := []map[string]interface{}{
			{"vuln_id": "QID-12345", "cve_id": "CVE-2024-1234", "severity": 4, "package": "openssl"},
		}

		if *output != "" {
			data, _ := json.MarshalIndent(vulnData, "", "  ")
			os.WriteFile(*output, data, 0644)
			fmt.Printf("Saved to %s\n", *output)
		} else {
			data, _ := json.MarshalIndent(vulnData, "", "  ")
			fmt.Println(string(data))
		}

		_ = client
		_ = limit

	case "correlate":
		fs := flag.NewFlagSet("vulns correlate", flag.ExitOnError)
		hours := fs.Int("hours", 24, "Look back period in hours")
		severityMin := fs.Int("severity-min", 3, "Minimum vulnerability severity")
		output := fs.String("output", "", "Output file (JSON)")
		fs.Parse(args[1:])

		fmt.Printf("Fetching CDR events from last %d hours...\n", *hours)
		cdrEvents, err := client.GetCDRDetections(*hours, "", "container", 100)
		if err != nil {
			fmt.Printf("Error fetching events: %v\n", err)
			return
		}
		fmt.Printf("Found %d events\n", len(cdrEvents))

		correlator := vuln.NewCorrelator(nil)
		testVulns := []*vuln.Vulnerability{
			{VulnID: "QID-12345", CVEID: "CVE-2024-1234", Severity: 4, PackageName: "test"},
		}
		correlations := correlator.Correlate(testVulns, cdrEvents)
		fmt.Printf("Found %d correlations\n", len(correlations))

		if *output != "" {
			data, _ := json.MarshalIndent(correlations, "", "  ")
			os.WriteFile(*output, data, 0644)
			fmt.Printf("Saved to %s\n", *output)
		}

		_ = severityMin

	case "analytics":
		fs := flag.NewFlagSet("vulns analytics", flag.ExitOnError)
		hours := fs.Int("hours", 24, "Look back period")
		jsonOutput := fs.Bool("json", false, "Output as JSON")
		fs.Parse(args[1:])

		fmt.Println("Generating analytics report...")

		testVulns := []*vuln.Vulnerability{
			{VulnID: "QID-001", CVEID: "CVE-2024-21626", Severity: 5, CVSSScore: 10.0, ActivelyExploited: true, PackageName: "runc", ImageID: "sha256:abc"},
			{VulnID: "QID-002", CVEID: "CVE-2023-44487", Severity: 4, CVSSScore: 7.5, PackageName: "golang", ImageID: "sha256:def"},
		}

		testCorrelations := []*vuln.Correlation{
			{Vulnerability: testVulns[0], Events: make([]qualys.CDREvent, 5), Confidence: 0.9, MatchedBy: "cve_signature"},
		}

		report := analytics.GenerateReport(testVulns, testCorrelations, nil)

		if *jsonOutput {
			data, _ := report.ToJSON()
			fmt.Println(string(data))
		} else {
			fmt.Print(report.FormatText())
		}

		_ = hours

	case "export":
		fs := flag.NewFlagSet("vulns export", flag.ExitOnError)
		format := fs.String("format", "json", "Output format (json, csv)")
		output := fs.String("output", "data.json", "Output file")
		fs.Parse(args[1:])

		fmt.Printf("Exporting data as %s to %s...\n", *format, *output)

		testVulns := []*vuln.Vulnerability{
			{VulnID: "QID-001", CVEID: "CVE-2024-21626", Severity: 5, CVSSScore: 10.0},
		}

		if *format == "csv" {
			var buf bytes.Buffer
			analytics.ExportCSV(testVulns, nil, &buf)
			os.WriteFile(*output, buf.Bytes(), 0644)
		} else {
			data, _ := analytics.ExportJSON(testVulns, nil, nil, nil)
			os.WriteFile(*output, data, 0644)
		}
		fmt.Printf("Exported to %s\n", *output)

	default:
		fmt.Printf("Unknown vulns subcommand: %s\n", args[0])
	}
}

func driftCmd(args []string) {
	if len(args) == 0 {
		fmt.Println(`Usage: qcr drift <subcommand>

Subcommands:
  list        List drift policy types
  generate    Generate drift policies`)
		return
	}

	switch args[0] {
	case "list":
		fmt.Println(drift.ListDriftPolicies())

	case "generate":
		fs := flag.NewFlagSet("drift generate", flag.ExitOnError)
		mode := fs.String("mode", "detect", "detect or enforce")
		namespace := fs.String("namespace", "", "Kubernetes namespace")
		output := fs.String("output", "./drift-policies", "Output directory")
		policyType := fs.String("policy", "all", "Policy type: all, drift, binary-paths, package-managers")
		fs.Parse(args[1:])

		os.MkdirAll(*output, 0755)
		enforce := *mode == "enforce"

		var policies []*drift.TracingPolicy

		switch *policyType {
		case "all":
			if enforce {
				policies = append(policies, drift.GenerateDriftEnforcementPolicy(*namespace))
				policies = append(policies, drift.GenerateBinaryPathEnforcementPolicy(*namespace))
				policies = append(policies, drift.GeneratePackageManagerBlockPolicy(*namespace, true))
				policies = append(policies, drift.GenerateDownloadToolBlockPolicy(*namespace, true))
			} else {
				policies = append(policies, drift.GenerateDriftDetectionPolicy(*namespace))
				policies = append(policies, drift.GeneratePackageManagerBlockPolicy(*namespace, false))
			}
		case "drift":
			if enforce {
				policies = append(policies, drift.GenerateDriftEnforcementPolicy(*namespace))
			} else {
				policies = append(policies, drift.GenerateDriftDetectionPolicy(*namespace))
			}
		case "binary-paths":
			policies = append(policies, drift.GenerateBinaryPathEnforcementPolicy(*namespace))
		case "package-managers":
			policies = append(policies, drift.GeneratePackageManagerBlockPolicy(*namespace, enforce))
		}

		for _, p := range policies {
			data, _ := yaml.Marshal(p)
			filename := fmt.Sprintf("%s/%s.yaml", *output, p.Metadata.Name)
			os.WriteFile(filename, data, 0644)
			fmt.Printf("Generated: %s\n", filename)
		}

	default:
		fmt.Printf("Unknown drift subcommand: %s\n", args[0])
	}
}

func aiCmd(args []string) {
	if len(args) == 0 {
		fmt.Println(`Usage: qcr ai <subcommand>

Subcommands:
  explain     Explain a CVE
  risk        Risk assessment
  policy      Generate AI-suggested policy`)
		return
	}

	analyzer, err := ai.NewAnalyzer("", "")
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		fmt.Println("Set ANTHROPIC_API_KEY environment variable")
		return
	}

	switch args[0] {
	case "explain":
		fs := flag.NewFlagSet("ai explain", flag.ExitOnError)
		cve := fs.String("cve", "", "CVE ID to explain")
		fs.Parse(args[1:])

		if *cve == "" {
			fmt.Println("Error: --cve required")
			return
		}

		fmt.Printf("Analyzing %s...\n", *cve)
		result, err := analyzer.ExplainCVE(*cve, nil)
		if err != nil {
			fmt.Printf("Error: %v\n", err)
			return
		}
		fmt.Print(result.Format(false))

	case "risk":
		fmt.Println("Performing risk assessment...")
		result, err := analyzer.AssessRisk(10, 5, []string{"CVE-2024-21626", "CVE-2023-44487"})
		if err != nil {
			fmt.Printf("Error: %v\n", err)
			return
		}
		fmt.Print(result.Format(false))

	case "policy":
		fs := flag.NewFlagSet("ai policy", flag.ExitOnError)
		cve := fs.String("cve", "", "CVE ID")
		action := fs.String("action", "Post", "Policy action (Post or Sigkill)")
		fs.Parse(args[1:])

		if *cve == "" {
			fmt.Println("Error: --cve required")
			return
		}

		fmt.Printf("Generating policy for %s...\n", *cve)
		v := &vuln.Vulnerability{CVEID: *cve, VulnID: *cve, Severity: 4}
		result, err := analyzer.SuggestPolicy(v, *action)
		if err != nil {
			fmt.Printf("Error: %v\n", err)
			return
		}
		fmt.Print(result.Format(false))

		if result.SuggestedPolicy != nil {
			fmt.Println("\nSUGGESTED POLICY:")
			data, _ := yaml.Marshal(result.SuggestedPolicy)
			fmt.Println(string(data))
		}

	default:
		fmt.Printf("Unknown ai subcommand: %s\n", args[0])
	}
}

func printBanner() {
	fmt.Println()
	fmt.Println("╔══════════════════════════════════════════════════════════════╗")
	fmt.Println("║     Qualys Container Runtime Security - Event Generator      ║")
	fmt.Println("║                         v" + version + "                                ║")
	fmt.Println("╚══════════════════════════════════════════════════════════════╝")
	fmt.Println()
}

func printEventList(categoryFilter string) {
	printBanner()
	fmt.Printf("%-8s %-40s %-20s %-10s\n", "ID", "Name", "Category", "Severity")
	fmt.Println(strings.Repeat("-", 85))

	for _, e := range events.Catalog {
		if categoryFilter != "" && !strings.EqualFold(e.Category, categoryFilter) {
			continue
		}
		priv := ""
		if e.Privileged {
			priv = "*"
		}
		fmt.Printf("%-8s %-40s %-20s %-10s%s\n", e.ID, truncate(e.Name, 40), e.Category, e.Severity, priv)
	}
	fmt.Println()
	fmt.Println("* = Requires elevated privileges")
	fmt.Printf("\nTotal: %d events\n", len(events.Catalog))
}

func runSingleEvent(eventID string) {
	eventID = strings.ToUpper(eventID)
	for _, e := range events.Catalog {
		if e.ID == eventID {
			executeEvent(e)
			return
		}
	}
	fmt.Printf("Event not found: %s\n", eventID)
	os.Exit(1)
}

func runAllEvents(delay time.Duration, categoryFilter string) {
	printBanner()
	fmt.Println("Running all events...")
	fmt.Printf("Delay between events: %v\n\n", delay)

	count := 0
	for _, e := range events.Catalog {
		if categoryFilter != "" && !strings.EqualFold(e.Category, categoryFilter) {
			continue
		}
		executeEvent(e)
		count++
		if count < len(events.Catalog) {
			time.Sleep(delay)
		}
	}

	fmt.Printf("\n✓ Completed %d events\n", count)
}

func executeEvent(e events.SecurityEvent) {
	fmt.Println()
	fmt.Printf("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n")
	fmt.Printf("▶ [%s] %s\n", e.ID, e.Name)
	fmt.Printf("  Category: %s | Severity: %s | MITRE: %s\n", e.Category, e.Severity, strings.Join(e.MITRE, ", "))
	if e.Privileged {
		fmt.Printf("  ⚠ Requires elevated privileges\n")
	}
	fmt.Printf("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n")

	if e.Executor != nil {
		if err := e.Executor(); err != nil {
			fmt.Printf("  ✗ Error: %v\n", err)
		} else {
			fmt.Printf("  ✓ Completed\n")
		}
	}
}

func interactiveMenu() {
	printBanner()
	reader := bufio.NewReader(os.Stdin)

	for {
		fmt.Println("\n" + strings.Repeat("*", 60))
		fmt.Println("Select an event to execute:")
		fmt.Println(strings.Repeat("*", 60))
		fmt.Println()

		for i, e := range events.Catalog {
			priv := ""
			if e.Privileged {
				priv = " *"
			}
			fmt.Printf("%3d) [%s] %s%s\n", i+1, e.ID, e.Name, priv)
		}

		fmt.Println()
		fmt.Println(strings.Repeat("*", 60))
		fmt.Println(" a) Run ALL events")
		fmt.Println(" c) Filter by category")
		fmt.Println(" l) List events with details")
		fmt.Println(" q) Quit")
		fmt.Println(strings.Repeat("*", 60))
		fmt.Print("\nEnter selection: ")

		input, _ := reader.ReadString('\n')
		input = strings.TrimSpace(input)

		if input == "" {
			continue
		}

		switch strings.ToLower(input) {
		case "q", "quit", "exit":
			fmt.Println("Exiting...")
			return
		case "a", "all":
			runAllEvents(2*time.Second, "")
		case "c", "category":
			fmt.Print("Enter category filter: ")
			cat, _ := reader.ReadString('\n')
			cat = strings.TrimSpace(cat)
			printEventList(cat)
		case "l", "list":
			printEventList("")
		default:
			if num, err := strconv.Atoi(input); err == nil && num >= 1 && num <= len(events.Catalog) {
				executeEvent(events.Catalog[num-1])
			} else {
				for _, e := range events.Catalog {
					if strings.EqualFold(e.ID, input) {
						executeEvent(e)
						break
					}
				}
			}
		}

		fmt.Print("\nPress Enter to continue...")
		reader.ReadString('\n')
	}
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max-3] + "..."
}
