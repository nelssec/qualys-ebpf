package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"qualys-policy-operator/pkg/cdr"
	"qualys-policy-operator/pkg/network"
	"qualys-policy-operator/pkg/policy"
	"qualys-policy-operator/pkg/reputation"
	"sigs.k8s.io/yaml"
)

type Config struct {
	Username       string
	Password       string
	GatewayURL     string
	Platform       string
	LookbackHours  int
	Action         string
	OutputDir      string
	ApplyToCluster bool
	RunOnce        bool
	Interval       time.Duration

	// Threat intel options
	EnableThreatIntel bool
	AbuseIPDBKey      string
	ReputationThreshold int
}

func main() {
	cfg := parseFlags()

	if cfg.Username == "" {
		cfg.Username = os.Getenv("QUALYS_USERNAME")
	}
	if cfg.Password == "" {
		cfg.Password = os.Getenv("QUALYS_PASSWORD")
	}
	if cfg.GatewayURL == "" {
		cfg.GatewayURL = os.Getenv("QUALYS_GATEWAY_URL")
	}
	if cfg.AbuseIPDBKey == "" {
		cfg.AbuseIPDBKey = os.Getenv("ABUSEIPDB_API_KEY")
	}

	if cfg.Username == "" || cfg.Password == "" {
		fmt.Fprintln(os.Stderr, "Error: QUALYS_USERNAME and QUALYS_PASSWORD required")
		fmt.Fprintln(os.Stderr, "")
		fmt.Fprintln(os.Stderr, "Environment variables:")
		fmt.Fprintln(os.Stderr, "  QUALYS_USERNAME      - Qualys API username")
		fmt.Fprintln(os.Stderr, "  QUALYS_PASSWORD      - Qualys API password")
		fmt.Fprintln(os.Stderr, "  QUALYS_GATEWAY_URL   - Gateway URL (e.g., gateway.qg2.apps.qualys.com)")
		fmt.Fprintln(os.Stderr, "  ABUSEIPDB_API_KEY    - Optional: AbuseIPDB API key for reputation checks")
		os.Exit(1)
	}

	if cfg.Platform != "" && cfg.GatewayURL == "" {
		cfg.GatewayURL = cdr.GetGatewayURL(cfg.Platform)
	}
	if cfg.GatewayURL == "" {
		cfg.GatewayURL = "gateway.qg2.apps.qualys.com"
	}

	client := cdr.NewClient(cfg.Username, cfg.Password, cfg.GatewayURL)

	// Initialize reputation checker if enabled
	var repChecker *reputation.ReputationChecker
	if cfg.EnableThreatIntel {
		repChecker = reputation.NewReputationChecker(cfg.AbuseIPDBKey)
		fmt.Println("Loading threat intelligence feeds...")
		if err := repChecker.LoadThreatFeeds(context.Background()); err != nil {
			fmt.Fprintf(os.Stderr, "Warning: some threat feeds failed: %v\n", err)
		}
		stats := repChecker.Stats()
		fmt.Printf("Loaded %d known bad IPs from threat feeds\n", stats["total_known_bad"])
	}

	if cfg.RunOnce {
		if err := runOnce(context.Background(), client, repChecker, cfg); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
		return
	}

	fmt.Printf("Starting policy controller (interval: %v)\n", cfg.Interval)
	ticker := time.NewTicker(cfg.Interval)
	defer ticker.Stop()

	if err := runOnce(context.Background(), client, repChecker, cfg); err != nil {
		fmt.Fprintf(os.Stderr, "Warning: %v\n", err)
	}

	for range ticker.C {
		if err := runOnce(context.Background(), client, repChecker, cfg); err != nil {
			fmt.Fprintf(os.Stderr, "Warning: %v\n", err)
		}
	}
}

func parseFlags() Config {
	cfg := Config{}

	flag.StringVar(&cfg.Platform, "platform", "", "Qualys platform (US1, US2, CA1, EU1, etc.)")
	flag.StringVar(&cfg.GatewayURL, "gateway", "", "Qualys gateway URL")
	flag.IntVar(&cfg.LookbackHours, "hours", 24, "Lookback period in hours")
	flag.StringVar(&cfg.Action, "action", "Post", "Policy action: Post (audit) or Sigkill (block)")
	flag.StringVar(&cfg.OutputDir, "output", "./policies", "Output directory")
	flag.BoolVar(&cfg.ApplyToCluster, "apply", false, "Apply policies to cluster")
	flag.BoolVar(&cfg.RunOnce, "once", false, "Run once and exit")
	flag.DurationVar(&cfg.Interval, "interval", 1*time.Hour, "Update interval")
	flag.BoolVar(&cfg.EnableThreatIntel, "threat-intel", false, "Enable threat intel feed integration")
	flag.IntVar(&cfg.ReputationThreshold, "reputation-threshold", 50, "Block IPs with reputation score >= threshold")

	flag.Parse()
	return cfg
}

func runOnce(ctx context.Context, client *cdr.Client, repChecker *reputation.ReputationChecker, cfg Config) error {
	fmt.Printf("\n=== Policy Generation Run: %s ===\n", time.Now().Format(time.RFC3339))

	// 1. Fetch CDR events
	fmt.Printf("\nFetching CDR events (last %d hours)...\n", cfg.LookbackHours)
	events, err := client.GetDetections(ctx, cfg.LookbackHours)
	if err != nil {
		return fmt.Errorf("failed to fetch events: %w", err)
	}
	fmt.Printf("Found %d events\n", len(events))

	if err := os.MkdirAll(cfg.OutputDir, 0755); err != nil {
		return fmt.Errorf("failed to create output dir: %w", err)
	}

	// 2. Generate behavior-based policies from CDR events
	if len(events) > 0 {
		categories := make(map[string]int)
		for _, e := range events {
			categories[e.ThreatCategory]++
		}
		fmt.Println("\nEvent categories:")
		for cat, count := range categories {
			fmt.Printf("  %s: %d\n", cat, count)
		}

		fmt.Println("\nGenerating behavior-based policies...")
		generator := policy.NewGenerator(cfg.Action)
		policies := generator.FromEvents(events)
		fmt.Printf("Generated %d behavior policies\n", len(policies))

		for _, p := range policies {
			if err := writePolicy(cfg.OutputDir, p.Name, p); err != nil {
				fmt.Fprintf(os.Stderr, "Warning: %v\n", err)
			}
		}

		// 3. Extract network IOCs from events
		fmt.Println("\nExtracting network indicators from events...")
		blocklist := network.NewNetworkBlocklist()
		blocklist.ExtractFromEvents(events)
		stats := blocklist.Stats()
		fmt.Printf("Extracted: %d IPs, %d domains, %d ports\n",
			stats["ips"], stats["domains"], stats["ports"])

		if stats["ips"] > 0 || stats["ports"] > 0 {
			// Generate Tetragon policy for extracted IOCs
			tetragonPolicy := blocklist.GenerateTetragonPolicy(
				fmt.Sprintf("cdr-dynamic-blocklist-%s", time.Now().Format("20060102")),
				cfg.Action,
			)
			if err := writePolicy(cfg.OutputDir, "cdr-dynamic-blocklist", tetragonPolicy); err != nil {
				fmt.Fprintf(os.Stderr, "Warning: %v\n", err)
			}

			// Generate Cilium network policy
			ciliumPolicy := blocklist.GenerateCiliumPolicy(
				"cdr-network-blocklist",
				"default",
			)
			if err := writePolicy(cfg.OutputDir, "cilium-cdr-blocklist", ciliumPolicy); err != nil {
				fmt.Fprintf(os.Stderr, "Warning: %v\n", err)
			}
		}
	}

	// 4. Generate threat intel blocklist if enabled
	if repChecker != nil {
		fmt.Println("\nGenerating threat intel blocklist...")
		repStats := repChecker.Stats()
		fmt.Printf("Known bad IPs: %d\n", repStats["total_known_bad"])

		threatIntelPolicy := repChecker.GenerateBlocklistPolicy(
			fmt.Sprintf("threat-intel-blocklist-%s", time.Now().Format("20060102")),
			cfg.Action,
		)
		if err := writePolicy(cfg.OutputDir, "threat-intel-blocklist", threatIntelPolicy); err != nil {
			fmt.Fprintf(os.Stderr, "Warning: %v\n", err)
		}

		// Check extracted IPs against reputation
		if len(events) > 0 {
			blocklist := network.NewNetworkBlocklist()
			blocklist.ExtractFromEvents(events)

			var ipsToCheck []string
			for ip := range blocklist.Stats() {
				ipsToCheck = append(ipsToCheck, ip)
			}

			if len(ipsToCheck) > 0 {
				fmt.Printf("\nChecking %d IPs against reputation database...\n", len(ipsToCheck))
				badIPs := repChecker.CheckBatch(ctx, ipsToCheck, cfg.ReputationThreshold)
				fmt.Printf("Found %d IPs with bad reputation (score >= %d)\n",
					len(badIPs), cfg.ReputationThreshold)
			}
		}
	}

	// 5. Apply to cluster if requested
	if cfg.ApplyToCluster {
		fmt.Println("\nApplying policies to cluster...")
		fmt.Println("  kubectl apply -f", cfg.OutputDir)
	}

	fmt.Println("\nDone.")
	return nil
}

func writePolicy(dir, name string, policy interface{}) error {
	data, err := yaml.Marshal(policy)
	if err != nil {
		return fmt.Errorf("failed to marshal %s: %w", name, err)
	}

	filename := filepath.Join(dir, name+".yaml")
	if err := os.WriteFile(filename, data, 0644); err != nil {
		return fmt.Errorf("failed to write %s: %w", filename, err)
	}
	fmt.Printf("  Created: %s\n", filename)
	return nil
}
