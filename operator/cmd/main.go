package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/qualys/qualys-policy-operator/pkg/cdr"
	"github.com/qualys/qualys-policy-operator/pkg/policy"
	"sigs.k8s.io/yaml"
)

type Config struct {
	// Qualys credentials (from env or secret)
	Username   string
	Password   string
	GatewayURL string
	Platform   string

	// Policy generation options
	LookbackHours int
	Action        string // "Post" (audit) or "Sigkill" (block)
	OutputDir     string
	ApplyToCluster bool

	// Runtime options
	RunOnce    bool
	Interval   time.Duration
}

func main() {
	cfg := parseFlags()

	// Load credentials from environment
	if cfg.Username == "" {
		cfg.Username = os.Getenv("QUALYS_USERNAME")
	}
	if cfg.Password == "" {
		cfg.Password = os.Getenv("QUALYS_PASSWORD")
	}
	if cfg.GatewayURL == "" {
		cfg.GatewayURL = os.Getenv("QUALYS_GATEWAY_URL")
	}

	if cfg.Username == "" || cfg.Password == "" {
		fmt.Fprintln(os.Stderr, "Error: QUALYS_USERNAME and QUALYS_PASSWORD required")
		fmt.Fprintln(os.Stderr, "")
		fmt.Fprintln(os.Stderr, "Set via environment variables or Kubernetes Secret:")
		fmt.Fprintln(os.Stderr, "  export QUALYS_USERNAME=your_username")
		fmt.Fprintln(os.Stderr, "  export QUALYS_PASSWORD=your_password")
		fmt.Fprintln(os.Stderr, "  export QUALYS_GATEWAY_URL=gateway.qg2.apps.qualys.com")
		os.Exit(1)
	}

	// Resolve platform to gateway URL if provided
	if cfg.Platform != "" && cfg.GatewayURL == "" {
		cfg.GatewayURL = cdr.GetGatewayURL(cfg.Platform)
	}
	if cfg.GatewayURL == "" {
		cfg.GatewayURL = "gateway.qg2.apps.qualys.com" // Default to US2
	}

	client := cdr.NewClient(cfg.Username, cfg.Password, cfg.GatewayURL)

	if cfg.RunOnce {
		if err := runOnce(context.Background(), client, cfg); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
		return
	}

	// Run as controller with interval
	fmt.Printf("Starting policy controller (interval: %v)\n", cfg.Interval)
	ticker := time.NewTicker(cfg.Interval)
	defer ticker.Stop()

	// Run immediately, then on interval
	if err := runOnce(context.Background(), client, cfg); err != nil {
		fmt.Fprintf(os.Stderr, "Warning: %v\n", err)
	}

	for range ticker.C {
		if err := runOnce(context.Background(), client, cfg); err != nil {
			fmt.Fprintf(os.Stderr, "Warning: %v\n", err)
		}
	}
}

func parseFlags() Config {
	cfg := Config{}

	flag.StringVar(&cfg.Platform, "platform", "", "Qualys platform (US1, US2, CA1, EU1, etc.)")
	flag.StringVar(&cfg.GatewayURL, "gateway", "", "Qualys gateway URL (overrides platform)")
	flag.IntVar(&cfg.LookbackHours, "hours", 24, "Lookback period in hours")
	flag.StringVar(&cfg.Action, "action", "Post", "Policy action: Post (audit) or Sigkill (block)")
	flag.StringVar(&cfg.OutputDir, "output", "./policies", "Output directory for generated policies")
	flag.BoolVar(&cfg.ApplyToCluster, "apply", false, "Apply policies directly to cluster")
	flag.BoolVar(&cfg.RunOnce, "once", false, "Run once and exit (for CronJob)")
	flag.DurationVar(&cfg.Interval, "interval", 1*time.Hour, "Interval between policy updates")

	flag.Parse()
	return cfg
}

func runOnce(ctx context.Context, client *cdr.Client, cfg Config) error {
	fmt.Printf("\n=== Fetching CDR events (last %d hours) ===\n", cfg.LookbackHours)

	events, err := client.GetDetections(ctx, cfg.LookbackHours)
	if err != nil {
		return fmt.Errorf("failed to fetch events: %w", err)
	}

	fmt.Printf("Found %d events\n", len(events))
	if len(events) == 0 {
		fmt.Println("No events to process")
		return nil
	}

	// Print event summary
	categories := make(map[string]int)
	for _, e := range events {
		categories[e.ThreatCategory]++
	}
	fmt.Println("\nEvent categories:")
	for cat, count := range categories {
		fmt.Printf("  %s: %d\n", cat, count)
	}

	// Generate policies
	fmt.Println("\nGenerating policies...")
	generator := policy.NewGenerator(cfg.Action)
	policies := generator.FromEvents(events)

	fmt.Printf("Generated %d policies\n", len(policies))

	// Output policies
	if err := os.MkdirAll(cfg.OutputDir, 0755); err != nil {
		return fmt.Errorf("failed to create output dir: %w", err)
	}

	for _, p := range policies {
		data, err := yaml.Marshal(p)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Warning: failed to marshal %s: %v\n", p.Name, err)
			continue
		}

		filename := filepath.Join(cfg.OutputDir, p.Name+".yaml")
		if err := os.WriteFile(filename, data, 0644); err != nil {
			fmt.Fprintf(os.Stderr, "Warning: failed to write %s: %v\n", filename, err)
			continue
		}
		fmt.Printf("  Created: %s\n", filename)
	}

	// Apply to cluster if requested
	if cfg.ApplyToCluster {
		fmt.Println("\nApplying policies to cluster...")
		// Implementation would use client-go to apply TracingPolicies
		fmt.Println("  (kubectl apply -f would be called here)")
	}

	return nil
}
