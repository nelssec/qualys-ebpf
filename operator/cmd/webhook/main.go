package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"qualys-policy-operator/pkg/reputation"
	"qualys-policy-operator/pkg/webhook"
)

func main() {
	var (
		addr           = flag.String("addr", ":8080", "Webhook server address")
		webhookSecret  = flag.String("secret", "", "Webhook signature secret")
		action         = flag.String("action", "Sigkill", "Policy action: Post or Sigkill")
		outputDir      = flag.String("output", "/policies", "Output directory for policies")
		applyToCluster = flag.Bool("apply", true, "Apply policies to cluster")
		enableThreatIntel = flag.Bool("threat-intel", false, "Enable threat intel checking")
	)
	flag.Parse()

	// Load from environment
	if *webhookSecret == "" {
		*webhookSecret = os.Getenv("WEBHOOK_SECRET")
	}
	abuseIPDBKey := os.Getenv("ABUSEIPDB_API_KEY")

	// Initialize reputation checker if enabled
	var repChecker *reputation.ReputationChecker
	if *enableThreatIntel {
		repChecker = reputation.NewReputationChecker(abuseIPDBKey)
		fmt.Println("Loading threat intelligence feeds...")
		if err := repChecker.LoadThreatFeeds(context.Background()); err != nil {
			fmt.Fprintf(os.Stderr, "Warning: %v\n", err)
		}
		stats := repChecker.Stats()
		fmt.Printf("Loaded %d known bad IPs\n", stats["total_known_bad"])
	}

	// Create webhook server
	server := webhook.NewServer(
		*addr,
		*webhookSecret,
		*action,
		*outputDir,
		*applyToCluster,
		repChecker,
	)

	// Handle shutdown
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		fmt.Println("\nShutting down...")
		cancel()
	}()

	// Start server
	if err := server.Start(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "Server error: %v\n", err)
		os.Exit(1)
	}
}
