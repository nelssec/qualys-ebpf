package main

import (
	"bufio"
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/qualys/eventgen/pkg/events"
)

var (
	version   = "1.0.0"
	buildTime = "dev"
)

func main() {
	runAll := flag.Bool("all", false, "Run all events sequentially")
	runEvent := flag.String("event", "", "Run specific event by ID (e.g., QCR001)")
	listEvents := flag.Bool("list", false, "List all available events")
	category := flag.String("category", "", "Filter by category")
	delay := flag.Duration("delay", 2*time.Second, "Delay between events when running all")
	showVersion := flag.Bool("version", false, "Show version")
	interactive := flag.Bool("i", false, "Interactive menu mode")

	flag.Parse()

	if *showVersion {
		fmt.Printf("Qualys CRS Event Generator v%s (%s)\n", version, buildTime)
		return
	}

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

	if *interactive || flag.NArg() == 0 {
		interactiveMenu()
		return
	}

	flag.Usage()
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
