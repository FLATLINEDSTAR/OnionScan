// Command onionsec is the CLI entry point.
//
// Usage:
//
//	onionsec scan <target.onion> [--json out.json] [--md out.md]
//	onionsec report <target.onion>          (re-render the latest saved scan)
//	onionsec monitor <target.onion>         (scan + diff against last run)
//	onionsec version
//
// See docs/ROADMAP.md for the CLI-first -> API -> dashboard phasing, and
// README.md for the authorized-use requirement before running this against
// any target.
package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/AryanXCode646/OnionScan/internal/config"
	"github.com/AryanXCode646/OnionScan/internal/diff"
	"github.com/AryanXCode646/OnionScan/internal/graph"
	"github.com/AryanXCode646/OnionScan/internal/model"
	"github.com/AryanXCode646/OnionScan/internal/report"
	"github.com/AryanXCode646/OnionScan/internal/scan"
	"github.com/AryanXCode646/OnionScan/internal/storage"
	"github.com/AryanXCode646/OnionScan/internal/tor"
)

const version = "0.1.0-dev"

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(1)
	}

	switch os.Args[1] {
	case "scan":
		cmdScan(os.Args[2:])
	case "report":
		cmdReport(os.Args[2:])
	case "graph":
		cmdGraph(os.Args[2:])
	case "monitor":
		cmdMonitor(os.Args[2:])
	case "diff":
		cmdDiff(os.Args[2:])
	case "version":
		fmt.Println("onionsec " + version)
	default:
		usage()
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, `onionsec - security observability for Tor onion services

Only scan targets you own or are authorized to test.

Usage:
  onionsec scan <target.onion> [--config <path>] [--json <out.json>] [--md <out.md>]
  onionsec report <target.onion>
  onionsec graph <target.onion> [--dot] [--out <path>]
  onionsec monitor <target.onion> [--config <path>] [--json <out.json>] [--md <out.md>]
  onionsec diff <target.onion> <scan-id-1> <scan-id-2> [--json <out.json>] [--md <out.md>]
  onionsec version`)
}

func cmdScan(args []string) {
	var targetOnion string
	var configPath string
	var explicitConfig bool
	var jsonPath string
	var mdPath string

	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg == "--config" || arg == "-config" {
			if i+1 < len(args) {
				configPath = args[i+1]
				explicitConfig = true
				i++
			} else {
				fmt.Fprintln(os.Stderr, "error: --config requires a path argument")
				os.Exit(1)
			}
		} else if strings.HasPrefix(arg, "--config=") || strings.HasPrefix(arg, "-config=") {
			parts := strings.SplitN(arg, "=", 2)
			configPath = parts[1]
			explicitConfig = true
		} else if arg == "--json" || arg == "-json" {
			if i+1 < len(args) {
				jsonPath = args[i+1]
				i++
			} else {
				fmt.Fprintln(os.Stderr, "error: --json requires a path argument")
				os.Exit(1)
			}
		} else if strings.HasPrefix(arg, "--json=") || strings.HasPrefix(arg, "-json=") {
			parts := strings.SplitN(arg, "=", 2)
			jsonPath = parts[1]
		} else if arg == "--md" || arg == "-md" {
			if i+1 < len(args) {
				mdPath = args[i+1]
				i++
			} else {
				fmt.Fprintln(os.Stderr, "error: --md requires a path argument")
				os.Exit(1)
			}
		} else if strings.HasPrefix(arg, "--md=") || strings.HasPrefix(arg, "-md=") {
			parts := strings.SplitN(arg, "=", 2)
			mdPath = parts[1]
		} else if targetOnion == "" && !strings.HasPrefix(arg, "-") {
			targetOnion = arg
		}
	}

	if targetOnion == "" {
		fmt.Fprintln(os.Stderr, "usage: onionsec scan <target.onion> [--config <path>] [--json <out.json>] [--md <out.md>]")
		os.Exit(1)
	}

	cfg, err := config.LoadFile(configPath, explicitConfig)
	if err != nil {
		fmt.Fprintln(os.Stderr, "config error:", err)
		os.Exit(1)
	}

	target := model.Target{Onion: targetOnion, CreatedAt: time.Now()}

	client := tor.NewHTTPClient(cfg.SOCKSAddr, 30*time.Second)
	store, err := storage.New(defaultDataDir())
	if err != nil {
		fmt.Fprintln(os.Stderr, "storage error:", err)
		os.Exit(1)
	}
	defer store.Close()

	ctx, cancel := context.WithTimeout(context.Background(), cfg.Limits.TotalBudget+time.Minute)
	defer cancel()

	result, err := scan.Run(ctx, client, store, target, cfg.Limits)
	if err != nil {
		fmt.Fprintln(os.Stderr, "scan failed:", err)
		os.Exit(1)
	}

	printSummary(result)
	if err := report.WriteMarkdown(os.Stdout, result); err != nil {
		fmt.Fprintln(os.Stderr, "render report:", err)
		os.Exit(1)
	}

	if jsonPath != "" {
		f, err := os.Create(jsonPath)
		if err != nil {
			fmt.Fprintln(os.Stderr, "create json output file:", err)
			os.Exit(1)
		}
		defer f.Close()
		if err := report.WriteJSON(f, result); err != nil {
			fmt.Fprintln(os.Stderr, "write json report:", err)
			os.Exit(1)
		}
	}

	if mdPath != "" {
		f, err := os.Create(mdPath)
		if err != nil {
			fmt.Fprintln(os.Stderr, "create markdown output file:", err)
			os.Exit(1)
		}
		defer f.Close()
		if err := report.WriteMarkdown(f, result); err != nil {
			fmt.Fprintln(os.Stderr, "write markdown report:", err)
			os.Exit(1)
		}
	}
}

func cmdReport(args []string) {
	if len(args) < 1 {
		fmt.Fprintln(os.Stderr, "usage: onionsec report <target.onion>")
		os.Exit(1)
	}
	store, err := storage.New(defaultDataDir())
	if err != nil {
		fmt.Fprintln(os.Stderr, "storage error:", err)
		os.Exit(1)
	}
	defer store.Close()
	result, ok, err := store.Latest(args[0])
	if err != nil {
		fmt.Fprintln(os.Stderr, "read history:", err)
		os.Exit(1)
	}
	if !ok {
		fmt.Fprintln(os.Stderr, "no saved scans for", args[0], "-- run `onionsec scan` first")
		os.Exit(1)
	}
	_ = report.WriteMarkdown(os.Stdout, result)
}

func cmdGraph(args []string) {
	var targetOnion string
	var dotFormat bool
	var outPath string

	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg == "--dot" || arg == "-dot" || arg == "--format=dot" || arg == "-format=dot" {
			dotFormat = true
		} else if arg == "--out" || arg == "-out" {
			if i+1 < len(args) {
				outPath = args[i+1]
				i++
			} else {
				fmt.Fprintln(os.Stderr, "error: --out requires a path argument")
				os.Exit(1)
			}
		} else if strings.HasPrefix(arg, "--out=") || strings.HasPrefix(arg, "-out=") {
			parts := strings.SplitN(arg, "=", 2)
			outPath = parts[1]
		} else if targetOnion == "" && !strings.HasPrefix(arg, "-") {
			targetOnion = arg
		}
	}

	if targetOnion == "" {
		fmt.Fprintln(os.Stderr, "usage: onionsec graph <target.onion> [--dot] [--out <path>]")
		os.Exit(1)
	}

	store, err := storage.New(defaultDataDir())
	if err != nil {
		fmt.Fprintln(os.Stderr, "storage error:", err)
		os.Exit(1)
	}
	defer store.Close()
	g, err := graph.BuildGraph(targetOnion, store)
	if err != nil {
		fmt.Fprintln(os.Stderr, "graph error:", err)
		os.Exit(1)
	}

	w := os.Stdout
	if outPath != "" {
		f, err := os.Create(outPath)
		if err != nil {
			fmt.Fprintln(os.Stderr, "create output file:", err)
			os.Exit(1)
		}
		defer f.Close()
		w = f
	}

	if dotFormat {
		if err := graph.RenderDOT(w, g); err != nil {
			fmt.Fprintln(os.Stderr, "render dot error:", err)
			os.Exit(1)
		}
	} else {
		if err := graph.RenderText(w, g); err != nil {
			fmt.Fprintln(os.Stderr, "render text error:", err)
			os.Exit(1)
		}
	}
}

func cmdMonitor(args []string) {
	var targetOnion string
	var configPath string
	var explicitConfig bool
	var jsonPath string
	var mdPath string

	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg == "--config" || arg == "-config" {
			if i+1 < len(args) {
				configPath = args[i+1]
				explicitConfig = true
				i++
			} else {
				fmt.Fprintln(os.Stderr, "error: --config requires a path argument")
				os.Exit(1)
			}
		} else if strings.HasPrefix(arg, "--config=") || strings.HasPrefix(arg, "-config=") {
			parts := strings.SplitN(arg, "=", 2)
			configPath = parts[1]
			explicitConfig = true
		} else if arg == "--json" || arg == "-json" {
			if i+1 < len(args) {
				jsonPath = args[i+1]
				i++
			} else {
				fmt.Fprintln(os.Stderr, "error: --json requires a path argument")
				os.Exit(1)
			}
		} else if strings.HasPrefix(arg, "--json=") || strings.HasPrefix(arg, "-json=") {
			parts := strings.SplitN(arg, "=", 2)
			jsonPath = parts[1]
		} else if arg == "--md" || arg == "-md" {
			if i+1 < len(args) {
				mdPath = args[i+1]
				i++
			} else {
				fmt.Fprintln(os.Stderr, "error: --md requires a path argument")
				os.Exit(1)
			}
		} else if strings.HasPrefix(arg, "--md=") || strings.HasPrefix(arg, "-md=") {
			parts := strings.SplitN(arg, "=", 2)
			mdPath = parts[1]
		} else if targetOnion == "" && !strings.HasPrefix(arg, "-") {
			targetOnion = arg
		}
	}

	if targetOnion == "" {
		fmt.Fprintln(os.Stderr, "usage: onionsec monitor <target.onion> [--config <path>] [--json <out.json>] [--md <out.md>]")
		os.Exit(1)
	}

	cfg, err := config.LoadFile(configPath, explicitConfig)
	if err != nil {
		fmt.Fprintln(os.Stderr, "config error:", err)
		os.Exit(1)
	}

	target := model.Target{Onion: targetOnion, CreatedAt: time.Now()}
	store, err := storage.New(defaultDataDir())
	if err != nil {
		fmt.Fprintln(os.Stderr, "storage error:", err)
		os.Exit(1)
	}
	defer store.Close()

	// 1. Retrieve the latest prior scan before running the new scan
	oldScan, hasOld, err := store.Latest(targetOnion)
	if err != nil {
		fmt.Fprintln(os.Stderr, "warning: unable to read previous scan history:", err)
		hasOld = false
	}

	// 2. Run the new scan
	client := tor.NewHTTPClient(cfg.SOCKSAddr, 30*time.Second)
	ctx, cancel := context.WithTimeout(context.Background(), cfg.Limits.TotalBudget+time.Minute)
	defer cancel()

	newScan, err := scan.Run(ctx, client, store, target, cfg.Limits)
	if err != nil {
		fmt.Fprintln(os.Stderr, "scan failed:", err)
		os.Exit(1)
	}

	// 3. Compute diff between previous scan and new scan
	d := diff.Diff(oldScan, hasOld, newScan)

	// 4. Render monitor diff report to stdout
	if err := diff.RenderText(os.Stdout, d); err != nil {
		fmt.Fprintln(os.Stderr, "render monitor report:", err)
		os.Exit(1)
	}

	// 5. Output JSON if requested
	if jsonPath != "" {
		f, err := os.Create(jsonPath)
		if err != nil {
			fmt.Fprintln(os.Stderr, "create json output file:", err)
			os.Exit(1)
		}
		defer f.Close()
		if err := diff.RenderJSON(f, d); err != nil {
			fmt.Fprintln(os.Stderr, "write json report:", err)
			os.Exit(1)
		}
	}

	// 6. Output Markdown if requested
	if mdPath != "" {
		f, err := os.Create(mdPath)
		if err != nil {
			fmt.Fprintln(os.Stderr, "create markdown output file:", err)
			os.Exit(1)
		}
		defer f.Close()
		if err := diff.RenderMarkdown(f, d); err != nil {
			fmt.Fprintln(os.Stderr, "write markdown report:", err)
			os.Exit(1)
		}
	}
}

func cmdDiff(args []string) {
	if err := runDiff(args, os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func runDiff(args []string, stdout io.Writer) error {
	var positional []string
	var jsonPath string
	var mdPath string

	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg == "--json" || arg == "-json" {
			if i+1 < len(args) {
				jsonPath = args[i+1]
				i++
			} else {
				return fmt.Errorf("error: --json requires a path argument")
			}
		} else if strings.HasPrefix(arg, "--json=") || strings.HasPrefix(arg, "-json=") {
			parts := strings.SplitN(arg, "=", 2)
			jsonPath = parts[1]
		} else if arg == "--md" || arg == "-md" {
			if i+1 < len(args) {
				mdPath = args[i+1]
				i++
			} else {
				return fmt.Errorf("error: --md requires a path argument")
			}
		} else if strings.HasPrefix(arg, "--md=") || strings.HasPrefix(arg, "-md=") {
			parts := strings.SplitN(arg, "=", 2)
			mdPath = parts[1]
		} else if !strings.HasPrefix(arg, "-") {
			positional = append(positional, arg)
		}
	}

	if len(positional) < 3 {
		return fmt.Errorf("usage: onionsec diff <target.onion> <scan-id-1> <scan-id-2> [--json <out.json>] [--md <out.md>]")
	}

	targetOnion := positional[0]
	scanID1 := positional[1]
	scanID2 := positional[2]

	store, err := storage.New(defaultDataDir())
	if err != nil {
		return fmt.Errorf("storage error: %w", err)
	}
	defer store.Close()

	scan1, ok1, err := store.GetScan(targetOnion, scanID1)
	if err != nil {
		return fmt.Errorf("error reading scan %q: %w", scanID1, err)
	}
	if !ok1 {
		return fmt.Errorf("scan %q not found for target %q", scanID1, targetOnion)
	}

	scan2, ok2, err := store.GetScan(targetOnion, scanID2)
	if err != nil {
		return fmt.Errorf("error reading scan %q: %w", scanID2, err)
	}
	if !ok2 {
		return fmt.Errorf("scan %q not found for target %q", scanID2, targetOnion)
	}

	d := diff.Diff(scan1, true, scan2)

	if err := diff.RenderText(stdout, d); err != nil {
		return fmt.Errorf("render diff report: %w", err)
	}

	if jsonPath != "" {
		f, err := os.Create(jsonPath)
		if err != nil {
			return fmt.Errorf("create json output file: %w", err)
		}
		defer f.Close()
		if err := diff.RenderJSON(f, d); err != nil {
			return fmt.Errorf("write json report: %w", err)
		}
	}

	if mdPath != "" {
		f, err := os.Create(mdPath)
		if err != nil {
			return fmt.Errorf("create markdown output file: %w", err)
		}
		defer f.Close()
		if err := diff.RenderMarkdown(f, d); err != nil {
			return fmt.Errorf("write markdown report: %w", err)
		}
	}

	return nil
}

func printSummary(r model.ScanResult) {
	fmt.Printf("Target:     %s\n", r.Target.Onion)
	fmt.Printf("Pages seen: %d\n", r.PagesSeen)
	fmt.Printf("Risk score: %d / 100\n\n", r.RiskScore)
}

func defaultDataDir() string {
	if env := os.Getenv("ONIONSEC_DATA_DIR"); env != "" {
		return env
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return ".onionsec/onionsec.db"
	}
	return home + "/.onionsec/onionsec.db"
}
