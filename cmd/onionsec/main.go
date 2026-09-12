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
	"os"
	"strings"
	"time"

	"github.com/AryanXCode646/OnionScan/internal/config"
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
  onionsec monitor <target.onion>
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
	store := storage.New(defaultDataDir())

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
	store := storage.New(defaultDataDir())
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

	store := storage.New(defaultDataDir())
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
	// TODO: tracked in issue "Phase 4: implement `onionsec monitor` diffing".
	// Should: run a new scan, load the previous scan via storage.Store,
	// diff finding IDs/evidence, and print NEW / REMOVED / CHANGED sections.
	fmt.Fprintln(os.Stderr, "onionsec monitor: not implemented yet -- see open issues")
	os.Exit(1)
}

func printSummary(r model.ScanResult) {
	fmt.Printf("Target:     %s\n", r.Target.Onion)
	fmt.Printf("Pages seen: %d\n", r.PagesSeen)
	fmt.Printf("Risk score: %d / 100\n\n", r.RiskScore)
}

func defaultDataDir() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ".onionsec"
	}
	return home + "/.onionsec/scans"
}
