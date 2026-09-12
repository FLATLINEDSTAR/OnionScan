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
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
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

type exitCodeError struct {
	code int
	msg  string
}

func (e *exitCodeError) Error() string {
	return e.msg
}

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
  onionsec scan <target.onion> [--targets-file <path>] [--config <path>] [--json <out.json>] [--md <out.md>] [--quiet] [--fail-above-score <N>]
  onionsec report <target.onion>
  onionsec graph <target.onion> [--dot] [--out <path>]
  onionsec monitor <target.onion> [--targets-file <path>] [--config <path>] [--json <out.json>] [--md <out.md>] [--quiet] [--fail-on-changes] [--fail-above-score <N>] [--interval <duration>]
  onionsec diff <target.onion> <scan-id-1> <scan-id-2> [--json <out.json>] [--md <out.md>]
  onionsec version`)
}

func cleanOnion(s string) string {
	s = strings.TrimSpace(s)
	s = strings.TrimPrefix(s, "http://")
	s = strings.TrimPrefix(s, "https://")
	s = strings.TrimRight(s, "/")
	return s
}

func loadTargets(targetArg, targetsFilePath string) ([]string, error) {
	var targets []string
	if targetArg != "" {
		cleaned := cleanOnion(targetArg)
		if cleaned != "" {
			targets = append(targets, cleaned)
		}
	}
	if targetsFilePath != "" {
		data, err := os.ReadFile(targetsFilePath)
		if err != nil {
			return nil, fmt.Errorf("read targets file %q: %w", targetsFilePath, err)
		}
		lines := strings.Split(string(data), "\n")
		for _, line := range lines {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			cleaned := cleanOnion(line)
			if cleaned != "" {
				targets = append(targets, cleaned)
			}
		}
	}
	return targets, nil
}

type scanOptions struct {
	targetOnion     string
	targetsFilePath string
	configPath      string
	explicitConfig  bool
	jsonPath        string
	mdPath          string
	quiet           bool
	failAboveScore  int
	hasFailAbove    bool
}

func parseScanOptions(args []string) (scanOptions, error) {
	var opts scanOptions
	opts.failAboveScore = -1

	for i := 0; i < len(args); i++ {
		arg := args[i]
		switch {
		case arg == "--config" || arg == "-config":
			if i+1 < len(args) {
				opts.configPath = args[i+1]
				opts.explicitConfig = true
				i++
			} else {
				return opts, fmt.Errorf("error: --config requires a path argument")
			}
		case strings.HasPrefix(arg, "--config=") || strings.HasPrefix(arg, "-config="):
			opts.configPath = strings.SplitN(arg, "=", 2)[1]
			opts.explicitConfig = true
		case arg == "--json" || arg == "-json":
			if i+1 < len(args) {
				opts.jsonPath = args[i+1]
				i++
			} else {
				return opts, fmt.Errorf("error: --json requires a path argument")
			}
		case strings.HasPrefix(arg, "--json=") || strings.HasPrefix(arg, "-json="):
			opts.jsonPath = strings.SplitN(arg, "=", 2)[1]
		case arg == "--md" || arg == "-md":
			if i+1 < len(args) {
				opts.mdPath = args[i+1]
				i++
			} else {
				return opts, fmt.Errorf("error: --md requires a path argument")
			}
		case strings.HasPrefix(arg, "--md=") || strings.HasPrefix(arg, "-md="):
			opts.mdPath = strings.SplitN(arg, "=", 2)[1]
		case arg == "--targets-file" || arg == "-targets-file":
			if i+1 < len(args) {
				opts.targetsFilePath = args[i+1]
				i++
			} else {
				return opts, fmt.Errorf("error: --targets-file requires a path argument")
			}
		case strings.HasPrefix(arg, "--targets-file=") || strings.HasPrefix(arg, "-targets-file="):
			opts.targetsFilePath = strings.SplitN(arg, "=", 2)[1]
		case arg == "--quiet" || arg == "-quiet" || arg == "-q":
			opts.quiet = true
		case arg == "--fail-above-score" || arg == "-fail-above-score":
			if i+1 < len(args) {
				val, err := strconv.Atoi(args[i+1])
				if err != nil {
					return opts, fmt.Errorf("invalid score for --fail-above-score: %w", err)
				}
				opts.failAboveScore = val
				opts.hasFailAbove = true
				i++
			} else {
				return opts, fmt.Errorf("error: --fail-above-score requires an integer argument")
			}
		case strings.HasPrefix(arg, "--fail-above-score=") || strings.HasPrefix(arg, "-fail-above-score="):
			val, err := strconv.Atoi(strings.SplitN(arg, "=", 2)[1])
			if err != nil {
				return opts, fmt.Errorf("invalid score for --fail-above-score: %w", err)
			}
			opts.failAboveScore = val
			opts.hasFailAbove = true
		case opts.targetOnion == "" && !strings.HasPrefix(arg, "-"):
			opts.targetOnion = arg
		}
	}
	return opts, nil
}

func cmdScan(args []string) {
	if err := runScan(context.Background(), args, os.Stdout, os.Stderr); err != nil {
		var exitErr *exitCodeError
		if errors.As(err, &exitErr) {
			os.Exit(exitErr.code)
		}
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func runScan(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	return runScanWithClient(ctx, args, nil, stdout, stderr)
}

func runScanWithClient(ctx context.Context, args []string, client *http.Client, stdout, stderr io.Writer) error {
	opts, err := parseScanOptions(args)
	if err != nil {
		return err
	}

	targets, err := loadTargets(opts.targetOnion, opts.targetsFilePath)
	if err != nil {
		return err
	}
	if len(targets) == 0 {
		return fmt.Errorf("usage: onionsec scan <target.onion> [--targets-file <path>] [--config <path>] [--json <out.json>] [--md <out.md>] [--quiet] [--fail-above-score <N>]")
	}

	cfg, err := config.LoadFile(opts.configPath, opts.explicitConfig)
	if err != nil {
		return fmt.Errorf("config error: %w", err)
	}

	store, err := storage.New(defaultDataDir())
	if err != nil {
		return fmt.Errorf("storage error: %w", err)
	}
	defer store.Close()

	if client == nil {
		client = tor.NewHTTPClient(cfg.SOCKSAddr, 30*time.Second)
	}

	maxScore := 0
	for _, onion := range targets {
		if ctx.Err() != nil {
			return ctx.Err()
		}

		target := model.Target{Onion: onion, CreatedAt: time.Now()}
		scanCtx, cancel := context.WithTimeout(ctx, cfg.Limits.TotalBudget+time.Minute)
		result, err := scan.Run(scanCtx, client, store, target, cfg.Limits)
		cancel()
		if err != nil {
			fmt.Fprintf(stderr, "scan failed [%s]: %v\n", onion, err)
			continue
		}

		if result.RiskScore > maxScore {
			maxScore = result.RiskScore
		}

		if !opts.quiet || (opts.hasFailAbove && result.RiskScore > opts.failAboveScore) || len(result.Findings) > 0 {
			printSummary(stdout, result)
			if err := report.WriteMarkdown(stdout, result); err != nil {
				fmt.Fprintf(stderr, "render report [%s]: %v\n", onion, err)
			}
		}

		if opts.jsonPath != "" {
			f, err := os.Create(opts.jsonPath)
			if err != nil {
				fmt.Fprintf(stderr, "create json output [%s]: %v\n", onion, err)
			} else {
				_ = report.WriteJSON(f, result)
				f.Close()
			}
		}

		if opts.mdPath != "" {
			f, err := os.Create(opts.mdPath)
			if err != nil {
				fmt.Fprintf(stderr, "create md output [%s]: %v\n", onion, err)
			} else {
				_ = report.WriteMarkdown(f, result)
				f.Close()
			}
		}
	}

	if opts.hasFailAbove && maxScore > opts.failAboveScore {
		return &exitCodeError{code: 2, msg: fmt.Sprintf("risk score %d exceeded threshold %d", maxScore, opts.failAboveScore)}
	}

	return nil
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

type monitorOptions struct {
	targetOnion     string
	targetsFilePath string
	configPath      string
	explicitConfig  bool
	jsonPath        string
	mdPath          string
	quiet           bool
	failOnChanges   bool
	failAboveScore  int
	hasFailAbove    bool
	interval        time.Duration
}

func parseMonitorOptions(args []string) (monitorOptions, error) {
	var opts monitorOptions
	opts.failAboveScore = -1

	for i := 0; i < len(args); i++ {
		arg := args[i]
		switch {
		case arg == "--config" || arg == "-config":
			if i+1 < len(args) {
				opts.configPath = args[i+1]
				opts.explicitConfig = true
				i++
			} else {
				return opts, fmt.Errorf("error: --config requires a path argument")
			}
		case strings.HasPrefix(arg, "--config=") || strings.HasPrefix(arg, "-config="):
			opts.configPath = strings.SplitN(arg, "=", 2)[1]
			opts.explicitConfig = true
		case arg == "--json" || arg == "-json":
			if i+1 < len(args) {
				opts.jsonPath = args[i+1]
				i++
			} else {
				return opts, fmt.Errorf("error: --json requires a path argument")
			}
		case strings.HasPrefix(arg, "--json=") || strings.HasPrefix(arg, "-json="):
			opts.jsonPath = strings.SplitN(arg, "=", 2)[1]
		case arg == "--md" || arg == "-md":
			if i+1 < len(args) {
				opts.mdPath = args[i+1]
				i++
			} else {
				return opts, fmt.Errorf("error: --md requires a path argument")
			}
		case strings.HasPrefix(arg, "--md=") || strings.HasPrefix(arg, "-md="):
			opts.mdPath = strings.SplitN(arg, "=", 2)[1]
		case arg == "--targets-file" || arg == "-targets-file":
			if i+1 < len(args) {
				opts.targetsFilePath = args[i+1]
				i++
			} else {
				return opts, fmt.Errorf("error: --targets-file requires a path argument")
			}
		case strings.HasPrefix(arg, "--targets-file=") || strings.HasPrefix(arg, "-targets-file="):
			opts.targetsFilePath = strings.SplitN(arg, "=", 2)[1]
		case arg == "--quiet" || arg == "-quiet" || arg == "-q":
			opts.quiet = true
		case arg == "--fail-on-changes" || arg == "-fail-on-changes":
			opts.failOnChanges = true
		case arg == "--fail-above-score" || arg == "-fail-above-score":
			if i+1 < len(args) {
				val, err := strconv.Atoi(args[i+1])
				if err != nil {
					return opts, fmt.Errorf("invalid score for --fail-above-score: %w", err)
				}
				opts.failAboveScore = val
				opts.hasFailAbove = true
				i++
			} else {
				return opts, fmt.Errorf("error: --fail-above-score requires an integer argument")
			}
		case strings.HasPrefix(arg, "--fail-above-score=") || strings.HasPrefix(arg, "-fail-above-score="):
			val, err := strconv.Atoi(strings.SplitN(arg, "=", 2)[1])
			if err != nil {
				return opts, fmt.Errorf("invalid score for --fail-above-score: %w", err)
			}
			opts.failAboveScore = val
			opts.hasFailAbove = true
		case arg == "--interval" || arg == "-interval":
			if i+1 < len(args) {
				dur, err := time.ParseDuration(args[i+1])
				if err != nil {
					return opts, fmt.Errorf("invalid duration for --interval: %w", err)
				}
				opts.interval = dur
				i++
			} else {
				return opts, fmt.Errorf("error: --interval requires a duration argument (e.g. 1h, 30m)")
			}
		case strings.HasPrefix(arg, "--interval=") || strings.HasPrefix(arg, "-interval="):
			dur, err := time.ParseDuration(strings.SplitN(arg, "=", 2)[1])
			if err != nil {
				return opts, fmt.Errorf("invalid duration for --interval: %w", err)
			}
			opts.interval = dur
		case opts.targetOnion == "" && !strings.HasPrefix(arg, "-"):
			opts.targetOnion = arg
		}
	}
	return opts, nil
}

func cmdMonitor(args []string) {
	if err := runMonitor(context.Background(), args, os.Stdout, os.Stderr); err != nil {
		var exitErr *exitCodeError
		if errors.As(err, &exitErr) {
			os.Exit(exitErr.code)
		}
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func runMonitor(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	return runMonitorWithClient(ctx, args, nil, stdout, stderr)
}

func runMonitorWithClient(ctx context.Context, args []string, client *http.Client, stdout, stderr io.Writer) error {
	opts, err := parseMonitorOptions(args)
	if err != nil {
		return err
	}

	targets, err := loadTargets(opts.targetOnion, opts.targetsFilePath)
	if err != nil {
		return err
	}
	if len(targets) == 0 {
		return fmt.Errorf("usage: onionsec monitor <target.onion> [--targets-file <path>] [--config <path>] [--json <out.json>] [--md <out.md>] [--quiet] [--fail-on-changes] [--fail-above-score <N>] [--interval <duration>]")
	}

	cfg, err := config.LoadFile(opts.configPath, opts.explicitConfig)
	if err != nil {
		return fmt.Errorf("config error: %w", err)
	}

	store, err := storage.New(defaultDataDir())
	if err != nil {
		return fmt.Errorf("storage error: %w", err)
	}
	defer store.Close()

	if client == nil {
		client = tor.NewHTTPClient(cfg.SOCKSAddr, 30*time.Second)
	}

	if opts.interval > 0 {
		sigCtx, stop := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
		defer stop()

		ticker := time.NewTicker(opts.interval)
		defer ticker.Stop()

		// Initial cycle
		if _, _, err := executeMonitorBatch(sigCtx, targets, opts, cfg, store, client, stdout, stderr); err != nil {
			fmt.Fprintf(stderr, "monitor cycle error: %v\n", err)
		}

		for {
			select {
			case <-sigCtx.Done():
				return nil
			case <-ticker.C:
				if _, _, err := executeMonitorBatch(sigCtx, targets, opts, cfg, store, client, stdout, stderr); err != nil {
					fmt.Fprintf(stderr, "monitor cycle error: %v\n", err)
				}
			}
		}
	}

	hadChanges, maxScore, err := executeMonitorBatch(ctx, targets, opts, cfg, store, client, stdout, stderr)
	if err != nil {
		return err
	}

	if opts.failOnChanges && hadChanges {
		return &exitCodeError{code: 2, msg: "changes detected between scans"}
	}
	if opts.hasFailAbove && maxScore > opts.failAboveScore {
		return &exitCodeError{code: 2, msg: fmt.Sprintf("risk score %d exceeded threshold %d", maxScore, opts.failAboveScore)}
	}

	return nil
}

func executeMonitorBatch(ctx context.Context, targets []string, opts monitorOptions, cfg config.Config, store storage.Store, client *http.Client, stdout, stderr io.Writer) (bool, int, error) {
	hadAnyChanges := false
	maxScore := 0

	for _, onion := range targets {
		if ctx.Err() != nil {
			return hadAnyChanges, maxScore, ctx.Err()
		}

		target := model.Target{Onion: onion, CreatedAt: time.Now()}

		oldScan, hasOld, err := store.Latest(onion)
		if err != nil {
			fmt.Fprintf(stderr, "warning [%s]: unable to read previous scan history: %v\n", onion, err)
			hasOld = false
		}

		scanCtx, cancel := context.WithTimeout(ctx, cfg.Limits.TotalBudget+time.Minute)
		newScan, err := scan.Run(scanCtx, client, store, target, cfg.Limits)
		cancel()
		if err != nil {
			fmt.Fprintf(stderr, "scan failed [%s]: %v\n", onion, err)
			continue
		}

		if newScan.RiskScore > maxScore {
			maxScore = newScan.RiskScore
		}

		d := diff.Diff(oldScan, hasOld, newScan)
		if d.HasChanges() {
			hadAnyChanges = true
		}

		if !opts.quiet || d.HasChanges() {
			if err := diff.RenderText(stdout, d); err != nil {
				fmt.Fprintf(stderr, "render monitor report [%s]: %v\n", onion, err)
			}
		}

		if opts.jsonPath != "" {
			f, err := os.Create(opts.jsonPath)
			if err != nil {
				fmt.Fprintf(stderr, "create json output [%s]: %v\n", onion, err)
			} else {
				_ = diff.RenderJSON(f, d)
				f.Close()
			}
		}

		if opts.mdPath != "" {
			f, err := os.Create(opts.mdPath)
			if err != nil {
				fmt.Fprintf(stderr, "create markdown output [%s]: %v\n", onion, err)
			} else {
				_ = diff.RenderMarkdown(f, d)
				f.Close()
			}
		}
	}

	return hadAnyChanges, maxScore, nil
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

func printSummary(w io.Writer, r model.ScanResult) {
	fmt.Fprintf(w, "Target:     %s\n", r.Target.Onion)
	fmt.Fprintf(w, "Pages seen: %d\n", r.PagesSeen)
	fmt.Fprintf(w, "Risk score: %d / 100\n\n", r.RiskScore)
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
