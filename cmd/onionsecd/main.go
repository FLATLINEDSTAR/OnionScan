// Command onionsecd provides the HTTP API daemon server for OnionSec.
package main

import (
	"context"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/AryanXCode646/OnionScan/internal/api"
	"github.com/AryanXCode646/OnionScan/internal/config"
	"github.com/AryanXCode646/OnionScan/internal/storage"
	"github.com/AryanXCode646/OnionScan/internal/tor"
)

const defaultAddr = "127.0.0.1:8080"

func main() {
	var addr string
	var dbPath string
	var socksAddr string
	var apiKey string
	var configPath string
	var maxScans int
	var maxQueue int

	flag.StringVar(&addr, "addr", defaultAddr, "HTTP listen address")
	flag.StringVar(&dbPath, "db", defaultDataDir(), "Path to SQLite database file")
	flag.StringVar(&socksAddr, "socks", "127.0.0.1:9050", "Tor SOCKS5 proxy address")
	flag.StringVar(&apiKey, "key", os.Getenv("ONIONSEC_API_KEY"), "Bearer auth token for API")
	flag.StringVar(&configPath, "config", "", "Path to YAML config file")
	flag.IntVar(&maxScans, "max-scans", 0, "Maximum concurrent active scans (default 4)")
	flag.IntVar(&maxQueue, "max-queue", 0, "Maximum queued async scan jobs (default 32)")
	flag.Parse()

	cfg, err := config.LoadFile(configPath, configPath != "")
	if err != nil {
		fmt.Fprintf(os.Stderr, "config error: %v\n", err)
		os.Exit(1)
	}
	if socksAddr != "127.0.0.1:9050" {
		cfg.SOCKSAddr = socksAddr
	}

	store, err := storage.New(dbPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "storage error: %v\n", err)
		os.Exit(1)
	}
	defer store.Close()

	torClient := tor.NewHTTPClient(cfg.SOCKSAddr, 30*time.Second)

	server := api.NewServer(store, torClient, cfg.Limits, apiKey)
	if maxScans > 0 {
		server.MaxConcurrentScans = maxScans
	} else if cfg.MaxConcurrentScans > 0 {
		server.MaxConcurrentScans = cfg.MaxConcurrentScans
	}
	if maxQueue > 0 {
		server.MaxQueueSize = maxQueue
	} else if cfg.MaxQueueSize > 0 {
		server.MaxQueueSize = cfg.MaxQueueSize
	}

	httpServer := &http.Server{
		Addr:         addr,
		Handler:      server,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 60 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	sigCtx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	go func() {
		fmt.Printf("onionsecd listening on http://%s (db: %s)\n", addr, dbPath)
		if apiKey == "" {
			fmt.Println("warning: running without API key authentication")
		}
		if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			fmt.Fprintf(os.Stderr, "HTTP server error: %v\n", err)
			os.Exit(1)
		}
	}()

	<-sigCtx.Done()
	fmt.Println("\nshutting down onionsecd...")

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := httpServer.Shutdown(shutdownCtx); err != nil {
		fmt.Fprintf(os.Stderr, "server shutdown error: %v\n", err)
	}
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
