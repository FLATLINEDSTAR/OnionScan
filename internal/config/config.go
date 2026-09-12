// Package config provides configuration parsing for scan limits and Tor connection parameters.
package config

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/AryanXCode646/OnionScan/internal/crawler"
	"github.com/AryanXCode646/OnionScan/internal/tor"
)

// Config holds runtime options for OnionSec scanning.
type Config struct {
	SOCKSAddr          string
	Limits             crawler.Limits
	MaxConcurrentScans int
	MaxQueueSize       int
}

// DefaultConfig returns the baseline configuration with crawler and tor defaults.
func DefaultConfig() Config {
	return Config{
		SOCKSAddr:          tor.DefaultSOCKSAddr,
		Limits:             crawler.DefaultLimits,
		MaxConcurrentScans: 4,
		MaxQueueSize:       32,
	}
}

// DefaultConfigPath returns ~/.onionsec/config.yaml or fallback.
func DefaultConfigPath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return filepath.Join(".onionsec", "config.yaml")
	}
	return filepath.Join(home, ".onionsec", "config.yaml")
}

// LoadFile reads config from the specified path. If explicit is false and the file does not exist,
// DefaultConfig() is returned with no error.
func LoadFile(path string, explicit bool) (Config, error) {
	cfg := DefaultConfig()
	if path == "" {
		path = DefaultConfigPath()
	}

	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) && !explicit {
			return cfg, nil
		}
		return cfg, fmt.Errorf("open config file %q: %w", path, err)
	}
	defer f.Close()

	return Parse(f, cfg)
}

// Parse reads minimal YAML key-value pairs into a Config struct.
func Parse(r io.Reader, base Config) (Config, error) {
	scanner := bufio.NewScanner(r)
	lineNum := 0

	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Remove inline comments after values, if not quoted
		if idx := strings.Index(line, "#"); idx != -1 {
			quotes := strings.Count(line[:idx], "\"") + strings.Count(line[:idx], "'")
			if quotes%2 == 0 {
				line = strings.TrimSpace(line[:idx])
			}
		}

		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			return base, fmt.Errorf("line %d: invalid format, expected key: value", lineNum)
		}

		key := strings.ToLower(strings.TrimSpace(parts[0]))
		val := strings.TrimSpace(parts[1])
		val = strings.Trim(val, `"'`)

		switch key {
		case "socks_addr", "socks_address", "socks":
			base.SOCKSAddr = val

		case "max_pages", "maxpages":
			n, err := strconv.Atoi(val)
			if err != nil {
				return base, fmt.Errorf("line %d: invalid integer for %s: %w", lineNum, key, err)
			}
			base.Limits.MaxPages = n

		case "max_body_byte", "max_body_bytes", "max_body_size":
			bytes, err := parseBytes(val)
			if err != nil {
				return base, fmt.Errorf("line %d: invalid byte size for %s: %w", lineNum, key, err)
			}
			base.Limits.MaxBodyByte = bytes

		case "page_timeout", "pagetimeout":
			d, err := parseDuration(val)
			if err != nil {
				return base, fmt.Errorf("line %d: invalid duration for %s: %w", lineNum, key, err)
			}
			base.Limits.PageTimeout = d

		case "total_budget", "totalbudget":
			d, err := parseDuration(val)
			if err != nil {
				return base, fmt.Errorf("line %d: invalid duration for %s: %w", lineNum, key, err)
			}
			base.Limits.TotalBudget = d

		case "max_concurrent_scans", "max_concurrency", "max_scans":
			n, err := strconv.Atoi(val)
			if err != nil {
				return base, fmt.Errorf("line %d: invalid integer for %s: %w", lineNum, key, err)
			}
			base.MaxConcurrentScans = n

		case "max_queue_size", "max_queue":
			n, err := strconv.Atoi(val)
			if err != nil {
				return base, fmt.Errorf("line %d: invalid integer for %s: %w", lineNum, key, err)
			}
			base.MaxQueueSize = n

		default:
			// Unknown key: ignore to allow forward compatibility
		}
	}

	if err := scanner.Err(); err != nil {
		return base, fmt.Errorf("read config: %w", err)
	}

	return base, nil
}

func parseDuration(s string) (time.Duration, error) {
	d, err := time.ParseDuration(s)
	if err == nil {
		return d, nil
	}
	sec, err := strconv.Atoi(s)
	if err == nil {
		return time.Duration(sec) * time.Second, nil
	}
	return 0, fmt.Errorf("cannot parse %q as duration", s)
}

func parseBytes(s string) (int64, error) {
	sUpper := strings.ToUpper(strings.TrimSpace(s))
	multipliers := map[string]int64{
		"K":  1024,
		"KB": 1024,
		"M":  1024 * 1024,
		"MB": 1024 * 1024,
		"G":  1024 * 1024 * 1024,
		"GB": 1024 * 1024 * 1024,
	}

	for suffix, mult := range multipliers {
		if strings.HasSuffix(sUpper, suffix) {
			raw := strings.TrimSpace(sUpper[:len(sUpper)-len(suffix)])
			n, err := strconv.ParseInt(raw, 10, 64)
			if err != nil {
				return 0, err
			}
			return n * mult, nil
		}
	}

	return strconv.ParseInt(s, 10, 64)
}
