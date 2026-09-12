package model

import (
	"errors"
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// Target is a single authorized onion service being scanned.
type Target struct {
	Onion     string    `json:"onion"`           // e.g. exampleabc...xyz.onion
	Label     string    `json:"label,omitempty"` // optional human-friendly name
	CreatedAt time.Time `json:"created_at"`
}

// Page is a single fetched resource belonging to a Target.
type Page struct {
	URL        string            `json:"url"`
	StatusCode int               `json:"status_code"`
	Headers    map[string]string `json:"headers"`
	Body       []byte            `json:"-"` // never serialized directly; keep out of reports
	FetchedAt  time.Time         `json:"fetched_at"`
}

var onionRegex = regexp.MustCompile(`^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)*([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)\.onion$`)

// ValidateOnion normalizes and validates a target onion address.
// It trims leading whitespace, scheme prefixes (http://, https://), and trailing slashes.
// It rejects path traversal sequences (..), path separators (/, \), invalid characters, and non-onion domains.
// Returns the normalized target address or a descriptive error.
func ValidateOnion(raw string) (string, error) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return "", errors.New("target address cannot be empty")
	}

	// Reject control characters or null bytes
	for _, r := range s {
		if r < 32 || r == 127 {
			return "", fmt.Errorf("target contains invalid control characters: %q", raw)
		}
	}

	// Trim case-insensitive scheme
	lower := strings.ToLower(s)
	if strings.HasPrefix(lower, "http://") {
		s = s[7:]
	} else if strings.HasPrefix(lower, "https://") {
		s = s[8:]
	}

	// Trim trailing slashes and whitespace
	s = strings.TrimRight(s, "/")
	s = strings.TrimSpace(s)
	if s == "" {
		return "", fmt.Errorf("target is empty after trimming scheme: %q", raw)
	}

	// Reject path separators or traversal sequences
	if strings.Contains(s, "/") || strings.Contains(s, "\\") {
		return "", fmt.Errorf("target contains path separator: %q", raw)
	}
	if strings.Contains(s, "..") {
		return "", fmt.Errorf("target contains path traversal sequence: %q", raw)
	}

	host := s
	portStr := ""
	if strings.Contains(s, ":") {
		var err error
		host, portStr, err = net.SplitHostPort(s)
		if err != nil {
			return "", fmt.Errorf("invalid host:port in target: %w", err)
		}
		portNum, err := strconv.Atoi(portStr)
		if err != nil || portNum < 1 || portNum > 65535 {
			return "", fmt.Errorf("invalid port %q in target: %q", portStr, raw)
		}
	}

	host = strings.ToLower(host)

	// Allow loopback / localhost targets for local development and integration testing
	if isLoopback(host) {
		if portStr != "" {
			return host + ":" + portStr, nil
		}
		return host, nil
	}

	if !strings.HasSuffix(host, ".onion") {
		return "", fmt.Errorf("target must end with .onion: %q", raw)
	}

	if !onionRegex.MatchString(host) {
		return "", fmt.Errorf("invalid onion address format: %q", raw)
	}

	if portStr != "" {
		return host + ":" + portStr, nil
	}
	return host, nil
}

func isLoopback(host string) bool {
	if host == "localhost" {
		return true
	}
	if ip := net.ParseIP(host); ip != nil && ip.IsLoopback() {
		return true
	}
	return false
}
