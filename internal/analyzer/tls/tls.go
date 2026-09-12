// Package tls inspects the target's TLS configuration and peer certificates
// if reachable over HTTPS. It looks for clearnet hostnames (SEC-001) that could link
// the onion service to clearnet infrastructure, as well as weak/deprecated TLS
// versions, expired certificates, and legacy cipher suites (SEC-002).
package tls

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/AryanXCode646/OnionScan/internal/model"
	"github.com/AryanXCode646/OnionScan/internal/tor"
)

// TLSInfo holds TLS handshake details and peer certificates.
type TLSInfo struct {
	Version          uint16
	CipherSuite      uint16
	PeerCertificates []*x509.Certificate
}

// Analyzer implements analyzer.Analyzer for TLS inspection.
type Analyzer struct {
	// DialTLS allows overriding the handshake for testing or custom proxies.
	DialTLS func(ctx context.Context, target string) (*TLSInfo, error)

	visitedMu sync.Mutex
	visited   map[string]bool
}

// New returns a new TLS analyzer with default dialer.
func New() *Analyzer {
	return &Analyzer{
		DialTLS: defaultDialTLS,
		visited: make(map[string]bool),
	}
}

// NewWithDialer returns a new TLS analyzer using the provided custom DialTLS function.
func NewWithDialer(dialTLS func(ctx context.Context, target string) (*TLSInfo, error)) *Analyzer {
	if dialTLS == nil {
		dialTLS = defaultDialTLS
	}
	return &Analyzer{
		DialTLS: dialTLS,
		visited: make(map[string]bool),
	}
}

// NewWithDialContext returns a new TLS analyzer that connects using dialContext
// (such as a Tor SOCKS5 dialer) before completing the TLS handshake.
func NewWithDialContext(dialContext func(ctx context.Context, network, addr string) (net.Conn, error)) *Analyzer {
	if dialContext == nil {
		return New()
	}
	return NewWithDialer(func(ctx context.Context, target string) (*TLSInfo, error) {
		addr := target
		if !strings.Contains(addr, ":") {
			addr = net.JoinHostPort(addr, "443")
		}

		rawConn, err := dialContext(ctx, "tcp", addr)
		if err != nil {
			return nil, err
		}
		defer rawConn.Close()

		host, _, _ := net.SplitHostPort(addr)
		tlsConfig := &tls.Config{
			InsecureSkipVerify: true,
			ServerName:         host,
		}

		tlsConn := tls.Client(rawConn, tlsConfig)
		if err := tlsConn.HandshakeContext(ctx); err != nil {
			return nil, err
		}

		state := tlsConn.ConnectionState()
		return &TLSInfo{
			Version:          state.Version,
			CipherSuite:      state.CipherSuite,
			PeerCertificates: state.PeerCertificates,
		}, nil
	})
}

// NewWithSOCKS returns a new TLS analyzer routed through the Tor SOCKS5 proxy at socksAddr.
func NewWithSOCKS(socksAddr string) *Analyzer {
	return NewWithDialContext(func(ctx context.Context, network, addr string) (net.Conn, error) {
		return tor.DialContext(ctx, socksAddr, addr)
	})
}

// Name returns "tls".
func (a *Analyzer) Name() string { return "tls" }

// Analyze checks TLS configuration and certificates for the target.
func (a *Analyzer) Analyze(ctx context.Context, target model.Target, page model.Page) ([]model.Finding, error) {
	// Check TLS once per target onion
	a.visitedMu.Lock()
	if a.visited == nil {
		a.visited = make(map[string]bool)
	}
	if a.visited[target.Onion] {
		a.visitedMu.Unlock()
		return nil, nil
	}
	a.visited[target.Onion] = true
	a.visitedMu.Unlock()

	dialFn := a.DialTLS
	if dialFn == nil {
		dialFn = defaultDialTLS
	}

	info, err := dialFn(ctx, target.Onion)
	if err != nil {
		// Target does not serve HTTPS or unreachable; not a finding.
		return nil, nil
	}

	var findings []model.Finding
	now := time.Now()

	// Inspect peer certificates
	if len(info.PeerCertificates) > 0 {
		cert := info.PeerCertificates[0]

		// 1. Clearnet hostnames in CN or SANs (SEC-001)
		var clearnetHosts []string
		if isClearnetHost(cert.Subject.CommonName) {
			clearnetHosts = append(clearnetHosts, cert.Subject.CommonName)
		}
		for _, san := range cert.DNSNames {
			if isClearnetHost(san) && !contains(clearnetHosts, san) {
				clearnetHosts = append(clearnetHosts, san)
			}
		}

		if len(clearnetHosts) > 0 {
			var ev []model.Evidence
			for _, h := range clearnetHosts {
				ev = append(ev, model.Evidence{
					Type:        model.EvidenceTLS,
					Description: fmt.Sprintf("hostname: %s", h),
					Source:      "tls_cert",
				})
			}

			findings = append(findings, model.Finding{
				ID:             "SEC-001",
				Title:          "TLS certificate issued to a clearnet hostname",
				Severity:       model.SeverityHigh,
				Confidence:     0.9,
				Target:         target.Onion,
				Analyzer:       a.Name(),
				Evidence:       ev,
				Explanation:    fmt.Sprintf("The TLS certificate presents clearnet hostnames (%s). This links the onion service directly to clearnet infrastructure or public domain registrations.", strings.Join(clearnetHosts, ", ")),
				Recommendation: "If this service is intended to remain anonymous, do not reuse clearnet TLS certificates. Rely on standard Tor onion encryption or use certificates issued solely for the .onion address.",
				CreatedAt:      now,
			})
		}

		// 2. Certificate expiration (part of SEC-002)
		if now.After(cert.NotAfter) {
			findings = append(findings, model.Finding{
				ID:         "SEC-002",
				Title:      "Weak/deprecated TLS configuration",
				Severity:   model.SeverityMedium,
				Confidence: 0.95,
				Target:     target.Onion,
				Analyzer:   a.Name(),
				Evidence: []model.Evidence{
					{
						Type:        model.EvidenceTLS,
						Description: fmt.Sprintf("Certificate expired on %s", cert.NotAfter.Format("2006-01-02")),
						Source:      "tls_cert",
					},
				},
				Explanation:    "The certificate presented by this service is expired.",
				Recommendation: "Renew or remove expired certificates.",
				CreatedAt:      now,
			})
		}
	}

	// 3. Deprecated TLS version (SEC-002)
	if info.Version != 0 && info.Version < tls.VersionTLS12 {
		verStr := tlsVersionString(info.Version)
		findings = append(findings, model.Finding{
			ID:         "SEC-002",
			Title:      "Weak/deprecated TLS configuration",
			Severity:   model.SeverityMedium,
			Confidence: 0.95,
			Target:     target.Onion,
			Analyzer:   a.Name(),
			Evidence: []model.Evidence{
				{
					Type:        model.EvidenceTLS,
					Description: fmt.Sprintf("Deprecated TLS version: %s", verStr),
					Source:      "tls_handshake",
				},
			},
			Explanation:    fmt.Sprintf("The server negotiated %s, which has known security weaknesses and is deprecated.", verStr),
			Recommendation: "Upgrade server configuration to require TLS 1.2 or TLS 1.3.",
			CreatedAt:      now,
		})
	}

	// 4. Insecure / weak cipher suite (SEC-002)
	if isWeakCipher(info.CipherSuite) {
		findings = append(findings, model.Finding{
			ID:         "SEC-002",
			Title:      "Weak/deprecated TLS configuration",
			Severity:   model.SeverityMedium,
			Confidence: 0.95,
			Target:     target.Onion,
			Analyzer:   a.Name(),
			Evidence: []model.Evidence{
				{
					Type:        model.EvidenceTLS,
					Description: fmt.Sprintf("Weak cipher suite ID: 0x%04x", info.CipherSuite),
					Source:      "tls_handshake",
				},
			},
			Explanation:    "The server negotiated a cipher suite that lacks forward secrecy or uses legacy CBC/RC4/3DES algorithms.",
			Recommendation: "Configure modern cipher suites with ephemeral key exchange (ECDHE) and AEAD ciphers (GCM, ChaCha20).",
			CreatedAt:      now,
		})
	}

	return findings, nil
}

func isClearnetHost(host string) bool {
	host = strings.ToLower(strings.TrimSpace(host))
	host = strings.TrimPrefix(host, "*.")
	if host == "" || strings.HasSuffix(host, ".onion") || host == "localhost" {
		return false
	}
	// Exclude pure IP loopback
	ip := net.ParseIP(host)
	if ip != nil && (ip.IsLoopback() || ip.IsPrivate()) {
		return false
	}
	return strings.Contains(host, ".")
}

func isWeakCipher(suite uint16) bool {
	switch suite {
	case tls.TLS_RSA_WITH_RC4_128_SHA,
		tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA,
		tls.TLS_RSA_WITH_AES_128_CBC_SHA,
		tls.TLS_RSA_WITH_AES_256_CBC_SHA,
		tls.TLS_RSA_WITH_AES_128_CBC_SHA256,
		tls.TLS_ECDHE_ECDSA_WITH_RC4_128_SHA,
		tls.TLS_ECDHE_RSA_WITH_RC4_128_SHA,
		tls.TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA:
		return true
	default:
		return false
	}
}

func tlsVersionString(ver uint16) string {
	switch ver {
	case tls.VersionTLS10:
		return "TLS 1.0"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS13:
		return "TLS 1.3"
	default:
		return fmt.Sprintf("TLS 0x%04x", ver)
	}
}

func contains(slice []string, s string) bool {
	for _, v := range slice {
		if v == s {
			return true
		}
	}
	return false
}

func defaultDialTLS(ctx context.Context, target string) (*TLSInfo, error) {
	addr := target
	if !strings.Contains(addr, ":") {
		addr = net.JoinHostPort(addr, "443")
	}

	dialer := &net.Dialer{Timeout: 5 * time.Second}
	conn, err := tls.DialWithDialer(dialer, "tcp", addr, &tls.Config{
		InsecureSkipVerify: true, // Needed to read certs on onion/self-signed endpoints
	})
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	state := conn.ConnectionState()
	return &TLSInfo{
		Version:          state.Version,
		CipherSuite:      state.CipherSuite,
		PeerCertificates: state.PeerCertificates,
	}, nil
}
