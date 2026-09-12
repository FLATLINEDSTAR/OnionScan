package tls

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"testing"
	"time"

	"github.com/AryanXCode646/OnionScan/internal/model"
)

func TestAnalyze_ClearnetHostname_SEC001(t *testing.T) {
	cert := &x509.Certificate{
		Subject:   pkix.Name{CommonName: "hidden.onion"},
		DNSNames:  []string{"hidden.onion", "clearnet-api.example.com"},
		NotBefore: time.Now().Add(-24 * time.Hour),
		NotAfter:  time.Now().Add(365 * 24 * time.Hour),
	}

	a := New()
	a.DialTLS = func(ctx context.Context, target string) (*TLSInfo, error) {
		return &TLSInfo{
			Version:          tls.VersionTLS13,
			CipherSuite:      tls.TLS_AES_128_GCM_SHA256,
			PeerCertificates: []*x509.Certificate{cert},
		}, nil
	}

	target := model.Target{Onion: "hidden.onion"}
	page := model.Page{URL: "http://hidden.onion/"}

	findings, err := a.Analyze(context.Background(), target, page)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var foundSEC001 bool
	for _, f := range findings {
		if f.ID == "SEC-001" {
			foundSEC001 = true
			if f.Severity != model.SeverityHigh {
				t.Errorf("expected SeverityHigh for SEC-001, got %v", f.Severity)
			}
		}
	}

	if !foundSEC001 {
		t.Errorf("expected SEC-001 finding for clearnet hostname in certificate, got %+v", findings)
	}
}

func TestAnalyze_OnionOnlyCert_NoSEC001(t *testing.T) {
	cert := &x509.Certificate{
		Subject:   pkix.Name{CommonName: "clean.onion"},
		DNSNames:  []string{"clean.onion"},
		NotBefore: time.Now().Add(-24 * time.Hour),
		NotAfter:  time.Now().Add(365 * 24 * time.Hour),
	}

	a := New()
	a.DialTLS = func(ctx context.Context, target string) (*TLSInfo, error) {
		return &TLSInfo{
			Version:          tls.VersionTLS13,
			CipherSuite:      tls.TLS_AES_128_GCM_SHA256,
			PeerCertificates: []*x509.Certificate{cert},
		}, nil
	}

	target := model.Target{Onion: "clean.onion"}
	page := model.Page{URL: "http://clean.onion/"}

	findings, err := a.Analyze(context.Background(), target, page)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	for _, f := range findings {
		if f.ID == "SEC-001" {
			t.Errorf("did not expect SEC-001 for pure onion certificate, got %+v", f)
		}
	}
}

func TestAnalyze_WeakTLS_SEC002(t *testing.T) {
	expiredCert := &x509.Certificate{
		Subject:   pkix.Name{CommonName: "expired.onion"},
		DNSNames:  []string{"expired.onion"},
		NotBefore: time.Now().Add(-48 * time.Hour),
		NotAfter:  time.Now().Add(-24 * time.Hour), // Expired!
	}

	a := New()
	a.DialTLS = func(ctx context.Context, target string) (*TLSInfo, error) {
		return &TLSInfo{
			Version:          tls.VersionTLS10,             // Deprecated!
			CipherSuite:      tls.TLS_RSA_WITH_RC4_128_SHA, // Weak cipher!
			PeerCertificates: []*x509.Certificate{expiredCert},
		}, nil
	}

	target := model.Target{Onion: "expired.onion"}
	page := model.Page{URL: "http://expired.onion/"}

	findings, err := a.Analyze(context.Background(), target, page)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	sec002Count := 0
	for _, f := range findings {
		if f.ID == "SEC-002" {
			sec002Count++
		}
	}

	if sec002Count == 0 {
		t.Errorf("expected at least one SEC-002 finding for deprecated TLS/expired cert/weak cipher, got %+v", findings)
	}
}

func TestAnalyze_UnreachableHTTPS(t *testing.T) {
	a := New()
	a.DialTLS = func(ctx context.Context, target string) (*TLSInfo, error) {
		return nil, errors.New("connection refused")
	}

	target := model.Target{Onion: "nohttps.onion"}
	page := model.Page{URL: "http://nohttps.onion/"}

	findings, err := a.Analyze(context.Background(), target, page)
	if err != nil {
		t.Fatalf("unexpected error when HTTPS unreachable: %v", err)
	}

	if len(findings) != 0 {
		t.Errorf("expected 0 findings when target does not serve HTTPS, got %+v", findings)
	}
}
