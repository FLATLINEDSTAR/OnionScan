package tor

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// startMockSOCKS5 starts a lightweight in-memory SOCKS5 proxy server for unit testing.
func startMockSOCKS5(t *testing.T) (string, func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to start mock SOCKS5 listener: %v", err)
	}

	done := make(chan struct{})

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				select {
				case <-done:
					return
				default:
					return
				}
			}

			go func(c net.Conn) {
				defer c.Close()

				// Read version identifier and auth methods
				buf := make([]byte, 256)
				n, err := c.Read(buf)
				if err != nil || n < 2 || buf[0] != socksVersion5 {
					return
				}

				// Respond with no authentication required (0x05, 0x00)
				if _, err := c.Write([]byte{socksVersion5, authNone}); err != nil {
					return
				}

				// Read CONNECT request: VER CMD RSV ATYP [DST.ADDR] [DST.PORT]
				n, err = c.Read(buf)
				if err != nil || n < 7 || buf[0] != socksVersion5 || buf[1] != cmdConnect {
					return
				}

				var targetHost string
				var targetPort uint16
				idx := 4

				switch buf[3] {
				case atypDomainName:
					domainLen := int(buf[4])
					idx = 5
					if n < idx+domainLen+2 {
						return
					}
					targetHost = string(buf[idx : idx+domainLen])
					idx += domainLen
					targetPort = binary.BigEndian.Uint16(buf[idx : idx+2])
				case 0x01: // IPv4
					if n < idx+4+2 {
						return
					}
					targetHost = net.IP(buf[idx : idx+4]).String()
					idx += 4
					targetPort = binary.BigEndian.Uint16(buf[idx : idx+2])
				default:
					return
				}

				targetAddr := net.JoinHostPort(targetHost, fmt.Sprintf("%d", targetPort))
				targetConn, err := net.DialTimeout("tcp", targetAddr, 2*time.Second)
				if err != nil {
					// 0x05, 0x05 (Connection refused), 0x00, 0x01, ...
					c.Write([]byte{socksVersion5, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
					return
				}
				defer targetConn.Close()

				// Succeeded: 0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, port
				c.Write([]byte{socksVersion5, repSucceeded, 0x00, 0x01, 127, 0, 0, 1, 0, 0})

				// Bidirectional copy
				errCh := make(chan error, 2)
				go func() {
					_, err := io.Copy(targetConn, c)
					errCh <- err
				}()
				go func() {
					_, err := io.Copy(c, targetConn)
					errCh <- err
				}()
				<-errCh
			}(conn)
		}
	}()

	cleanup := func() {
		close(done)
		ln.Close()
	}

	return ln.Addr().String(), cleanup
}

func generateSelfSignedCert(t *testing.T, host string) (*tls.Config, []byte) {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey: %v", err)
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: host,
		},
		NotBefore: time.Now().Add(-1 * time.Hour),
		NotAfter:  time.Now().Add(24 * time.Hour),
		DNSNames:  []string{host},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("x509.CreateCertificate: %v", err)
	}

	tlsCert := tls.Certificate{
		Certificate: [][]byte{certDER},
		PrivateKey:  priv,
	}

	return &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
	}, certDER
}

func TestDialContext_ThroughMockSOCKS5(t *testing.T) {
	// Start a mock TCP echo server
	targetLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen target: %v", err)
	}
	defer targetLn.Close()

	go func() {
		conn, err := targetLn.Accept()
		if err == nil {
			defer conn.Close()
			buf := make([]byte, 128)
			n, _ := conn.Read(buf)
			conn.Write(append([]byte("echo: "), buf[:n]...))
		}
	}()

	socksAddr, cleanup := startMockSOCKS5(t)
	defer cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	conn, err := DialContext(ctx, socksAddr, targetLn.Addr().String())
	if err != nil {
		t.Fatalf("DialContext failed: %v", err)
	}
	defer conn.Close()

	msg := []byte("hello")
	if _, err := conn.Write(msg); err != nil {
		t.Fatalf("Write: %v", err)
	}

	reply := make([]byte, 128)
	n, err := conn.Read(reply)
	if err != nil {
		t.Fatalf("Read: %v", err)
	}

	expected := "echo: hello"
	if string(reply[:n]) != expected {
		t.Errorf("expected %q, got %q", expected, string(reply[:n]))
	}
}

func TestDialTLSContext_ThroughMockSOCKS5(t *testing.T) {
	tlsConfig, _ := generateSelfSignedCert(t, "127.0.0.1")
	targetLn, err := tls.Listen("tcp", "127.0.0.1:0", tlsConfig)
	if err != nil {
		t.Fatalf("tls.Listen: %v", err)
	}
	defer targetLn.Close()

	go func() {
		conn, err := targetLn.Accept()
		if err == nil {
			defer conn.Close()
			buf := make([]byte, 64)
			n, _ := conn.Read(buf)
			conn.Write(append([]byte("tls-echo: "), buf[:n]...))
		}
	}()

	socksAddr, cleanup := startMockSOCKS5(t)
	defer cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	clientTLSConn, err := DialTLSContext(ctx, socksAddr, targetLn.Addr().String(), &tls.Config{
		InsecureSkipVerify: true,
	})
	if err != nil {
		t.Fatalf("DialTLSContext failed: %v", err)
	}
	defer clientTLSConn.Close()

	if _, err := clientTLSConn.Write([]byte("ping")); err != nil {
		t.Fatalf("Write: %v", err)
	}

	reply := make([]byte, 64)
	n, err := clientTLSConn.Read(reply)
	if err != nil {
		t.Fatalf("Read: %v", err)
	}

	expected := "tls-echo: ping"
	if string(reply[:n]) != expected {
		t.Errorf("expected %q, got %q", expected, string(reply[:n]))
	}
}

func TestNewHTTPClient_ThroughMockSOCKS5(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok from mock server"))
	}))
	defer ts.Close()

	socksAddr, cleanup := startMockSOCKS5(t)
	defer cleanup()

	client := NewHTTPClient(socksAddr, 3*time.Second)
	resp, err := client.Get(ts.URL)
	if err != nil {
		t.Fatalf("client.Get failed: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}

	if string(body) != "ok from mock server" {
		t.Errorf("expected %q, got %q", "ok from mock server", string(body))
	}
}
