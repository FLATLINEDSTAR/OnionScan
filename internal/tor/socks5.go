// Package tor provides a minimal SOCKS5 CONNECT client so OnionSec can
// route HTTP requests through a local Tor daemon (default 127.0.0.1:9050)
// without pulling in an external dependency. It intentionally implements
// only what's needed for outbound CONNECT to a hostname:port (including
// .onion addresses) with no authentication, which is what Tor's SOCKSPort
// expects by default.
package tor

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
)

const (
	socksVersion5  = 0x05
	authNone       = 0x00
	cmdConnect     = 0x01
	atypDomainName = 0x03
	repSucceeded   = 0x00
)

// DialContext connects to targetAddr ("host:port") through the SOCKS5
// proxy at proxyAddr ("host:port"), suitable for reaching .onion hosts via
// a local Tor daemon. Callers should wire this into http.Transport.DialContext.
func DialContext(ctx context.Context, proxyAddr, targetAddr string) (net.Conn, error) {
	if proxyAddr == "" {
		proxyAddr = DefaultSOCKSAddr
	}
	var d net.Dialer
	conn, err := d.DialContext(ctx, "tcp", proxyAddr)
	if err != nil {
		return nil, fmt.Errorf("connect to tor proxy %s: %w", proxyAddr, err)
	}

	if err := handshake(conn); err != nil {
		conn.Close()
		return nil, err
	}

	host, portStr, err := net.SplitHostPort(targetAddr)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("invalid target address %q: %w", targetAddr, err)
	}
	var port uint16
	if _, err := fmt.Sscanf(portStr, "%d", &port); err != nil {
		conn.Close()
		return nil, fmt.Errorf("invalid port %q: %w", portStr, err)
	}

	if err := connect(conn, host, port); err != nil {
		conn.Close()
		return nil, err
	}

	return conn, nil
}

// DialTLSContext connects to targetAddr ("host:port") through the SOCKS5
// proxy at proxyAddr ("host:port"), then initiates a TLS handshake with
// targetAddr using the provided config. If config is nil, a default config
// with InsecureSkipVerify: true and ServerName set to target hostname is used.
func DialTLSContext(ctx context.Context, proxyAddr, targetAddr string, config *tls.Config) (*tls.Conn, error) {
	conn, err := DialContext(ctx, proxyAddr, targetAddr)
	if err != nil {
		return nil, fmt.Errorf("connect to tor proxy %s for tls: %w", proxyAddr, err)
	}

	host, _, err := net.SplitHostPort(targetAddr)
	if err != nil {
		host = targetAddr
	}

	if config == nil {
		config = &tls.Config{
			InsecureSkipVerify: true,
			ServerName:         host,
		}
	} else if config.ServerName == "" {
		config = config.Clone()
		config.ServerName = host
	}

	tlsConn := tls.Client(conn, config)
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		conn.Close()
		return nil, fmt.Errorf("tls handshake with %s via tor proxy %s: %w", targetAddr, proxyAddr, err)
	}

	return tlsConn, nil
}

func handshake(conn net.Conn) error {
	// greeting: version, nmethods, methods...
	if _, err := conn.Write([]byte{socksVersion5, 1, authNone}); err != nil {
		return fmt.Errorf("socks5 greeting: %w", err)
	}
	resp := make([]byte, 2)
	if _, err := readFull(conn, resp); err != nil {
		return fmt.Errorf("socks5 greeting response: %w", err)
	}
	if resp[0] != socksVersion5 {
		return errors.New("socks5: unexpected server version")
	}
	if resp[1] != authNone {
		return errors.New("socks5: server requires unsupported auth method")
	}
	return nil
}

func connect(conn net.Conn, host string, port uint16) error {
	if len(host) > 255 {
		return errors.New("socks5: hostname too long")
	}
	req := []byte{socksVersion5, cmdConnect, 0x00, atypDomainName, byte(len(host))}
	req = append(req, []byte(host)...)
	portBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(portBytes, port)
	req = append(req, portBytes...)

	if _, err := conn.Write(req); err != nil {
		return fmt.Errorf("socks5 connect request: %w", err)
	}

	// Reply header: VER REP RSV ATYP
	head := make([]byte, 4)
	if _, err := readFull(conn, head); err != nil {
		return fmt.Errorf("socks5 connect response: %w", err)
	}
	if head[1] != repSucceeded {
		return fmt.Errorf("socks5: proxy refused connection (code %d) -- is Tor running with a SOCKSPort?", head[1])
	}

	// Consume the bound address so the connection stream is left clean.
	switch head[3] {
	case 0x01: // IPv4
		if _, err := readFull(conn, make([]byte, 4+2)); err != nil {
			return err
		}
	case 0x03: // domain name
		lenBuf := make([]byte, 1)
		if _, err := readFull(conn, lenBuf); err != nil {
			return err
		}
		if _, err := readFull(conn, make([]byte, int(lenBuf[0])+2)); err != nil {
			return err
		}
	case 0x04: // IPv6
		if _, err := readFull(conn, make([]byte, 16+2)); err != nil {
			return err
		}
	default:
		return errors.New("socks5: unknown address type in reply")
	}

	return nil
}

func readFull(conn net.Conn, buf []byte) (int, error) {
	total := 0
	for total < len(buf) {
		n, err := conn.Read(buf[total:])
		total += n
		if err != nil {
			return total, err
		}
	}
	return total, nil
}
