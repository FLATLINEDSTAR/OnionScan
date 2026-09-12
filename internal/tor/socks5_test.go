package tor

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"
)

func TestDialContext_StalledProxyTimeout(t *testing.T) {
	// Mock server accepts TCP connection but never sends SOCKS5 greeting reply
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			defer c.Close()
			// Don't send anything back, just keep connection open
			buf := make([]byte, 128)
			_, _ = c.Read(buf)
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	start := time.Now()
	conn, err := DialContext(ctx, ln.Addr().String(), "target.onion:80")
	elapsed := time.Since(start)

	if err == nil {
		if conn != nil {
			conn.Close()
		}
		t.Fatalf("expected error from stalled proxy, got nil")
	}

	if !errors.Is(err, context.DeadlineExceeded) {
		var netErr net.Error
		if !errors.As(err, &netErr) || !netErr.Timeout() {
			t.Errorf("expected deadline exceeded or timeout error, got: %v", err)
		}
	}

	if elapsed > 1*time.Second {
		t.Errorf("DialContext took %v, expected timeout around 100ms", elapsed)
	}
}

func TestDialContext_ContextCancelledBeforeDial(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	_, err := DialContext(ctx, "127.0.0.1:9050", "target.onion:80")
	if !errors.Is(err, context.Canceled) {
		t.Errorf("expected context.Canceled, got: %v", err)
	}
}

func TestDialContext_ContextCancelledDuringHandshake(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			defer c.Close()
			buf := make([]byte, 128)
			_, _ = c.Read(buf)
		}
	}()

	ctx, cancel := context.WithCancel(context.Background())
	time.AfterFunc(50*time.Millisecond, cancel)

	_, err = DialContext(ctx, ln.Addr().String(), "target.onion:80")
	if err == nil {
		t.Fatalf("expected context cancellation error, got nil")
	}
	if !errors.Is(err, context.Canceled) {
		t.Errorf("expected context.Canceled, got: %v", err)
	}
}

func TestDialContext_ContextCancelledDuringConnect(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			defer c.Close()

			// Read version & greeting
			buf := make([]byte, 128)
			n, err := c.Read(buf)
			if err != nil || n < 2 {
				return
			}

			// Respond to handshake successfully
			_, _ = c.Write([]byte{socksVersion5, authNone})

			// Hang on connect request without sending reply
			_, _ = c.Read(buf)
		}
	}()

	ctx, cancel := context.WithCancel(context.Background())
	time.AfterFunc(50*time.Millisecond, cancel)

	_, err = DialContext(ctx, ln.Addr().String(), "target.onion:80")
	if err == nil {
		t.Fatalf("expected context cancellation error, got nil")
	}
	if !errors.Is(err, context.Canceled) {
		t.Errorf("expected context.Canceled, got: %v", err)
	}
}

func TestDialContext_DeadlineClearedOnSuccess(t *testing.T) {
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
			_, _ = conn.Write(append([]byte("echo: "), buf[:n]...))
		}
	}()

	socksAddr, cleanup := startMockSOCKS5(t)
	defer cleanup()

	// Dial with a short deadline
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	conn, err := DialContext(ctx, socksAddr, targetLn.Addr().String())
	if err != nil {
		t.Fatalf("DialContext failed: %v", err)
	}
	defer conn.Close()

	// Wait 250ms so that the initial 200ms context deadline has expired.
	time.Sleep(250 * time.Millisecond)

	// Since DialContext clears the connection deadline on success, this write/read must succeed.
	msg := []byte("hello after deadline")
	if _, err := conn.Write(msg); err != nil {
		t.Fatalf("Write failed after original deadline: %v", err)
	}

	reply := make([]byte, 128)
	n, err := conn.Read(reply)
	if err != nil {
		t.Fatalf("Read failed after original deadline: %v", err)
	}

	expected := "echo: hello after deadline"
	if string(reply[:n]) != expected {
		t.Errorf("expected %q, got %q", expected, string(reply[:n]))
	}
}
