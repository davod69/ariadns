package sni

import (
	"context"
	"crypto/tls"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"
)

// captureHello returns the first bytes a real Go TLS client sends.
func captureHello(t *testing.T, name string) []byte {
	t.Helper()
	c, s := net.Pipe()
	go func() {
		_ = tls.Client(c, &tls.Config{ServerName: name, InsecureSkipVerify: true}).Handshake()
	}()
	b := make([]byte, 4096)
	_ = s.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, _ := s.Read(b)
	s.Close()
	return b[:n]
}

func TestParseClientHello(t *testing.T) {
	b := captureHello(t, "Store.SteamPowered.com")
	host, off, err := ParseClientHello(b)
	if err != nil || host != "store.steampowered.com" {
		t.Fatalf("host=%q err=%v", host, err)
	}
	if string(b[off:off+5]) != "Store" {
		t.Fatalf("hostOff wrong: %q", b[off:off+5])
	}
	if _, _, err := ParseClientHello(b[:20]); err != ErrNeedMore {
		t.Fatalf("truncated: %v", err)
	}
	if _, _, err := ParseClientHello([]byte("GET / HTTP/1.1\r\n\r\n")); err == nil {
		t.Fatal("HTTP must not parse as TLS")
	}
}

func TestParseHTTPHost(t *testing.T) {
	h, err := ParseHTTPHost([]byte("GET / HTTP/1.1\r\nUser-Agent: x\r\nHost: Example.com:80\r\n\r\n"))
	if err != nil || h != "example.com" {
		t.Fatalf("%q %v", h, err)
	}
	if _, err := ParseHTTPHost([]byte("GET / HTTP/1.1\r\nHost: a")); err != ErrNeedMore {
		t.Fatal("want ErrNeedMore")
	}
}

func TestRelayEndToEnd(t *testing.T) {
	echo, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer echo.Close()
	go func() {
		for {
			c, err := echo.Accept()
			if err != nil {
				return
			}
			go func() { defer c.Close(); io.Copy(c, c) }()
		}
	}()
	var traffic atomic.Int64
	allowed := atomic.Bool{}
	allowed.Store(true)
	r := New(Hooks{
		Allow: func(netip.Addr) bool { return allowed.Load() },
		Match: func(h string) bool { return h == "game.example" },
		Resolve: func(context.Context, string) ([]netip.Addr, error) {
			return []netip.Addr{netip.MustParseAddr("127.0.0.1")}, nil
		},
		Traffic: func(_ netip.Addr, n int64) { traffic.Add(n) },
	}, Options{DestPort: echo.Addr().(*net.TCPAddr).Port}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	r.Serve(ln, false)
	defer r.Close()

	// matching host is relayed to the echo server and back
	c, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	req := "GET / HTTP/1.1\r\nHost: game.example\r\n\r\n"
	c.Write([]byte(req))
	got := make([]byte, len(req))
	_ = c.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, err := io.ReadFull(c, got); err != nil || string(got) != req {
		t.Fatalf("relay did not echo: %q %v", got, err)
	}
	c.Close()
	if traffic.Load() < int64(len(req)) {
		t.Fatalf("traffic not counted: %d", traffic.Load())
	}

	// unmatched host is dropped (never an open proxy)
	c, _ = net.Dial("tcp", ln.Addr().String())
	c.Write([]byte("GET / HTTP/1.1\r\nHost: evil.example\r\n\r\n"))
	_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
	if n, _ := c.Read(make([]byte, 10)); n != 0 {
		t.Fatal("unmatched host must be dropped")
	}
	c.Close()

	// disallowed client is dropped
	allowed.Store(false)
	c, _ = net.Dial("tcp", ln.Addr().String())
	c.Write([]byte(req))
	_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
	if n, _ := c.Read(make([]byte, 10)); n != 0 {
		t.Fatal("disallowed client must be dropped")
	}
	c.Close()
}
