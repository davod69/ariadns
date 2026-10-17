package sni

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"sync/atomic"
	"time"
)

// Hooks connect the relay to the rest of the server.
type Hooks struct {
	Allow   func(client netip.Addr) bool                                 // may this client use the relay?
	Match   func(host string) bool                                       // is this host smart-routed?
	Resolve func(ctx context.Context, host string) ([]netip.Addr, error) // real addresses of host
	Traffic func(client netip.Addr, n int64)                             // bytes transferred
}

// Options tune the relay.
type Options struct {
	Fragment  bool // split the TLS ClientHello across two TCP segments
	MaxRelays int
	Idle      time.Duration
	DestPort  int // 0 = same port the client connected to (tests override)
}

// Relay accepts connections and forwards them to the real destination.
type Relay struct {
	h     Hooks
	opt   Options
	log   *slog.Logger
	sem   chan struct{}
	conns sync.Map
	wg    sync.WaitGroup
	lns   []net.Listener
	Stats struct{ Accepted, Relayed, Rejected, Failed atomic.Uint64 }
}

func New(h Hooks, opt Options, log *slog.Logger) *Relay {
	if opt.MaxRelays <= 0 {
		opt.MaxRelays = 4096
	}
	if opt.Idle <= 0 {
		opt.Idle = 5 * time.Minute
	}
	return &Relay{h: h, opt: opt, log: log, sem: make(chan struct{}, opt.MaxRelays)}
}

// Serve accepts on ln until it is closed. tls selects ClientHello (true) or
// HTTP Host (false) parsing; the destination port is the listener's port.
func (r *Relay) Serve(ln net.Listener, tls bool) {
	r.lns = append(r.lns, ln)
	port := ln.Addr().(*net.TCPAddr).Port
	if r.opt.DestPort != 0 {
		port = r.opt.DestPort
	}
	r.wg.Add(1)
	go func() {
		defer r.wg.Done()
		for {
			c, err := ln.Accept()
			if err != nil {
				if errors.Is(err, net.ErrClosed) {
					return
				}
				time.Sleep(10 * time.Millisecond)
				continue
			}
			r.Stats.Accepted.Add(1)
			select {
			case r.sem <- struct{}{}:
			default:
				r.Stats.Rejected.Add(1)
				_ = c.Close()
				continue
			}
			r.wg.Add(1)
			go func() {
				defer r.wg.Done()
				defer func() { <-r.sem }()
				r.handle(c, tls, port)
			}()
		}
	}()
}

// Close stops the listeners and drops open relays.
func (r *Relay) Close() {
	for _, l := range r.lns {
		_ = l.Close()
	}
	r.conns.Range(func(k, _ any) bool { _ = k.(net.Conn).Close(); return true })
	r.wg.Wait()
}

func (r *Relay) handle(c net.Conn, tls bool, port int) {
	defer c.Close()
	r.conns.Store(c, struct{}{})
	defer r.conns.Delete(c)

	ta, ok := c.RemoteAddr().(*net.TCPAddr)
	if !ok {
		return
	}
	client := ta.AddrPort().Addr().Unmap()
	if !r.h.Allow(client) {
		r.Stats.Rejected.Add(1)
		return
	}

	// Read just enough to learn the destination name.
	_ = c.SetReadDeadline(time.Now().Add(10 * time.Second))
	buf := make([]byte, 0, 2048)
	tmp := make([]byte, 4096)
	var host string
	var hostOff int
	for {
		n, err := c.Read(tmp)
		buf = append(buf, tmp[:n]...)
		var perr error
		if tls {
			host, hostOff, perr = ParseClientHello(buf)
		} else {
			host, perr = ParseHTTPHost(buf)
		}
		if perr == nil {
			break
		}
		if perr != ErrNeedMore || err != nil || len(buf) > 20<<10 {
			r.Stats.Rejected.Add(1)
			return
		}
	}
	if host == "" || !r.h.Match(host) {
		r.Stats.Rejected.Add(1) // never act as an open proxy
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	ips, err := r.h.Resolve(ctx, host)
	if err != nil || len(ips) == 0 {
		cancel()
		r.Stats.Failed.Add(1)
		r.log.Debug("sni resolve failed", "host", host, "err", err)
		return
	}
	var up net.Conn
	d := net.Dialer{Timeout: 6 * time.Second}
	for _, ip := range ips {
		up, err = d.DialContext(ctx, "tcp", net.JoinHostPort(ip.String(), strconv.Itoa(port)))
		if err == nil {
			break
		}
	}
	cancel()
	if up == nil {
		r.Stats.Failed.Add(1)
		r.log.Debug("sni dial failed", "host", host, "err", err)
		return
	}
	defer up.Close()
	r.conns.Store(up, struct{}{})
	defer r.conns.Delete(up)
	r.Stats.Relayed.Add(1)

	if uc, ok := up.(*net.TCPConn); ok {
		_ = uc.SetNoDelay(true)
	}
	var sent int64
	if tls && r.opt.Fragment && hostOff > 1 && hostOff < len(buf) {
		cut := hostOff + len(host)/2
		if cut >= len(buf) {
			cut = hostOff
		}
		if _, err := up.Write(buf[:cut]); err != nil {
			return
		}
		time.Sleep(2 * time.Millisecond)
		if _, err := up.Write(buf[cut:]); err != nil {
			return
		}
	} else if _, err := up.Write(buf); err != nil {
		return
	}
	sent = int64(len(buf))
	r.h.Traffic(client, sent)

	done := make(chan struct{}, 2)
	pipe := func(dst, src net.Conn) {
		b := make([]byte, 32<<10)
		for {
			_ = src.SetReadDeadline(time.Now().Add(r.opt.Idle))
			n, err := src.Read(b)
			if n > 0 {
				if _, werr := dst.Write(b[:n]); werr != nil {
					break
				}
				r.h.Traffic(client, int64(n))
				if !r.h.Allow(client) { // quota used up or access revoked mid-stream
					break
				}
			}
			if err != nil {
				if !errors.Is(err, io.EOF) {
					r.log.Debug("relay read", "err", err)
				}
				break
			}
		}
		done <- struct{}{}
	}
	_ = c.SetReadDeadline(time.Time{})
	go pipe(up, c)
	go pipe(c, up)
	<-done
	_ = c.Close()
	_ = up.Close()
	<-done
}
