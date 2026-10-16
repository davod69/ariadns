// Package server wires the DNS handler to its network listeners: UDP, TCP,
// DNS-over-TLS, DNS-over-HTTPS and the admin web UI.
package server

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"ariadns/internal/config"
	"ariadns/internal/dnsmsg"
	"ariadns/internal/stats"
	"ariadns/internal/upstream"
	"ariadns/internal/web"
)

// Server owns the listeners and the handler.
type Server struct {
	cfgPath string
	cfg     *config.Config
	log     *slog.Logger
	h       *Handler
	certs   *certStore
	st      *stats.Collector

	addrs   map[string]string
	cancel  context.CancelFunc
	wg      sync.WaitGroup
	closers []func()
	conns   sync.Map // net.Conn -> struct{}
	connSem chan struct{}
	pktPool sync.Pool
	shed    atomic.Uint64 // queries/connections dropped because limits were reached
}

// New builds a Server. cfgPath is only used by Reload.
func New(cfg *config.Config, cfgPath string, log *slog.Logger, opts ...upstream.Option) (*Server, error) {
	col := stats.New(stats.Options{QueryLog: !cfg.Privacy.DisableQueryLog})
	h, err := NewHandler(cfg, log, col, opts...)
	if err != nil {
		return nil, err
	}
	return &Server{
		cfgPath: cfgPath, cfg: cfg, log: log, h: h, st: col,
		certs:   &certStore{},
		addrs:   map[string]string{},
		connSem: make(chan struct{}, cfg.Limits.MaxTCPConns),
		pktPool: sync.Pool{New: func() any { b := make([]byte, 4096); return &b }},
	}, nil
}

// Handler exposes the query handler (used by tests).
func (s *Server) Handler() *Handler { return s.h }

// Addr returns the bound address of a listener: "udp", "tcp", "dot", "doh" or "web".
func (s *Server) Addr(name string) string { return s.addrs[name] }

func (s *Server) needTLS() bool {
	return s.cfg.Listen.DoT != "" || (s.cfg.Listen.DoH != "" && !s.cfg.DoH.InsecureHTTP)
}

// Start binds every configured listener and begins serving in the
// background. It returns once everything is listening.
func (s *Server) Start(ctx context.Context) error {
	ctx, s.cancel = context.WithCancel(ctx)
	s.st.Start(ctx)
	s.goTicker(ctx, 30*time.Second, s.h.limiter.sweep)

	if s.needTLS() {
		msg, err := s.certs.load(s.cfg.TLS)
		if err != nil {
			s.cancel()
			return err
		}
		if s.cfg.TLS.SelfSigned && s.cfg.TLS.CertFile == "" {
			s.log.Warn(msg)
		} else {
			s.log.Info(msg)
		}
	}
	fail := func(err error) error {
		s.Shutdown()
		return err
	}

	if a := s.cfg.Listen.UDP; a != "" {
		pc, err := net.ListenPacket("udp", a)
		if err != nil {
			return fail(err)
		}
		uc := pc.(*net.UDPConn)
		_ = uc.SetReadBuffer(4 << 20)
		_ = uc.SetWriteBuffer(1 << 20)
		s.addrs["udp"] = pc.LocalAddr().String()
		s.closers = append(s.closers, func() { _ = pc.Close() })
		s.wg.Add(1)
		go s.serveUDP(ctx, uc)
		s.log.Info("listening", "proto", "udp", "addr", s.addrs["udp"])
	}
	if a := s.cfg.Listen.TCP; a != "" {
		ln, err := net.Listen("tcp", a)
		if err != nil {
			return fail(err)
		}
		s.addrs["tcp"] = ln.Addr().String()
		s.closers = append(s.closers, func() { _ = ln.Close() })
		s.wg.Add(1)
		go s.serveStream(ctx, ln, "tcp", time.Duration(s.cfg.Limits.TCPIdleSecs)*time.Second)
		s.log.Info("listening", "proto", "tcp", "addr", s.addrs["tcp"])
	}
	if a := s.cfg.Listen.DoT; a != "" {
		ln, err := net.Listen("tcp", a)
		if err != nil {
			return fail(err)
		}
		s.addrs["dot"] = ln.Addr().String()
		s.closers = append(s.closers, func() { _ = ln.Close() })
		tln := tls.NewListener(ln, s.certs.tlsConfig())
		s.wg.Add(1)
		go s.serveStream(ctx, tln, "dot", time.Duration(s.cfg.Limits.DoTIdleSecs)*time.Second)
		s.log.Info("listening", "proto", "dot", "addr", s.addrs["dot"])
	}
	if a := s.cfg.Listen.DoH; a != "" {
		if err := s.startDoH(a); err != nil {
			return fail(err)
		}
	}
	if a := s.cfg.Web.Listen; a != "" {
		if err := s.startWeb(a); err != nil {
			return fail(err)
		}
	}
	return nil
}

func (s *Server) goTicker(ctx context.Context, d time.Duration, fn func()) {
	go func() {
		t := time.NewTicker(d)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				fn()
			}
		}
	}()
}

// Run starts the server and blocks until ctx is cancelled.
func (s *Server) Run(ctx context.Context) error {
	if err := s.Start(ctx); err != nil {
		return err
	}
	<-ctx.Done()
	s.Shutdown()
	return nil
}

// Shutdown stops all listeners and waits briefly for connections to finish.
func (s *Server) Shutdown() {
	if s.cancel != nil {
		s.cancel()
	}
	for _, f := range s.closers {
		f()
	}
	s.closers = nil
	s.conns.Range(func(k, _ any) bool {
		_ = k.(net.Conn).Close()
		return true
	})
	done := make(chan struct{})
	go func() { s.wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		s.log.Warn("shutdown timed out waiting for connections")
	}
	s.h.close()
}

// Reload re-reads the config file and swaps rules, blocklists, the access
// list, forward zones and TLS certificates without dropping any traffic.
// Listeners, upstreams, cache and limits need a restart.
func (s *Server) Reload() error {
	cfg, err := config.Load(s.cfgPath)
	if err != nil {
		return err
	}
	if err := s.h.reload(cfg); err != nil {
		return err
	}
	if s.needTLS() && cfg.TLS.CertFile != "" {
		if _, err := s.certs.load(cfg.TLS); err != nil {
			return err
		}
	}
	c := s.h.live.Load().eng.Counts()
	s.log.Info("configuration reloaded", "blocked_domains", c.Blocked, "local_hosts", c.Hosts, "forward_zones", c.Zones)
	return nil
}

func (s *Server) serveUDP(ctx context.Context, pc *net.UDPConn) {
	defer s.wg.Done()
	sem := make(chan struct{}, s.cfg.Limits.MaxInflight)
	for {
		bp := s.pktPool.Get().(*[]byte)
		n, ap, err := pc.ReadFromUDPAddrPort(*bp)
		if err != nil {
			s.pktPool.Put(bp)
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return
			}
			s.log.Warn("udp read failed", "err", err)
			time.Sleep(10 * time.Millisecond)
			continue
		}
		select {
		case sem <- struct{}{}:
		default:
			s.shed.Add(1)
			s.pktPool.Put(bp)
			continue
		}
		go func() {
			defer func() {
				<-sem
				s.pktPool.Put(bp)
			}()
			if resp := s.h.Handle(ctx, (*bp)[:n], ap.Addr().Unmap(), "udp"); resp != nil {
				_, _ = pc.WriteToUDPAddrPort(resp, ap)
			}
		}()
	}
}

func (s *Server) serveStream(ctx context.Context, ln net.Listener, transport string, idle time.Duration) {
	defer s.wg.Done()
	for {
		c, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return
			}
			s.log.Warn("accept failed", "proto", transport, "err", err)
			time.Sleep(10 * time.Millisecond)
			continue
		}
		select {
		case s.connSem <- struct{}{}:
		default:
			s.shed.Add(1)
			_ = c.Close()
			continue
		}
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			defer func() { <-s.connSem }()
			s.handleConn(ctx, c, transport, idle)
		}()
	}
}

func (s *Server) handleConn(ctx context.Context, c net.Conn, transport string, idle time.Duration) {
	defer c.Close()
	s.conns.Store(c, struct{}{})
	defer s.conns.Delete(c)

	ta, ok := c.RemoteAddr().(*net.TCPAddr)
	if !ok {
		return
	}
	client := ta.AddrPort().Addr().Unmap()
	_ = c.SetDeadline(time.Now().Add(10 * time.Second)) // bounds the TLS handshake

	var lb [2]byte
	for {
		_ = c.SetReadDeadline(time.Now().Add(idle))
		if _, err := io.ReadFull(c, lb[:]); err != nil {
			return
		}
		n := int(binary.BigEndian.Uint16(lb[:]))
		if n < dnsmsg.HeaderLen {
			return
		}
		req := make([]byte, n)
		if _, err := io.ReadFull(c, req); err != nil {
			return
		}
		resp := s.h.Handle(ctx, req, client, transport)
		if resp == nil {
			return
		}
		out := make([]byte, 2+len(resp))
		binary.BigEndian.PutUint16(out, uint16(len(resp)))
		copy(out[2:], resp)
		_ = c.SetWriteDeadline(time.Now().Add(5 * time.Second))
		if _, err := c.Write(out); err != nil {
			return
		}
	}
}

func (s *Server) startWeb(addr string) error {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	s.addrs["web"] = ln.Addr().String()
	srv := &http.Server{
		Handler:           web.New(s, s.cfg.Web.Token),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    16 << 10,
	}
	s.closers = append(s.closers, func() { shutdownHTTP(srv) })
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			s.log.Error("web server stopped", "err", err)
		}
	}()
	s.log.Info("listening", "proto", "web", "addr", s.addrs["web"])
	return nil
}

func shutdownHTTP(srv *http.Server) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		_ = srv.Close()
	}
}

func addrPort(a net.Addr) (netip.AddrPort, bool) {
	if ta, ok := a.(*net.TCPAddr); ok {
		return ta.AddrPort(), true
	}
	return netip.AddrPort{}, false
}
