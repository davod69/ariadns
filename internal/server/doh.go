package server

import (
	"encoding/base64"
	"errors"
	"io"
	"mime"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"

	"ariadns/internal/dnsmsg"
)

func (s *Server) startDoH(addr string) error {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	s.addrs["doh"] = ln.Addr().String()
	ln = &limitListener{Listener: ln, sem: make(chan struct{}, s.cfg.Limits.MaxTCPConns)}

	mux := http.NewServeMux()
	mux.HandleFunc(s.cfg.DoH.Path, s.serveDoH)
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = io.WriteString(w, "ok\n")
	})
	srv := &http.Server{
		Handler:           mux,
		TLSConfig:         s.certs.tlsConfig(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    16 << 10,
	}
	s.closers = append(s.closers, func() { shutdownHTTP(srv) })
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		var err error
		if s.cfg.DoH.InsecureHTTP {
			err = srv.Serve(ln)
		} else {
			err = srv.ServeTLS(ln, "", "")
		}
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			s.log.Error("doh server stopped", "err", err)
		}
	}()
	scheme := "https"
	if s.cfg.DoH.InsecureHTTP {
		scheme = "http"
	}
	s.log.Info("listening", "proto", "doh", "addr", s.addrs["doh"], "url", scheme+"://"+s.addrs["doh"]+s.cfg.DoH.Path)
	return nil
}

// serveDoH implements RFC 8484 (GET ?dns= and POST application/dns-message).
func (s *Server) serveDoH(w http.ResponseWriter, r *http.Request) {
	var req []byte
	switch r.Method {
	case http.MethodGet:
		p := strings.TrimRight(r.URL.Query().Get("dns"), "=")
		if p == "" {
			http.Error(w, "missing dns parameter", http.StatusBadRequest)
			return
		}
		b, err := base64.RawURLEncoding.DecodeString(p)
		if err != nil {
			http.Error(w, "bad base64url", http.StatusBadRequest)
			return
		}
		req = b
	case http.MethodPost:
		mt, _, _ := mime.ParseMediaType(r.Header.Get("Content-Type"))
		if mt != "application/dns-message" {
			http.Error(w, "unsupported media type", http.StatusUnsupportedMediaType)
			return
		}
		b, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 65535))
		if err != nil {
			http.Error(w, "bad body", http.StatusBadRequest)
			return
		}
		req = b
	default:
		w.Header().Set("Allow", "GET, POST")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if len(req) < dnsmsg.HeaderLen {
		http.Error(w, "bad DNS message", http.StatusBadRequest)
		return
	}
	resp := s.h.Handle(r.Context(), req, s.dohClient(r), "doh")
	if resp == nil {
		http.Error(w, "bad DNS message", http.StatusBadRequest)
		return
	}
	maxAge := uint32(0)
	if rrs, err := dnsmsg.WalkRRs(resp); err == nil {
		first := true
		for _, rr := range rrs {
			if rr.Type != dnsmsg.TypeOPT && (first || rr.TTL < maxAge) {
				maxAge, first = rr.TTL, false
			}
		}
	}
	h := w.Header()
	h.Set("Content-Type", "application/dns-message")
	h.Set("Cache-Control", "max-age="+strconv.FormatUint(uint64(maxAge), 10))
	h.Set("X-Content-Type-Options", "nosniff")
	_, _ = w.Write(resp)
}

// dohClient returns the address queries are attributed to. Behind a trusted
// reverse proxy the right-most X-Forwarded-For entry (the one the proxy
// itself appended) is used; it is never taken from the client otherwise.
func (s *Server) dohClient(r *http.Request) netip.Addr {
	if s.cfg.DoH.TrustProxyHeaders {
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			parts := strings.Split(xff, ",")
			if ip, err := netip.ParseAddr(strings.TrimSpace(parts[len(parts)-1])); err == nil {
				return ip.Unmap()
			}
		}
	}
	if ap, err := netip.ParseAddrPort(r.RemoteAddr); err == nil {
		return ap.Addr().Unmap()
	}
	return netip.IPv4Unspecified()
}

// limitListener caps the number of concurrently open connections.
type limitListener struct {
	net.Listener
	sem chan struct{}
}

func (l *limitListener) Accept() (net.Conn, error) {
	for {
		c, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		select {
		case l.sem <- struct{}{}:
			return &limitConn{Conn: c, release: func() { <-l.sem }}, nil
		default:
			_ = c.Close() // over the limit: shed it
		}
	}
}

type limitConn struct {
	net.Conn
	once    sync.Once
	release func()
}

func (c *limitConn) Close() error {
	err := c.Conn.Close()
	c.once.Do(c.release)
	return err
}
