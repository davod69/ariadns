package server

import (
	"crypto/rand"
	"crypto/subtle"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"time"

	"ariadns/internal/admin"
	"ariadns/internal/smart"
	"ariadns/internal/sni"
	"ariadns/internal/subs"
	"ariadns/internal/version"
	"ariadns/internal/web"
)

// openData opens everything stored in cfg.DataDir.
func (s *Server) openData() error {
	dir := s.cfg.DataDir
	if dir == "" {
		return nil
	}
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return err
	}
	var err error
	if s.subs, err = subs.Open(filepath.Join(dir, "subscribers.json")); err != nil {
		return err
	}
	if s.smart, err = smart.Open(filepath.Join(dir, "smart.json"), s.cfg.Smart.PublicIP); err != nil {
		return err
	}
	var pw string
	if s.creds, pw, err = admin.OpenCreds(dir); err != nil {
		return err
	}
	if pw != "" {
		s.log.Warn("admin credentials created (shown once; use the `ariadns menu` command to reset)",
			"panel_path", "/"+s.creds.Path()+"/", "password", pw)
	}
	s.h.subs = s.subs
	if s.cfg.Smart.Enabled {
		s.h.smart = s.smart
	}
	return nil
}

// ctlToken is the bearer token for the loopback control API.
func (s *Server) ctlToken() (string, error) {
	if s.cfg.Web.Token != "" || s.cfg.DataDir == "" {
		return s.cfg.Web.Token, nil
	}
	path := filepath.Join(s.cfg.DataDir, "ctl.token")
	if b, err := os.ReadFile(path); err == nil && len(strings.TrimSpace(string(b))) >= 32 {
		return strings.TrimSpace(string(b)), nil
	}
	raw := make([]byte, 24)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	tok := hex.EncodeToString(raw)
	return tok, os.WriteFile(path, []byte(tok+"\n"), 0o600)
}

// webHandler serves the dashboard and, when a data dir is configured, the
// subscriber/routing control API. Everything requires the bearer token.
func (s *Server) webHandler(token string) http.Handler {
	dash := web.New(s, token)
	if s.creds == nil {
		return dash
	}
	api := admin.API(s, s.creds)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := r.URL.Path
		if strings.HasPrefix(p, "/api/subs") || strings.HasPrefix(p, "/api/smart") ||
			strings.HasPrefix(p, "/api/overview") || strings.HasPrefix(p, "/api/admin/") {
			got := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
			if token == "" || subtle.ConstantTimeCompare([]byte(got), []byte(token)) != 1 {
				w.Header().Set("WWW-Authenticate", `Bearer realm="ariadns"`)
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
			r.Header.Set("X-Ariadns-Local", "1")
			api.ServeHTTP(w, r)
			return
		}
		dash.ServeHTTP(w, r)
	})
}

// startSmart launches the SNI relay listeners.
func (s *Server) startSmart() error {
	rl := sni.New(sni.Hooks{
		Allow:   func(ip netip.Addr) bool { return s.h.allowed(s.h.live.Load(), ip) },
		Match:   func(host string) bool { _, ok := s.smart.Match(host); return ok },
		Resolve: s.h.ResolveAddrs,
		Traffic: func(ip netip.Addr, n int64) { s.subs.AddTraffic(ip, n) },
	}, sni.Options{Fragment: s.cfg.Smart.Fragment, MaxRelays: s.cfg.Smart.MaxRelays}, s.log)
	s.relay = rl
	for _, c := range []struct {
		name, addr string
		tls        bool
	}{{"relay-tls", s.cfg.Smart.ListenTLS, true}, {"relay-http", s.cfg.Smart.ListenHTTP, false}} {
		if c.addr == "" {
			continue
		}
		ln, err := net.Listen("tcp", c.addr)
		if err != nil {
			return err
		}
		s.addrs[c.name] = ln.Addr().String()
		rl.Serve(ln, c.tls)
		s.log.Info("listening", "proto", c.name, "addr", s.addrs[c.name])
	}
	return nil
}

// startPanel serves the hidden admin panel and the subscriber portal.
func (s *Server) startPanel(addr string) error {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	s.addrs["panel"] = ln.Addr().String()
	srv := &http.Server{
		Handler:           admin.Panel(s, s.creds),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    16 << 10,
	}
	var l net.Listener = ln
	scheme := "http"
	if s.cfg.Panel.TLS {
		l = tls.NewListener(ln, s.certs.tlsConfig())
		scheme = "https"
	}
	s.closers = append(s.closers, func() { shutdownHTTP(srv) })
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		if err := srv.Serve(l); err != nil && !errors.Is(err, http.ErrServerClosed) {
			s.log.Error("panel stopped", "err", err)
		}
	}()
	s.log.Info("admin panel listening", "url", scheme+"://"+s.addrs["panel"]+"/"+s.creds.Path()+"/")
	return nil
}

// --- admin.Backend ---

func (s *Server) Subs() *subs.Store    { return s.subs }
func (s *Server) Smart() *smart.Engine { return s.smart }
func (s *Server) Dash() http.Handler   { return web.New(s, "") }

func (s *Server) PanelBase() string {
	host := ""
	if ip, ok := s.smart.PublicV4(); ok {
		host = ip.String()
	}
	port := ""
	if _, p, err := net.SplitHostPort(s.cfg.Panel.Listen); err == nil {
		port = p
	}
	scheme := "http"
	if s.cfg.Panel.TLS {
		scheme = "https"
	}
	if host == "" {
		host = "SERVER_IP"
	}
	return scheme + "://" + host + ":" + port
}

func (s *Server) Overview() any {
	o := map[string]any{
		"version": version.Version, "stats": s.st.Snapshot(), "listeners": s.addrs,
		"subscribers": len(s.subs.List()),
	}
	if ip, ok := s.smart.PublicV4(); ok {
		o["public_ip"] = ip.String()
	}
	if s.relay != nil {
		o["relay"] = map[string]uint64{
			"accepted": s.relay.Stats.Accepted.Load(), "relayed": s.relay.Stats.Relayed.Load(),
			"rejected": s.relay.Stats.Rejected.Load(), "failed": s.relay.Stats.Failed.Load(),
		}
	}
	return o
}
