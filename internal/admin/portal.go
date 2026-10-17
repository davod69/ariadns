package admin

import (
	"errors"
	"io/fs"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"time"

	"ariadns/internal/subs"
)

type portalLimiter struct {
	mu sync.Mutex
	m  map[netip.Addr][]time.Time
}

func (l *portalLimiter) allow(ip netip.Addr) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.m == nil || len(l.m) > 10000 {
		l.m = map[netip.Addr][]time.Time{}
	}
	cut := time.Now().Add(-time.Minute)
	hits := l.m[ip][:0]
	for _, t := range l.m[ip] {
		if t.After(cut) {
			hits = append(hits, t)
		}
	}
	if len(hits) >= 30 {
		l.m[ip] = hits
		return false
	}
	l.m[ip] = append(hits, time.Now())
	return true
}

// portalHandler serves /sub/{token}[/info|/rebind]: the page a subscriber
// opens to see their usage and to bind their current IP address.
func portalHandler(b Backend, static fs.FS) http.Handler {
	var lim portalLimiter
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := ClientIP(r)
		if !lim.allow(ip) {
			fail(w, http.StatusTooManyRequests, errors.New("slow down"))
			return
		}
		rest := strings.TrimPrefix(r.URL.Path, "/sub/")
		token, action, _ := strings.Cut(rest, "/")
		v, ok := b.Subs().ByToken(token)
		if !ok {
			http.NotFound(w, r)
			return
		}
		switch {
		case action == "" && r.Method == http.MethodGet:
			data, _ := fs.ReadFile(static, "portal.html")
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			_, _ = w.Write(data)
		case action == "info" && r.Method == http.MethodGet:
			writeJSON(w, 200, portalInfo(b, v, ip))
		case action == "rebind" && r.Method == http.MethodPost:
			if r.Header.Get("X-Requested-With") != "ariadns" {
				fail(w, http.StatusForbidden, errors.New("bad request"))
				return
			}
			nv, err := b.Subs().Rebind(token, ip)
			switch {
			case err == nil:
				writeJSON(w, 200, portalInfo(b, nv, ip))
			case errors.Is(err, subs.ErrCooldown), errors.Is(err, subs.ErrDisabled), errors.Is(err, subs.ErrIPInUse):
				fail(w, http.StatusConflict, err)
			default:
				fail(w, http.StatusInternalServerError, err)
			}
		default:
			http.NotFound(w, r)
		}
	})
}

func portalInfo(b Backend, v subs.View, ip netip.Addr) map[string]any {
	dns := ""
	if a, ok := b.Smart().PublicV4(); ok {
		dns = a.String()
	}
	return map[string]any{
		"name": v.Name, "status": v.Status, "ip": v.IP, "your_ip": ip.String(),
		"used_bytes": v.UsedBytes, "limit_bytes": v.LimitBytes, "expires_at": v.ExpiresAt,
		"self_rebind": v.SelfRebind, "dns_server": dns,
	}
}
