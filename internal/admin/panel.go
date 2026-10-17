package admin

import (
	"embed"
	"errors"
	"io/fs"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"time"
)

//go:embed static
var staticFS embed.FS

const csp = "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self' data:; base-uri 'none'; form-action 'none'; frame-ancestors 'none'"

const (
	cookieName = "ariadns_s"
	sessionTTL = 12 * time.Hour
)

type lockout struct {
	mu sync.Mutex
	m  map[netip.Addr]*fails
}

type fails struct {
	n     int
	until time.Time
}

func (l *lockout) locked(ip netip.Addr) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	f := l.m[ip]
	return f != nil && time.Now().Before(f.until)
}

func (l *lockout) fail(ip netip.Addr) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.m == nil {
		l.m = map[netip.Addr]*fails{}
	}
	if len(l.m) > 10000 {
		l.m = map[netip.Addr]*fails{}
	}
	f := l.m[ip]
	if f == nil {
		f = &fails{}
		l.m[ip] = f
	}
	if f.n++; f.n >= 5 {
		f.n, f.until = 0, time.Now().Add(5*time.Minute)
	}
}

func (l *lockout) ok(ip netip.Addr) {
	l.mu.Lock()
	delete(l.m, ip)
	l.mu.Unlock()
}

func secure(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hd := w.Header()
		hd.Set("Content-Security-Policy", csp)
		hd.Set("X-Content-Type-Options", "nosniff")
		hd.Set("X-Frame-Options", "DENY")
		hd.Set("Referrer-Policy", "no-referrer")
		hd.Set("Cache-Control", "no-store")
		hd.Set("X-Robots-Tag", "noindex, nofollow")
		h.ServeHTTP(w, r)
	})
}

// Panel returns the public-facing handler: the hidden admin panel plus the
// subscriber portal. Everything else answers 404, so the panel's existence
// is not revealed to scanners.
func Panel(b Backend, cr *Creds) http.Handler {
	sub, _ := fs.Sub(staticFS, "static")
	assets := http.StripPrefix("/_a/", http.FileServer(http.FS(sub)))
	api := API(b, cr)
	var lock lockout
	portal := portalHandler(b, sub)

	page := func(w http.ResponseWriter, name string) {
		data, _ := fs.ReadFile(sub, name)
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write(data)
	}

	authed := func(r *http.Request) bool {
		c, err := r.Cookie(cookieName)
		return err == nil && cr.validSession(c.Value)
	}

	return secure(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := r.URL.Path
		switch {
		case strings.HasPrefix(p, "/_a/"):
			if strings.HasPrefix(p, "/_a/portal") || p == "/_a/style.css" || strings.HasPrefix(p, "/_a/panel") {
				assets.ServeHTTP(w, r)
				return
			}
		case strings.HasPrefix(p, "/sub/"):
			portal.ServeHTTP(w, r)
			return
		}

		prefix := "/" + cr.Path()
		if p != prefix && !strings.HasPrefix(p, prefix+"/") {
			http.NotFound(w, r)
			return
		}
		rel := strings.TrimPrefix(p, prefix)
		if rel == "" {
			http.Redirect(w, r, prefix+"/", http.StatusMovedPermanently)
			return
		}
		ip := ClientIP(r)

		switch {
		case rel == "/" && r.Method == http.MethodGet:
			page(w, "panel.html")
		case rel == "/login" && r.Method == http.MethodPost:
			if lock.locked(ip) {
				fail(w, http.StatusTooManyRequests, errors.New("too many attempts, try again in a few minutes"))
				return
			}
			var in struct {
				Password string `json:"password"`
			}
			if !decode(w, r, &in) {
				return
			}
			if !cr.Verify(in.Password) {
				lock.fail(ip)
				fail(w, http.StatusUnauthorized, errors.New("wrong password"))
				return
			}
			lock.ok(ip)
			http.SetCookie(w, &http.Cookie{
				Name: cookieName, Value: cr.newSession(sessionTTL), Path: prefix + "/",
				HttpOnly: true, SameSite: http.SameSiteStrictMode, Secure: r.TLS != nil,
				MaxAge: int(sessionTTL.Seconds()),
			})
			writeJSON(w, 200, map[string]string{"status": "ok"})
		case rel == "/logout" && r.Method == http.MethodPost:
			http.SetCookie(w, &http.Cookie{Name: cookieName, Value: "", Path: prefix + "/", MaxAge: -1, HttpOnly: true})
			writeJSON(w, 200, map[string]string{"status": "ok"})
		case rel == "/api/me":
			if !authed(r) {
				fail(w, http.StatusUnauthorized, errors.New("login required"))
				return
			}
			writeJSON(w, 200, map[string]string{"status": "ok"})
		case strings.HasPrefix(rel, "/api/"):
			if !authed(r) {
				fail(w, http.StatusUnauthorized, errors.New("login required"))
				return
			}
			if r.Method != http.MethodGet && r.Header.Get("X-Requested-With") != "ariadns" {
				fail(w, http.StatusForbidden, errors.New("missing X-Requested-With header"))
				return
			}
			r2 := r.Clone(r.Context())
			r2.Header.Del("X-Ariadns-Local")
			r2.URL.Path = rel
			api.ServeHTTP(w, r2)
		case rel == "/dash":
			http.Redirect(w, r, prefix+"/dash/", http.StatusMovedPermanently)
		case strings.HasPrefix(rel, "/dash/"):
			if !authed(r) {
				http.NotFound(w, r)
				return
			}
			http.StripPrefix(prefix+"/dash", b.Dash()).ServeHTTP(w, r)
		default:
			http.NotFound(w, r)
		}
	}))
}
