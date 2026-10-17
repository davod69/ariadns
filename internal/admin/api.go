package admin

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/netip"
	"strings"
	"time"

	"ariadns/internal/smart"
	"ariadns/internal/subs"
)

// Backend is what the admin layer needs from the running server.
type Backend interface {
	Subs() *subs.Store
	Smart() *smart.Engine
	Overview() any
	Dash() http.Handler // read-only statistics dashboard
	PanelBase() string  // e.g. http://1.2.3.4:8080 (for display)
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func fail(w http.ResponseWriter, code int, err error) {
	writeJSON(w, code, map[string]string{"error": err.Error()})
}

func decode(w http.ResponseWriter, r *http.Request, v any) bool {
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		fail(w, http.StatusBadRequest, errors.New("bad JSON: "+err.Error()))
		return false
	}
	return true
}

const gb = 1 << 30

type createReq struct {
	Name       string  `json:"name"`
	IP         string  `json:"ip"`
	LimitGB    float64 `json:"limit_gb"`
	Days       int     `json:"days"`
	SelfRebind bool    `json:"self_rebind"`
}

type patchReq struct {
	Name       *string  `json:"name"`
	IP         *string  `json:"ip"`
	LimitGB    *float64 `json:"limit_gb"`
	ExtendDays *int     `json:"extend_days"`
	NoExpiry   *bool    `json:"no_expiry"`
	Enabled    *bool    `json:"enabled"`
	SelfRebind *bool    `json:"self_rebind"`
	ResetUsed  bool     `json:"reset_used"`
}

// API serves /api/subs, /api/smart, /api/overview and /api/admin/*.
// Authentication is the caller's job. password may be nil to disable the
// password endpoints.
func API(b Backend, cr *Creds) http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("/api/overview", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, b.Overview())
	})

	mux.HandleFunc("/api/subs", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			writeJSON(w, 200, b.Subs().List())
		case http.MethodPost:
			var in createReq
			if !decode(w, r, &in) {
				return
			}
			if in.LimitGB < 0 || in.LimitGB > 1e6 {
				fail(w, 400, errors.New("limit_gb out of range"))
				return
			}
			v, err := b.Subs().Add(subs.NewSub{
				Name: strings.TrimSpace(in.Name), IP: strings.TrimSpace(in.IP),
				LimitBytes: int64(in.LimitGB * gb), Days: in.Days, SelfRebind: in.SelfRebind,
			})
			if err != nil {
				fail(w, 400, err)
				return
			}
			writeJSON(w, 201, v)
		default:
			w.Header().Set("Allow", "GET, POST")
			fail(w, 405, errors.New("method not allowed"))
		}
	})

	mux.HandleFunc("/api/subs/", func(w http.ResponseWriter, r *http.Request) {
		id := strings.TrimPrefix(r.URL.Path, "/api/subs/")
		switch r.Method {
		case http.MethodDelete:
			if err := b.Subs().Delete(id); err != nil {
				fail(w, statusFor(err), err)
				return
			}
			writeJSON(w, 200, map[string]string{"status": "deleted"})
		case http.MethodPatch:
			var in patchReq
			if !decode(w, r, &in) {
				return
			}
			p := subs.Patch{Name: in.Name, IP: in.IP, Enabled: in.Enabled, SelfRebind: in.SelfRebind, ResetUsed: in.ResetUsed}
			if in.LimitGB != nil {
				if *in.LimitGB < 0 || *in.LimitGB > 1e6 {
					fail(w, 400, errors.New("limit_gb out of range"))
					return
				}
				l := int64(*in.LimitGB * gb)
				p.LimitBytes = &l
			}
			if in.NoExpiry != nil && *in.NoExpiry {
				z := int64(0)
				p.ExpiresAt = &z
			}
			if in.ExtendDays != nil && *in.ExtendDays != 0 {
				base := time.Now().Unix()
				for _, v := range b.Subs().List() {
					if v.ID == id && v.ExpiresAt > base {
						base = v.ExpiresAt
					}
				}
				e := base + int64(*in.ExtendDays)*86400
				p.ExpiresAt = &e
			}
			v, err := b.Subs().Update(id, p)
			if err != nil {
				fail(w, statusFor(err), err)
				return
			}
			writeJSON(w, 200, v)
		default:
			w.Header().Set("Allow", "PATCH, DELETE")
			fail(w, 405, errors.New("method not allowed"))
		}
	})

	mux.HandleFunc("/api/smart", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			writeJSON(w, 200, b.Smart().Snapshot())
		case http.MethodPut:
			var in struct {
				Enabled  []string `json:"enabled"`
				Custom   []string `json:"custom"`
				PublicIP *string  `json:"public_ip"`
			}
			if !decode(w, r, &in) {
				return
			}
			if err := b.Smart().Update(in.Enabled, in.Custom, in.PublicIP); err != nil {
				fail(w, 400, err)
				return
			}
			writeJSON(w, 200, b.Smart().Snapshot())
		default:
			w.Header().Set("Allow", "GET, PUT")
			fail(w, 405, errors.New("method not allowed"))
		}
	})

	mux.HandleFunc("/api/admin/info", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, map[string]string{
			"path": cr.Path(), "url": b.PanelBase() + "/" + cr.Path() + "/",
		})
	})
	mux.HandleFunc("/api/admin/password", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			fail(w, 405, errors.New("method not allowed"))
			return
		}
		var in struct {
			Current string `json:"current"`
			New     string `json:"new"`
			Reset   bool   `json:"reset"` // only honoured on the local control API
		}
		if !decode(w, r, &in) {
			return
		}
		if in.Reset && r.Header.Get("X-Ariadns-Local") == "1" {
			pw, err := cr.Reset()
			if err != nil {
				fail(w, 500, err)
				return
			}
			writeJSON(w, 200, map[string]string{"password": pw})
			return
		}
		if !cr.Verify(in.Current) {
			fail(w, 403, errors.New("current password is wrong"))
			return
		}
		if err := cr.Change(in.New); err != nil {
			fail(w, 400, err)
			return
		}
		writeJSON(w, 200, map[string]string{"status": "changed"})
	})
	return mux
}

func statusFor(err error) int {
	if errors.Is(err, subs.ErrNotFound) {
		return 404
	}
	return 400
}

// ClientIP extracts the peer address of a request.
func ClientIP(r *http.Request) netip.Addr {
	ap, err := netip.ParseAddrPort(r.RemoteAddr)
	if err != nil {
		return netip.Addr{}
	}
	return ap.Addr().Unmap()
}
