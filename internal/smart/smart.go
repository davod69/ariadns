// Package smart decides which domains are "smart-routed": their DNS answers
// point at this server and the SNI relay carries the connection onward.
package smart

import (
	"encoding/json"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
)

type state struct {
	Enabled  []string `json:"enabled"`
	Custom   []string `json:"custom"`
	PublicV4 string   `json:"public_ip"`
	PublicV6 string   `json:"public_ip6,omitempty"`
}

type index struct {
	m map[string]string // domain -> category id
}

// Engine is safe for concurrent use.
type Engine struct {
	path string
	mu   sync.Mutex // guards st and file writes
	st   state
	idx  atomic.Pointer[index]
	v4   atomic.Pointer[netip.Addr]
	v6   atomic.Pointer[netip.Addr]
}

// Open loads (or initialises) the state stored at path. defaultIP is used
// when no public address has been saved yet.
func Open(path, defaultIP string) (*Engine, error) {
	e := &Engine{path: path}
	data, err := os.ReadFile(path)
	switch {
	case err == nil:
		if err := json.Unmarshal(data, &e.st); err != nil {
			return nil, err
		}
	case errors.Is(err, os.ErrNotExist):
		for _, c := range Presets {
			if c.Default {
				e.st.Enabled = append(e.st.Enabled, c.ID)
			}
		}
	default:
		return nil, err
	}
	if e.st.PublicV4 == "" {
		e.st.PublicV4 = defaultIP
	}
	e.rebuild()
	return e, nil
}

func (e *Engine) rebuild() {
	on := map[string]bool{}
	for _, id := range e.st.Enabled {
		on[id] = true
	}
	m := map[string]string{}
	for _, c := range Presets {
		if !on[c.ID] {
			continue
		}
		for _, d := range c.Domains {
			m[d] = c.ID
		}
	}
	for _, d := range e.st.Custom {
		m[d] = "custom"
	}
	e.idx.Store(&index{m: m})
	e.v4.Store(parseAddr(e.st.PublicV4, true))
	e.v6.Store(parseAddr(e.st.PublicV6, false))
}

func parseAddr(s string, v4 bool) *netip.Addr {
	a, err := netip.ParseAddr(strings.TrimSpace(s))
	if err != nil || a.Is4() != v4 {
		return nil
	}
	return &a
}

// Match reports whether name should be smart-routed, and via which category.
func (e *Engine) Match(name string) (string, bool) {
	m := e.idx.Load().m
	if len(m) == 0 {
		return "", false
	}
	for {
		if id, ok := m[name]; ok {
			return id, true
		}
		i := strings.IndexByte(name, '.')
		if i < 0 {
			return "", false
		}
		name = name[i+1:]
	}
}

// PublicV4 / PublicV6 return the address clients are told to connect to.
func (e *Engine) PublicV4() (netip.Addr, bool) {
	if a := e.v4.Load(); a != nil {
		return *a, true
	}
	return netip.Addr{}, false
}

// Info describes one category for the API.
type Info struct {
	ID      string `json:"id"`
	Title   string `json:"title"`
	Enabled bool   `json:"enabled"`
	Domains int    `json:"domains"`
}

// Snapshot is the editable state.
type Snapshot struct {
	Categories []Info   `json:"categories"`
	Custom     []string `json:"custom"`
	PublicIP   string   `json:"public_ip"`
}

func (e *Engine) Snapshot() Snapshot {
	e.mu.Lock()
	defer e.mu.Unlock()
	on := map[string]bool{}
	for _, id := range e.st.Enabled {
		on[id] = true
	}
	s := Snapshot{Custom: append([]string{}, e.st.Custom...), PublicIP: e.st.PublicV4}
	for _, c := range Presets {
		s.Categories = append(s.Categories, Info{c.ID, c.Title, on[c.ID], len(c.Domains)})
	}
	return s
}

// NormalizeDomain lower-cases and validates a custom domain.
func NormalizeDomain(d string) (string, bool) {
	d = strings.Trim(strings.ToLower(strings.TrimSpace(d)), ".")
	d = strings.TrimPrefix(d, "*.")
	if d == "" || len(d) > 253 || !strings.Contains(d, ".") {
		return "", false
	}
	for _, r := range d {
		if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-' || r == '.') {
			return "", false
		}
	}
	return d, true
}

// Update replaces the enabled categories, custom domains and public IP,
// persists them and takes effect immediately. A nil argument keeps the
// current value.
func (e *Engine) Update(enabled []string, custom []string, publicIP *string) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	next := e.st
	if enabled != nil {
		known := map[string]bool{}
		for _, c := range Presets {
			known[c.ID] = true
		}
		next.Enabled = nil
		for _, id := range enabled {
			if !known[id] {
				return errors.New("unknown category: " + id)
			}
			next.Enabled = append(next.Enabled, id)
		}
		sort.Strings(next.Enabled)
	}
	if custom != nil {
		next.Custom = nil
		for _, d := range custom {
			n, ok := NormalizeDomain(d)
			if !ok {
				return errors.New("invalid domain: " + d)
			}
			next.Custom = append(next.Custom, n)
		}
	}
	if publicIP != nil {
		ip := strings.TrimSpace(*publicIP)
		if ip != "" {
			a, err := netip.ParseAddr(ip)
			if err != nil || !a.Is4() {
				return errors.New("public_ip must be an IPv4 address")
			}
		}
		next.PublicV4 = ip
	}
	if err := writeJSON(e.path, next); err != nil {
		return err
	}
	e.st = next
	e.rebuild()
	return nil
}

func writeJSON(path string, v any) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return err
	}
	b, _ := json.MarshalIndent(v, "", "  ")
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o640); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
