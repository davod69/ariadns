// Package subs stores subscribers: people allowed to use the server from one
// IP address, with an optional traffic quota and expiry date.
package subs

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"sync/atomic"
	"time"
)

// Sub is the persisted record.
type Sub struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	IP         string `json:"ip"` // empty until the user binds one
	Token      string `json:"token"`
	LimitBytes int64  `json:"limit_bytes"` // 0 = unlimited
	UsedBytes  int64  `json:"used_bytes"`
	ExpiresAt  int64  `json:"expires_at"` // unix seconds, 0 = never
	Enabled    bool   `json:"enabled"`
	SelfRebind bool   `json:"self_rebind"` // may the user change IP via the portal
	LastRebind int64  `json:"last_rebind"`
	CreatedAt  int64  `json:"created_at"`
}

// View is a Sub with live status for APIs.
type View struct {
	Sub
	Status string `json:"status"` // active | disabled | expired | over_quota | unbound
}

type entry struct {
	id      string
	used    atomic.Int64
	limit   int64
	expires int64
	enabled bool
}

var (
	ErrNotFound = errors.New("subscriber not found")
	ErrIPInUse  = errors.New("that IP already belongs to another subscriber")
	ErrCooldown = errors.New("IP was changed recently, try again later")
	ErrDisabled = errors.New("self-service IP change is disabled for this account")
)

// RebindCooldown limits self-service IP changes.
const RebindCooldown = 10 * time.Minute

// Store is safe for concurrent use.
type Store struct {
	path  string
	mu    sync.Mutex
	subs  map[string]*Sub
	live  map[string]*entry // by id
	byIP  atomic.Pointer[map[netip.Addr]*entry]
	dirty atomic.Bool
	stop  chan struct{}
	now   func() time.Time
}

// Open loads the store and starts a background flusher for traffic counters.
func Open(path string) (*Store, error) {
	s := &Store{path: path, subs: map[string]*Sub{}, live: map[string]*entry{}, stop: make(chan struct{}), now: time.Now}
	data, err := os.ReadFile(path)
	if err == nil {
		var list []*Sub
		if err := json.Unmarshal(data, &list); err != nil {
			return nil, err
		}
		for _, x := range list {
			s.subs[x.ID] = x
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	for _, x := range s.subs {
		e := &entry{id: x.ID}
		e.used.Store(x.UsedBytes)
		s.live[x.ID] = e
	}
	s.reindex()
	go s.flusher()
	return s, nil
}

func (s *Store) flusher() {
	t := time.NewTicker(30 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-s.stop:
			return
		case <-t.C:
			if s.dirty.Swap(false) {
				s.mu.Lock()
				_ = s.saveLocked()
				s.mu.Unlock()
			}
		}
	}
}

// Close flushes counters and stops the background goroutine.
func (s *Store) Close() {
	select {
	case <-s.stop:
		return
	default:
		close(s.stop)
	}
	s.mu.Lock()
	_ = s.saveLocked()
	s.mu.Unlock()
}

func (s *Store) reindex() {
	m := map[netip.Addr]*entry{}
	for id, x := range s.subs {
		e := s.live[id]
		e.limit, e.expires, e.enabled = x.LimitBytes, x.ExpiresAt, x.Enabled
		if ip, err := netip.ParseAddr(x.IP); err == nil {
			m[ip.Unmap()] = e
		}
	}
	s.byIP.Store(&m)
}

func (s *Store) saveLocked() error {
	list := make([]*Sub, 0, len(s.subs))
	for id, x := range s.subs {
		x.UsedBytes = s.live[id].used.Load()
		list = append(list, x)
	}
	sort.Slice(list, func(i, j int) bool { return list[i].CreatedAt < list[j].CreatedAt })
	if err := os.MkdirAll(filepath.Dir(s.path), 0o750); err != nil {
		return err
	}
	b, _ := json.MarshalIndent(list, "", "  ")
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, s.path)
}

func (e *entry) usable(now int64) bool {
	if !e.enabled || (e.expires != 0 && now >= e.expires) {
		return false
	}
	return e.limit == 0 || e.used.Load() < e.limit
}

// Allowed reports whether ip belongs to an active subscriber.
func (s *Store) Allowed(ip netip.Addr) bool {
	e := (*s.byIP.Load())[ip.Unmap()]
	return e != nil && e.usable(s.now().Unix())
}

// AddTraffic charges n bytes to the subscriber that owns ip.
func (s *Store) AddTraffic(ip netip.Addr, n int64) {
	if e := (*s.byIP.Load())[ip.Unmap()]; e != nil {
		e.used.Add(n)
		s.dirty.Store(true)
	}
}

func (s *Store) status(x *Sub) string {
	e := s.live[x.ID]
	switch {
	case !x.Enabled:
		return "disabled"
	case x.IP == "":
		return "unbound"
	case x.ExpiresAt != 0 && s.now().Unix() >= x.ExpiresAt:
		return "expired"
	case x.LimitBytes != 0 && e.used.Load() >= x.LimitBytes:
		return "over_quota"
	}
	return "active"
}

func (s *Store) view(x *Sub) View {
	v := View{Sub: *x, Status: s.status(x)}
	v.UsedBytes = s.live[x.ID].used.Load()
	return v
}

// List returns all subscribers, oldest first.
func (s *Store) List() []View {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]View, 0, len(s.subs))
	for _, x := range s.subs {
		out = append(out, s.view(x))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt < out[j].CreatedAt })
	return out
}

func randToken(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

func (s *Store) ipFree(ip, exceptID string) error {
	if ip == "" {
		return nil
	}
	a, err := netip.ParseAddr(ip)
	if err != nil {
		return errors.New("invalid IP address")
	}
	for id, x := range s.subs {
		if id == exceptID || x.IP == "" {
			continue
		}
		if b, _ := netip.ParseAddr(x.IP); b.Unmap() == a.Unmap() {
			return ErrIPInUse
		}
	}
	return nil
}

// NewSub is the input for Add.
type NewSub struct {
	Name       string
	IP         string
	LimitBytes int64
	Days       int // 0 = never expires
	SelfRebind bool
}

func (s *Store) Add(in NewSub) (View, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(in.Name) == 0 || len(in.Name) > 64 {
		return View{}, errors.New("name must be 1-64 characters")
	}
	if in.LimitBytes < 0 || in.Days < 0 {
		return View{}, errors.New("limit and days must not be negative")
	}
	if err := s.ipFree(in.IP, ""); err != nil {
		return View{}, err
	}
	if in.IP != "" {
		a, _ := netip.ParseAddr(in.IP)
		in.IP = a.Unmap().String()
	}
	idb := make([]byte, 4)
	_, _ = rand.Read(idb)
	x := &Sub{
		ID: hex.EncodeToString(idb), Name: in.Name, IP: in.IP, Token: randToken(24),
		LimitBytes: in.LimitBytes, Enabled: true, SelfRebind: in.SelfRebind, CreatedAt: s.now().Unix(),
	}
	if in.Days > 0 {
		x.ExpiresAt = s.now().Add(time.Duration(in.Days) * 24 * time.Hour).Unix()
	}
	s.subs[x.ID] = x
	s.live[x.ID] = &entry{id: x.ID}
	s.reindex()
	if err := s.saveLocked(); err != nil {
		return View{}, err
	}
	return s.view(x), nil
}

// Patch lists the fields Update may change; nil means "leave as is".
type Patch struct {
	Name       *string
	IP         *string
	LimitBytes *int64
	ExpiresAt  *int64
	Enabled    *bool
	SelfRebind *bool
	ResetUsed  bool
}

func (s *Store) Update(id string, p Patch) (View, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	x := s.subs[id]
	if x == nil {
		return View{}, ErrNotFound
	}
	if p.IP != nil {
		ip := *p.IP
		if err := s.ipFree(ip, id); err != nil {
			return View{}, err
		}
		if ip != "" {
			a, _ := netip.ParseAddr(ip)
			ip = a.Unmap().String()
		}
		x.IP = ip
	}
	if p.Name != nil {
		if len(*p.Name) == 0 || len(*p.Name) > 64 {
			return View{}, errors.New("name must be 1-64 characters")
		}
		x.Name = *p.Name
	}
	if p.LimitBytes != nil {
		if *p.LimitBytes < 0 {
			return View{}, errors.New("limit must not be negative")
		}
		x.LimitBytes = *p.LimitBytes
	}
	if p.ExpiresAt != nil {
		x.ExpiresAt = *p.ExpiresAt
	}
	if p.Enabled != nil {
		x.Enabled = *p.Enabled
	}
	if p.SelfRebind != nil {
		x.SelfRebind = *p.SelfRebind
	}
	if p.ResetUsed {
		s.live[id].used.Store(0)
	}
	s.reindex()
	if err := s.saveLocked(); err != nil {
		return View{}, err
	}
	return s.view(x), nil
}

func (s *Store) Delete(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.subs[id] == nil {
		return ErrNotFound
	}
	delete(s.subs, id)
	delete(s.live, id)
	s.reindex()
	return s.saveLocked()
}

// ByToken returns the subscriber for a portal token.
func (s *Store) ByToken(token string) (View, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, x := range s.subs {
		if len(token) == len(x.Token) && token == x.Token {
			return s.view(x), true
		}
	}
	return View{}, false
}

// Rebind lets a subscriber move their account to the IP they are connecting
// from, using the secret portal token.
func (s *Store) Rebind(token string, ip netip.Addr) (View, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var x *Sub
	for _, c := range s.subs {
		if len(token) == len(c.Token) && token == c.Token {
			x = c
		}
	}
	if x == nil {
		return View{}, ErrNotFound
	}
	if !x.SelfRebind {
		return View{}, ErrDisabled
	}
	ip = ip.Unmap()
	if x.IP == ip.String() {
		return s.view(x), nil
	}
	if x.IP != "" && s.now().Unix()-x.LastRebind < int64(RebindCooldown/time.Second) {
		return View{}, ErrCooldown
	}
	if err := s.ipFree(ip.String(), x.ID); err != nil {
		return View{}, err
	}
	x.IP, x.LastRebind = ip.String(), s.now().Unix()
	s.reindex()
	if err := s.saveLocked(); err != nil {
		return View{}, err
	}
	return s.view(x), nil
}
