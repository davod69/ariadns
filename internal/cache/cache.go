// Package cache implements a sharded, size-bounded LRU cache of DNS
// responses with TTL countdown, negative caching and optional serve-stale.
package cache

import (
	"bytes"
	"container/list"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"ariadns/internal/dnsmsg"
)

// State is the outcome of a lookup.
type State int

const (
	Miss  State = iota
	Hit         // fresh entry
	Stale       // expired but inside the serve-stale window
)

// Config controls cache behaviour. TTLs are in seconds.
type Config struct {
	MaxEntries int
	MinTTL     uint32        // raise shorter TTLs to this (0 = off)
	MaxTTL     uint32        // cap longer TTLs (0 = no cap)
	NegTTL     uint32        // cap for negative answers (0 = no cap)
	StaleFor   time.Duration // how long past expiry an entry may still be served
	StaleTTL   uint32        // TTL advertised on stale answers
}

const numShards = 64

type entry struct {
	key    string
	msg    []byte // immutable once stored
	stored time.Time
	life   time.Duration
}

type shard struct {
	mu    sync.Mutex
	items map[string]*list.Element
	lru   *list.List
	cap   int
}

// Cache is safe for concurrent use.
type Cache struct {
	cfg    Config
	shards [numShards]shard
	now    func() time.Time

	hits, stale, misses, puts, evictions atomic.Uint64
}

// New creates a cache. A non-positive MaxEntries falls back to 10000.
func New(cfg Config) *Cache {
	if cfg.MaxEntries <= 0 {
		cfg.MaxEntries = 10000
	}
	if cfg.StaleTTL == 0 {
		cfg.StaleTTL = 30
	}
	c := &Cache{cfg: cfg, now: time.Now}
	per := cfg.MaxEntries / numShards
	if per < 1 {
		per = 1
	}
	for i := range c.shards {
		c.shards[i] = shard{items: make(map[string]*list.Element), lru: list.New(), cap: per}
	}
	return c
}

// Key builds the cache key for a question. zone separates answers obtained
// from different upstream groups.
func Key(zone, name string, qtype, qclass uint16, do bool) string {
	var b bytes.Buffer
	b.Grow(len(zone) + len(name) + 16)
	b.WriteString(zone)
	b.WriteByte('|')
	b.WriteString(name)
	b.WriteByte('|')
	b.WriteString(strconv.Itoa(int(qtype)))
	b.WriteByte('|')
	b.WriteString(strconv.Itoa(int(qclass)))
	if do {
		b.WriteString("|do")
	}
	return b.String()
}

func (c *Cache) shardFor(key string) *shard {
	h := uint32(2166136261)
	for i := 0; i < len(key); i++ {
		h ^= uint32(key[i])
		h *= 16777619
	}
	return &c.shards[h%numShards]
}

// Get returns a private copy of the cached response with TTLs counted down.
func (c *Cache) Get(key string) ([]byte, State) {
	s := c.shardFor(key)
	s.mu.Lock()
	el, ok := s.items[key]
	if !ok {
		s.mu.Unlock()
		c.misses.Add(1)
		return nil, Miss
	}
	e := el.Value.(*entry)
	elapsed := c.now().Sub(e.stored)
	if elapsed >= e.life {
		if c.cfg.StaleFor <= 0 || elapsed >= e.life+c.cfg.StaleFor {
			s.lru.Remove(el)
			delete(s.items, key)
			s.mu.Unlock()
			c.misses.Add(1)
			return nil, Miss
		}
		s.lru.MoveToFront(el)
		msg := e.msg
		s.mu.Unlock()
		out := bytes.Clone(msg)
		staleTTL := c.cfg.StaleTTL
		_ = dnsmsg.MapTTLs(out, func(_ uint16, _ uint32) uint32 { return staleTTL })
		c.stale.Add(1)
		return out, Stale
	}
	s.lru.MoveToFront(el)
	msg, life := e.msg, e.life
	s.mu.Unlock()

	remaining := uint32((life - elapsed) / time.Second)
	if remaining < 1 {
		remaining = 1
	}
	out := bytes.Clone(msg)
	_ = dnsmsg.MapTTLs(out, func(_ uint16, ttl uint32) uint32 {
		if ttl > remaining {
			return remaining
		}
		return ttl
	})
	c.hits.Add(1)
	return out, Hit
}

// Put stores resp if it is cacheable and reports whether it did.
func (c *Cache) Put(key string, resp []byte) bool {
	ttl, ok := c.ttlFor(resp)
	if !ok {
		return false
	}
	e := &entry{key: key, msg: bytes.Clone(resp), stored: c.now(), life: time.Duration(ttl) * time.Second}
	s := c.shardFor(key)
	s.mu.Lock()
	if el, ok := s.items[key]; ok {
		el.Value = e
		s.lru.MoveToFront(el)
	} else {
		s.items[key] = s.lru.PushFront(e)
		for s.lru.Len() > s.cap {
			back := s.lru.Back()
			s.lru.Remove(back)
			delete(s.items, back.Value.(*entry).key)
			c.evictions.Add(1)
		}
	}
	s.mu.Unlock()
	c.puts.Add(1)
	return true
}

// ttlFor decides whether resp may be cached and for how many seconds.
func (c *Cache) ttlFor(resp []byte) (uint32, bool) {
	h, err := dnsmsg.ParseHeader(resp)
	if err != nil || !h.Response() || h.Truncated() {
		return 0, false
	}
	if rc := h.Rcode(); rc != dnsmsg.RcodeSuccess && rc != dnsmsg.RcodeNameError {
		return 0, false
	}
	rrs, err := dnsmsg.WalkRRs(resp)
	if err != nil {
		return 0, false
	}
	var ttl uint32
	haveTTL := false
	if h.ANCount > 0 {
		for _, rr := range rrs {
			if rr.Section == dnsmsg.SectionAnswer && (!haveTTL || rr.TTL < ttl) {
				ttl, haveTTL = rr.TTL, true
			}
		}
	} else {
		// Negative answer: RFC 2308 says use the SOA, otherwise do not cache.
		for _, rr := range rrs {
			if rr.Section == dnsmsg.SectionAuthority && rr.Type == dnsmsg.TypeSOA {
				t := rr.TTL
				if m, ok := dnsmsg.SOAMinimum(resp, rr); ok && m < t {
					t = m
				}
				if !haveTTL || t < ttl {
					ttl, haveTTL = t, true
				}
			}
		}
		if haveTTL && c.cfg.NegTTL > 0 && ttl > c.cfg.NegTTL {
			ttl = c.cfg.NegTTL
		}
	}
	if !haveTTL {
		return 0, false
	}
	if c.cfg.MaxTTL > 0 && ttl > c.cfg.MaxTTL {
		ttl = c.cfg.MaxTTL
	}
	if ttl < c.cfg.MinTTL {
		ttl = c.cfg.MinTTL
	}
	return ttl, ttl > 0
}

// Flush removes every entry.
func (c *Cache) Flush() {
	for i := range c.shards {
		s := &c.shards[i]
		s.mu.Lock()
		s.items = make(map[string]*list.Element)
		s.lru.Init()
		s.mu.Unlock()
	}
}

// Len returns the number of stored entries.
func (c *Cache) Len() int {
	n := 0
	for i := range c.shards {
		s := &c.shards[i]
		s.mu.Lock()
		n += s.lru.Len()
		s.mu.Unlock()
	}
	return n
}

// Stats is a point-in-time copy of the counters.
type Stats struct {
	Entries   int    `json:"entries"`
	Hits      uint64 `json:"hits"`
	Stale     uint64 `json:"stale"`
	Misses    uint64 `json:"misses"`
	Puts      uint64 `json:"puts"`
	Evictions uint64 `json:"evictions"`
}

// Stats returns the current counters.
func (c *Cache) Stats() Stats {
	return Stats{
		Entries: c.Len(), Hits: c.hits.Load(), Stale: c.stale.Load(),
		Misses: c.misses.Load(), Puts: c.puts.Load(), Evictions: c.evictions.Load(),
	}
}
