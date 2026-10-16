package server

import (
	"net/netip"
	"sync"
	"time"

	"ariadns/internal/config"
)

// acl is an immutable client allow-list. Loopback is always allowed so an
// operator can never lock themselves out of local diagnostics.
type acl struct {
	allowAll bool
	prefixes []netip.Prefix
}

func newACL(c config.AccessConfig) (*acl, error) {
	a := &acl{allowAll: c.AllowAll}
	for _, s := range c.Allow {
		p, err := config.ParseAllow(s)
		if err != nil {
			return nil, err
		}
		a.prefixes = append(a.prefixes, p.Masked())
	}
	return a, nil
}

func (a *acl) Allowed(ip netip.Addr) bool {
	if a.allowAll || ip.IsLoopback() {
		return true
	}
	ip = ip.Unmap()
	for _, p := range a.prefixes {
		if p.Contains(ip) {
			return true
		}
	}
	return false
}

// limiter is a per-client token bucket. IPv6 clients are tracked by /64.
type limiter struct {
	rate   float64
	burst  float64
	shards [32]limShard
}

type limShard struct {
	mu sync.Mutex
	m  map[netip.Addr]*bucket
}

type bucket struct {
	tokens float64
	last   time.Time
}

func newLimiter(qps float64, burst int) *limiter {
	l := &limiter{rate: qps, burst: float64(burst)}
	for i := range l.shards {
		l.shards[i].m = make(map[netip.Addr]*bucket)
	}
	return l
}

func limiterKey(ip netip.Addr) netip.Addr {
	ip = ip.Unmap()
	if ip.Is6() {
		return netip.PrefixFrom(ip, 64).Masked().Addr()
	}
	return ip
}

// Allow consumes one token for ip and reports whether the query may proceed.
func (l *limiter) Allow(ip netip.Addr) bool {
	if l == nil || l.rate <= 0 {
		return true
	}
	k := limiterKey(ip)
	b := k.As16()
	s := &l.shards[(uint(b[15])^uint(b[14])*31)%uint(len(l.shards))]
	now := time.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	bk, ok := s.m[k]
	if !ok {
		s.m[k] = &bucket{tokens: l.burst - 1, last: now}
		return true
	}
	bk.tokens += now.Sub(bk.last).Seconds() * l.rate
	if bk.tokens > l.burst {
		bk.tokens = l.burst
	}
	bk.last = now
	if bk.tokens < 1 {
		return false
	}
	bk.tokens--
	return true
}

// sweep drops buckets that have been idle long enough to be full again.
func (l *limiter) sweep() {
	if l == nil {
		return
	}
	cutoff := time.Now().Add(-time.Minute)
	for i := range l.shards {
		s := &l.shards[i]
		s.mu.Lock()
		for k, b := range s.m {
			if b.last.Before(cutoff) {
				delete(s.m, k)
			}
		}
		s.mu.Unlock()
	}
}
