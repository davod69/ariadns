// Package stats collects counters, a latency histogram, a per-second query
// series, top-N lists and a bounded in-memory query log. Nothing is ever
// written to disk.
package stats

import (
	"context"
	"sort"
	"sync"
	"sync/atomic"
	"time"
)

// Outcomes of a query.
const (
	OutUpstream    = "upstream"
	OutCache       = "cache"
	OutStale       = "stale"
	OutBlocked     = "blocked"
	OutLocal       = "local"
	OutRefused     = "refused"
	OutRateLimited = "ratelimited"
	OutError       = "error"
)

// Outcomes lists every outcome in display order.
var Outcomes = []string{OutUpstream, OutCache, OutStale, OutBlocked, OutLocal, OutRefused, OutRateLimited, OutError}

// Transports lists every transport in display order.
var Transports = []string{"udp", "tcp", "dot", "doh"}

// latBoundsUS are the histogram bucket upper bounds in microseconds.
var latBoundsUS = []int64{250, 500, 1000, 2000, 5000, 10000, 20000, 50000, 100000, 250000, 500000, 1000000, 2000000}

const (
	qpsWindow = 120
	topCap    = 4096
)

// Event is one handled query.
type Event struct {
	Time      time.Time `json:"time"`
	Client    string    `json:"client"`
	Name      string    `json:"name"`
	QType     string    `json:"qtype"`
	Transport string    `json:"transport"`
	Outcome   string    `json:"outcome"`
	Rcode     string    `json:"rcode"`
	LatencyUS int64     `json:"latency_us"`
	Upstream  string    `json:"upstream,omitempty"`
	Rule      string    `json:"rule,omitempty"`
}

// Options configure a Collector.
type Options struct {
	QueryLog bool // keep the recent-query ring and top-N lists
	RingSize int
}

// Collector is safe for concurrent use.
type Collector struct {
	opt   Options
	start time.Time

	total     atomic.Uint64
	outcome   [8]atomic.Uint64
	transport [4]atomic.Uint64
	lat       [14]atomic.Uint64
	latSumUS  atomic.Uint64
	latCount  atomic.Uint64
	cur       atomic.Uint64

	mu      sync.Mutex
	ring    []Event
	pos     int
	full    bool
	domains map[string]uint64
	blocked map[string]uint64
	clients map[string]uint64
	window  time.Time
	qps     [qpsWindow]uint64
	qpsPos  int
}

// New creates a Collector.
func New(opt Options) *Collector {
	if opt.RingSize <= 0 {
		opt.RingSize = 500
	}
	c := &Collector{
		opt: opt, start: time.Now(), window: time.Now(),
		domains: map[string]uint64{}, blocked: map[string]uint64{}, clients: map[string]uint64{},
	}
	if opt.QueryLog {
		c.ring = make([]Event, opt.RingSize)
	}
	return c
}

// Start runs the once-a-second ticker that feeds the QPS series.
func (c *Collector) Start(ctx context.Context) {
	go func() {
		t := time.NewTicker(time.Second)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				v := c.cur.Swap(0)
				c.mu.Lock()
				c.qps[c.qpsPos] = v
				c.qpsPos = (c.qpsPos + 1) % qpsWindow
				c.mu.Unlock()
			}
		}
	}()
}

func index(list []string, s string) int {
	for i, v := range list {
		if v == s {
			return i
		}
	}
	return -1
}

func bump(m map[string]uint64, k string) {
	if _, ok := m[k]; ok || len(m) < topCap {
		m[k]++
	}
}

// Record accounts for one handled query.
func (c *Collector) Record(ev Event) {
	c.total.Add(1)
	c.cur.Add(1)
	if i := index(Outcomes, ev.Outcome); i >= 0 {
		c.outcome[i].Add(1)
	}
	if i := index(Transports, ev.Transport); i >= 0 {
		c.transport[i].Add(1)
	}
	b := len(latBoundsUS)
	for i, ub := range latBoundsUS {
		if ev.LatencyUS <= ub {
			b = i
			break
		}
	}
	c.lat[b].Add(1)
	c.latSumUS.Add(uint64(ev.LatencyUS))
	c.latCount.Add(1)

	if !c.opt.QueryLog {
		return
	}
	c.mu.Lock()
	if time.Since(c.window) > time.Hour {
		c.domains, c.blocked, c.clients = map[string]uint64{}, map[string]uint64{}, map[string]uint64{}
		c.window = time.Now()
	}
	c.ring[c.pos] = ev
	c.pos = (c.pos + 1) % len(c.ring)
	if c.pos == 0 {
		c.full = true
	}
	if ev.Outcome == OutBlocked {
		bump(c.blocked, ev.Name)
	} else {
		bump(c.domains, ev.Name)
	}
	bump(c.clients, ev.Client)
	c.mu.Unlock()
}

// Recent returns up to n most recent events, newest first.
func (c *Collector) Recent(n int) []Event {
	if !c.opt.QueryLog || n <= 0 {
		return []Event{}
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	size := c.pos
	if c.full {
		size = len(c.ring)
	}
	if n > size {
		n = size
	}
	out := make([]Event, 0, n)
	for i := 1; i <= n; i++ {
		out = append(out, c.ring[(c.pos-i+len(c.ring))%len(c.ring)])
	}
	return out
}

// Count is a name with a number.
type Count struct {
	Name  string `json:"name"`
	Count uint64 `json:"count"`
}

// Snapshot is a JSON-friendly copy of the collector's state.
type Snapshot struct {
	UptimeSec    int64             `json:"uptime_sec"`
	Total        uint64            `json:"total"`
	Outcomes     map[string]uint64 `json:"outcomes"`
	Transports   map[string]uint64 `json:"transports"`
	LatencyAvgMS float64           `json:"latency_avg_ms"`
	LatencyP50MS float64           `json:"latency_p50_ms"`
	LatencyP95MS float64           `json:"latency_p95_ms"`
	QPS          []uint64          `json:"qps"` // last 120 seconds, oldest first
	TopDomains   []Count           `json:"top_domains"`
	TopBlocked   []Count           `json:"top_blocked"`
	TopClients   []Count           `json:"top_clients"`
}

func top(m map[string]uint64, n int) []Count {
	out := make([]Count, 0, len(m))
	for k, v := range m {
		out = append(out, Count{k, v})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Count != out[j].Count {
			return out[i].Count > out[j].Count
		}
		return out[i].Name < out[j].Name
	})
	if len(out) > n {
		out = out[:n]
	}
	return out
}

func (c *Collector) quantileMS(q float64) float64 {
	n := c.latCount.Load()
	if n == 0 {
		return 0
	}
	target := uint64(float64(n)*q + 0.5)
	if target < 1 {
		target = 1
	}
	var acc uint64
	for i := range c.lat {
		acc += c.lat[i].Load()
		if acc >= target {
			if i < len(latBoundsUS) {
				return float64(latBoundsUS[i]) / 1000
			}
			return float64(latBoundsUS[len(latBoundsUS)-1]) / 1000
		}
	}
	return 0
}

// Snapshot returns the current state.
func (c *Collector) Snapshot() Snapshot {
	s := Snapshot{
		UptimeSec:  int64(time.Since(c.start).Seconds()),
		Total:      c.total.Load(),
		Outcomes:   map[string]uint64{},
		Transports: map[string]uint64{},
	}
	for i, n := range Outcomes {
		s.Outcomes[n] = c.outcome[i].Load()
	}
	for i, n := range Transports {
		s.Transports[n] = c.transport[i].Load()
	}
	if n := c.latCount.Load(); n > 0 {
		s.LatencyAvgMS = float64(c.latSumUS.Load()) / float64(n) / 1000
	}
	s.LatencyP50MS = c.quantileMS(0.50)
	s.LatencyP95MS = c.quantileMS(0.95)

	c.mu.Lock()
	s.QPS = make([]uint64, qpsWindow)
	for i := 0; i < qpsWindow; i++ {
		s.QPS[i] = c.qps[(c.qpsPos+i)%qpsWindow]
	}
	s.TopDomains = top(c.domains, 10)
	s.TopBlocked = top(c.blocked, 10)
	s.TopClients = top(c.clients, 10)
	c.mu.Unlock()
	return s
}

// Histogram returns cumulative bucket counts for Prometheus: upper bounds
// in seconds (excluding +Inf), cumulative counts (including +Inf as the
// last element), the sum in seconds and the total count.
func (c *Collector) Histogram() (bounds []float64, cum []uint64, sum float64, count uint64) {
	bounds = make([]float64, len(latBoundsUS))
	for i, b := range latBoundsUS {
		bounds[i] = float64(b) / 1e6
	}
	cum = make([]uint64, len(c.lat))
	var acc uint64
	for i := range c.lat {
		acc += c.lat[i].Load()
		cum[i] = acc
	}
	return bounds, cum, float64(c.latSumUS.Load()) / 1e6, c.latCount.Load()
}
