package server

import (
	"bytes"
	"context"
	"log/slog"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"ariadns/internal/cache"
	"ariadns/internal/config"
	"ariadns/internal/dnsmsg"
	"ariadns/internal/rules"
	"ariadns/internal/stats"
	"ariadns/internal/upstream"
)

// liveState is everything a reload can swap atomically.
type liveState struct {
	eng     *rules.Engine
	acl     *acl
	forward map[string]*upstream.Group
}

func (s *liveState) close() {
	for _, g := range s.forward {
		g.Close()
	}
}

// Handler turns a DNS query into a response. It is transport-agnostic.
type Handler struct {
	cfg     *config.Config
	log     *slog.Logger
	cache   *cache.Cache // nil when disabled
	main    *upstream.Group
	live    atomic.Pointer[liveState]
	stats   *stats.Collector
	limiter *limiter
	flights flightGroup
	refresh sync.Map
	timeout time.Duration
}

func newLiveState(cfg *config.Config) (*liveState, error) {
	eng, err := rules.Build(cfg.Rules)
	if err != nil {
		return nil, err
	}
	a, err := newACL(cfg.Access)
	if err != nil {
		return nil, err
	}
	st := &liveState{eng: eng, acl: a, forward: map[string]*upstream.Group{}}
	for zone, specs := range eng.ForwardZones() {
		g, err := upstream.NewGroup(specs, cfg.Strategy, cfg.Timeout(), cfg.Hedge())
		if err != nil {
			st.close()
			return nil, err
		}
		st.forward[zone] = g
	}
	return st, nil
}

// NewHandler assembles a Handler from cfg. Extra upstream options (used by
// tests) apply to the main upstream group.
func NewHandler(cfg *config.Config, log *slog.Logger, col *stats.Collector, opts ...upstream.Option) (*Handler, error) {
	main, err := upstream.NewGroup(cfg.Upstreams, cfg.Strategy, cfg.Timeout(), cfg.Hedge(), opts...)
	if err != nil {
		return nil, err
	}
	live, err := newLiveState(cfg)
	if err != nil {
		main.Close()
		return nil, err
	}
	h := &Handler{
		cfg: cfg, log: log, main: main, stats: col,
		limiter: newLimiter(cfg.Access.RateLimitQPS, cfg.Access.RateBurst),
		timeout: cfg.Timeout(),
	}
	if cfg.Cache.Enabled {
		h.cache = cache.New(cache.Config{
			MaxEntries: cfg.Cache.MaxEntries,
			MinTTL:     cfg.Cache.MinTTL,
			MaxTTL:     cfg.Cache.MaxTTL,
			NegTTL:     cfg.Cache.NegativeTTL,
			StaleFor:   time.Duration(cfg.Cache.ServeStaleSecs) * time.Second,
			StaleTTL:   30,
		})
	}
	h.live.Store(live)
	return h, nil
}

// reload swaps rules, ACL and forward groups from a new configuration.
func (h *Handler) reload(cfg *config.Config) error {
	st, err := newLiveState(cfg)
	if err != nil {
		return err
	}
	if old := h.live.Swap(st); old != nil {
		// Give in-flight queries a moment before closing their pools.
		go func() {
			time.Sleep(5 * time.Second)
			old.close()
		}()
	}
	return nil
}

func (h *Handler) close() {
	h.main.Close()
	if st := h.live.Load(); st != nil {
		st.close()
	}
}

func (h *Handler) clientLabel(ip netip.Addr) string {
	ip = ip.Unmap()
	if h.cfg.Privacy.AnonymizeClientIPs {
		if ip.Is4() {
			return netip.PrefixFrom(ip, 24).Masked().Addr().String() + "/24"
		}
		return netip.PrefixFrom(ip, 48).Masked().Addr().String() + "/48"
	}
	return ip.String()
}

func (h *Handler) udpLimit(req []byte) int {
	limit := 512
	if e := dnsmsg.EDNS(req); e.Present && int(e.UDPSize) > limit {
		limit = int(e.UDPSize)
	}
	if limit > h.cfg.Limits.UDPMaxSize {
		limit = h.cfg.Limits.UDPMaxSize
	}
	return limit
}

// Handle answers one query. It returns nil when the packet should be
// dropped silently (not a query, or UDP rate limiting).
func (h *Handler) Handle(ctx context.Context, req []byte, client netip.Addr, transport string) []byte {
	start := time.Now()
	hdr, err := dnsmsg.ParseHeader(req)
	if err != nil || hdr.Response() {
		return nil
	}
	if hdr.Opcode() != 0 {
		return dnsmsg.HeaderReply(req, dnsmsg.RcodeNotImplemented)
	}
	q, _, err := dnsmsg.ParseQuestion(req)
	if err != nil {
		return dnsmsg.HeaderReply(req, dnsmsg.RcodeFormatError)
	}
	ev := stats.Event{
		Time: start, Client: h.clientLabel(client), Name: q.Name,
		QType: dnsmsg.TypeName(q.Type), Transport: transport,
	}
	finish := func(outcome string, resp []byte) []byte {
		ev.Outcome = outcome
		ev.LatencyUS = time.Since(start).Microseconds()
		if resp != nil {
			ev.Rcode = dnsmsg.RcodeName(dnsmsg.Rcode(resp))
			if transport == "udp" {
				resp = dnsmsg.Truncate(resp, h.udpLimit(req))
			}
		}
		h.stats.Record(ev)
		return resp
	}

	live := h.live.Load()
	if !live.acl.Allowed(client) {
		return finish(stats.OutRefused, dnsmsg.NewReply(req, dnsmsg.RcodeRefused))
	}
	if !h.limiter.Allow(client) {
		if transport == "udp" {
			return finish(stats.OutRateLimited, nil) // never reflect traffic at spoofed sources
		}
		return finish(stats.OutRateLimited, dnsmsg.NewReply(req, dnsmsg.RcodeRefused))
	}
	if q.Class != dnsmsg.ClassIN {
		return finish(stats.OutRefused, dnsmsg.NewReply(req, dnsmsg.RcodeRefused))
	}

	d := live.eng.Match(q.Name)
	ev.Rule = d.Rule
	switch d.Kind {
	case rules.Block:
		return finish(stats.OutBlocked, h.blockReply(live.eng, req, q))
	case rules.Local:
		return finish(stats.OutLocal, dnsmsg.AddrReply(req, q, d.IPs, live.eng.LocalTTL, true))
	}

	edns := dnsmsg.EDNS(req)
	key := cache.Key(d.Zone, q.Name, q.Type, q.Class, edns.DO)
	group := h.main
	if d.Kind == rules.Forward {
		group = live.forward[d.Zone]
	}

	if h.cache != nil {
		if cached, st := h.cache.Get(key); st != cache.Miss {
			out := h.prepare(cached, req, hdr, edns)
			if st == cache.Stale {
				h.refreshAsync(group, key, q, edns.DO)
				return finish(stats.OutStale, out)
			}
			return finish(stats.OutCache, out)
		}
	}

	resp, via, err := h.fetch(group, key, q, edns.DO)
	if err != nil {
		h.log.Debug("upstream failure", "name", q.Name, "type", ev.QType, "err", err)
		return finish(stats.OutError, dnsmsg.NewReply(req, dnsmsg.RcodeServerFailure))
	}
	ev.Upstream = via
	if h.cache != nil {
		h.cache.Put(key, resp)
	}
	return finish(stats.OutUpstream, h.prepare(resp, req, hdr, edns))
}

// prepare turns a shared/cached response into a reply for this client.
func (h *Handler) prepare(resp, req []byte, hdr dnsmsg.Header, edns dnsmsg.EDNSInfo) []byte {
	out := bytes.Clone(resp)
	dnsmsg.SetID(out, hdr.ID)
	dnsmsg.PatchFlags(out, req)
	dnsmsg.RestoreQuestion(out, req)
	if !edns.Present {
		out = dnsmsg.StripOPT(out)
	}
	return out
}

func (h *Handler) blockReply(eng *rules.Engine, req []byte, q dnsmsg.Question) []byte {
	switch eng.BlockMode {
	case "refused":
		return dnsmsg.NewReply(req, dnsmsg.RcodeRefused)
	case "null":
		return dnsmsg.AddrReply(req, q, []netip.Addr{netip.IPv4Unspecified(), netip.IPv6Unspecified()}, eng.BlockTTL, false)
	default:
		return dnsmsg.NewReply(req, dnsmsg.RcodeNameError)
	}
}

// fetch resolves a question upstream. Identical concurrent questions share
// one upstream query. The query sent upstream is rebuilt from scratch so
// client-specific EDNS options (cookies, client subnet, ...) never leak.
func (h *Handler) fetch(g *upstream.Group, key string, q dnsmsg.Question, do bool) ([]byte, string, error) {
	return h.flights.Do(key, func() ([]byte, string, error) {
		up, err := dnsmsg.NewQuery(0, q.Name, q.Type, true, do)
		if err != nil {
			return nil, "", err
		}
		ctx, cancel := context.WithTimeout(context.Background(), h.timeout+time.Second)
		defer cancel()
		return g.Exchange(ctx, up)
	})
}

// refreshAsync re-resolves an entry that was served stale.
func (h *Handler) refreshAsync(g *upstream.Group, key string, q dnsmsg.Question, do bool) {
	if _, busy := h.refresh.LoadOrStore(key, struct{}{}); busy {
		return
	}
	go func() {
		defer h.refresh.Delete(key)
		if resp, _, err := h.fetch(g, key, q, do); err == nil {
			h.cache.Put(key, resp)
		}
	}()
}

// flightGroup coalesces identical in-flight upstream queries.
type flightGroup struct {
	mu sync.Mutex
	m  map[string]*flight
}

type flight struct {
	wg   sync.WaitGroup
	resp []byte
	via  string
	err  error
}

// Do runs fn once per key at a time; concurrent callers share its result.
// Callers must treat the returned slice as read-only.
func (f *flightGroup) Do(key string, fn func() ([]byte, string, error)) ([]byte, string, error) {
	f.mu.Lock()
	if f.m == nil {
		f.m = make(map[string]*flight)
	}
	if c, ok := f.m[key]; ok {
		f.mu.Unlock()
		c.wg.Wait()
		return c.resp, c.via, c.err
	}
	c := &flight{}
	c.wg.Add(1)
	f.m[key] = c
	f.mu.Unlock()

	c.resp, c.via, c.err = fn()
	f.mu.Lock()
	delete(f.m, key)
	f.mu.Unlock()
	c.wg.Done()
	return c.resp, c.via, c.err
}
