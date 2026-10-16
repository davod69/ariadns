package server

import (
	"fmt"
	"io"
	"sort"
	"strings"

	"ariadns/internal/cache"
	"ariadns/internal/rules"
	"ariadns/internal/stats"
	"ariadns/internal/upstream"
	"ariadns/internal/version"
)

// apiStats is the JSON served at /api/stats.
type apiStats struct {
	Version   string                      `json:"version"`
	Stats     stats.Snapshot              `json:"stats"`
	Cache     *cache.Stats                `json:"cache,omitempty"`
	Upstreams []upstream.Stats            `json:"upstreams"`
	Zones     map[string][]upstream.Stats `json:"forward_zones,omitempty"`
	Rules     rules.Counts                `json:"rules"`
	Listeners map[string]string           `json:"listeners"`
	Shed      uint64                      `json:"shed"`
	QueryLog  bool                        `json:"query_log"`
}

// APIStats implements web.Provider.
func (s *Server) APIStats() any {
	live := s.h.live.Load()
	out := apiStats{
		Version:   version.Version,
		Stats:     s.st.Snapshot(),
		Upstreams: s.h.main.Stats(),
		Rules:     live.eng.Counts(),
		Listeners: s.addrs,
		Shed:      s.shed.Load(),
		QueryLog:  !s.cfg.Privacy.DisableQueryLog,
	}
	if s.h.cache != nil {
		cs := s.h.cache.Stats()
		out.Cache = &cs
	}
	if len(live.forward) > 0 {
		out.Zones = map[string][]upstream.Stats{}
		for z, g := range live.forward {
			out.Zones[z] = g.Stats()
		}
	}
	return out
}

// Recent implements web.Provider.
func (s *Server) Recent(n int) []stats.Event { return s.st.Recent(n) }

// FlushCache implements web.Provider.
func (s *Server) FlushCache() {
	if s.h.cache != nil {
		s.h.cache.Flush()
	}
}

// WriteMetrics implements web.Provider (Prometheus text exposition format).
func (s *Server) WriteMetrics(w io.Writer) {
	snap := s.st.Snapshot()
	p := func(format string, a ...any) { fmt.Fprintf(w, format, a...) }

	p("# HELP ariadns_queries_total Queries handled, by outcome.\n# TYPE ariadns_queries_total counter\n")
	for _, o := range stats.Outcomes {
		p("ariadns_queries_total{outcome=%q} %d\n", o, snap.Outcomes[o])
	}
	p("# HELP ariadns_transport_queries_total Queries handled, by transport.\n# TYPE ariadns_transport_queries_total counter\n")
	for _, t := range stats.Transports {
		p("ariadns_transport_queries_total{transport=%q} %d\n", t, snap.Transports[t])
	}

	bounds, cum, sum, count := s.st.Histogram()
	p("# HELP ariadns_query_duration_seconds Query handling latency.\n# TYPE ariadns_query_duration_seconds histogram\n")
	for i, b := range bounds {
		p("ariadns_query_duration_seconds_bucket{le=\"%g\"} %d\n", b, cum[i])
	}
	p("ariadns_query_duration_seconds_bucket{le=\"+Inf\"} %d\n", cum[len(cum)-1])
	p("ariadns_query_duration_seconds_sum %g\nariadns_query_duration_seconds_count %d\n", sum, count)

	if s.h.cache != nil {
		cs := s.h.cache.Stats()
		p("# TYPE ariadns_cache_entries gauge\nariadns_cache_entries %d\n", cs.Entries)
		p("# TYPE ariadns_cache_hits_total counter\nariadns_cache_hits_total %d\n", cs.Hits)
		p("# TYPE ariadns_cache_misses_total counter\nariadns_cache_misses_total %d\n", cs.Misses)
		p("# TYPE ariadns_cache_evictions_total counter\nariadns_cache_evictions_total %d\n", cs.Evictions)
	}

	ups := s.h.main.Stats()
	sort.Slice(ups, func(i, j int) bool { return ups[i].Name < ups[j].Name })
	p("# TYPE ariadns_upstream_queries_total counter\n# TYPE ariadns_upstream_failures_total counter\n# TYPE ariadns_upstream_up gauge\n# TYPE ariadns_upstream_rtt_seconds gauge\n")
	for _, u := range ups {
		l := fmt.Sprintf("{upstream=%q}", strings.ReplaceAll(u.Name, `"`, ""))
		up := 0
		if u.Up {
			up = 1
		}
		p("ariadns_upstream_queries_total%s %d\nariadns_upstream_failures_total%s %d\nariadns_upstream_up%s %d\nariadns_upstream_rtt_seconds%s %g\n",
			l, u.Queries, l, u.Failures, l, up, l, u.AvgRTTMS/1000)
	}
	p("# TYPE ariadns_shed_total counter\nariadns_shed_total %d\n", s.shed.Load())
	p("# TYPE ariadns_uptime_seconds gauge\nariadns_uptime_seconds %d\n", snap.UptimeSec)
}
