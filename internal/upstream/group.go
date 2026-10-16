package upstream

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"time"

	"ariadns/internal/dnsmsg"
)

// Strategies understood by NewGroup.
const (
	StrategyRace     = "race"     // ask every upstream at once, first good answer wins
	StrategyFastest  = "fastest"  // ask the best-scoring one, hedge to the next after a short delay
	StrategyFailover = "failover" // ask in configured order, move on only on failure
)

// Group is a set of upstreams used together.
type Group struct {
	ups      []*Upstream
	strategy string
	timeout  time.Duration
	hedge    time.Duration
}

// NewGroup builds a group from upstream specs.
func NewGroup(specs []string, strategy string, timeout, hedge time.Duration, opts ...Option) (*Group, error) {
	switch strategy {
	case StrategyRace, StrategyFastest, StrategyFailover:
	case "":
		strategy = StrategyFastest
	default:
		return nil, fmt.Errorf("unknown strategy %q (want race, fastest or failover)", strategy)
	}
	if len(specs) == 0 {
		return nil, errors.New("at least one upstream is required")
	}
	g := &Group{strategy: strategy, timeout: timeout, hedge: hedge}
	for _, s := range specs {
		sp, err := ParseSpec(s)
		if err != nil {
			g.Close()
			return nil, err
		}
		g.ups = append(g.ups, New(sp, timeout, opts...))
	}
	return g, nil
}

// usable reports whether a response is a definitive answer worth returning
// right away (as opposed to SERVFAIL/REFUSED, which another upstream may fix).
func usable(resp []byte) bool {
	rc := dnsmsg.Rcode(resp)
	return rc == dnsmsg.RcodeSuccess || rc == dnsmsg.RcodeNameError
}

// Exchange resolves q and returns the response and the name of the
// upstream that produced it.
func (g *Group) Exchange(ctx context.Context, q []byte) ([]byte, string, error) {
	switch g.strategy {
	case StrategyFailover:
		return g.failover(ctx, q)
	case StrategyRace:
		return g.parallel(ctx, q, g.ups, 0)
	default:
		ordered := append([]*Upstream(nil), g.ups...)
		sort.SliceStable(ordered, func(i, j int) bool { return ordered[i].score() < ordered[j].score() })
		return g.parallel(ctx, q, ordered, g.hedge)
	}
}

type result struct {
	resp []byte
	u    *Upstream
	err  error
}

// parallel starts upstream i after i*stagger and returns the first usable
// answer. With stagger 0 this is a plain race.
func (g *Group) parallel(ctx context.Context, q []byte, ups []*Upstream, stagger time.Duration) ([]byte, string, error) {
	ctx, cancel := context.WithTimeout(ctx, g.timeout)
	defer cancel()
	ch := make(chan result, len(ups))
	for i, u := range ups {
		go func(i int, u *Upstream) {
			if d := time.Duration(i) * stagger; d > 0 {
				t := time.NewTimer(d)
				select {
				case <-t.C:
				case <-ctx.Done():
					t.Stop()
					ch <- result{u: u, err: ctx.Err()}
					return
				}
			}
			resp, err := u.Exchange(ctx, q)
			ch <- result{resp, u, err}
		}(i, u)
	}
	var fallback *result
	var lastErr error
	for range ups {
		r := <-ch
		switch {
		case r.err != nil:
			lastErr = r.err
		case usable(r.resp):
			return r.resp, r.u.Name(), nil
		case fallback == nil:
			rc := r
			fallback = &rc
		}
	}
	if fallback != nil {
		return fallback.resp, fallback.u.Name(), nil
	}
	return nil, "", lastErr
}

func (g *Group) failover(ctx context.Context, q []byte) ([]byte, string, error) {
	var fallback *result
	var lastErr error
	for _, u := range g.ups {
		if ctx.Err() != nil {
			return nil, "", ctx.Err()
		}
		actx, cancel := context.WithTimeout(ctx, g.timeout)
		resp, err := u.Exchange(actx, q)
		cancel()
		switch {
		case err != nil:
			lastErr = err
		case usable(resp):
			return resp, u.Name(), nil
		case fallback == nil:
			fallback = &result{resp, u, nil}
		}
	}
	if fallback != nil {
		return fallback.resp, fallback.u.Name(), nil
	}
	return nil, "", lastErr
}

// Stats returns per-upstream counters in configured order.
func (g *Group) Stats() []Stats {
	out := make([]Stats, len(g.ups))
	for i, u := range g.ups {
		out[i] = u.Stats()
	}
	return out
}

// Close releases pooled connections.
func (g *Group) Close() {
	for _, u := range g.ups {
		u.Close()
	}
}
