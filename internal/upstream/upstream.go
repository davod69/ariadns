// Package upstream talks to recursive resolvers over plain UDP/TCP,
// DNS-over-TLS and DNS-over-HTTPS, and combines several of them into a
// Group with race / hedged / failover strategies.
package upstream

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	mrand "math/rand/v2"

	"ariadns/internal/dnsmsg"
)

// Proto is the transport used to reach an upstream.
type Proto string

const (
	UDP   Proto = "udp"
	TCP   Proto = "tcp"
	TLS   Proto = "tls"
	HTTPS Proto = "https"
)

// Spec is a parsed upstream address.
type Spec struct {
	Raw        string
	Proto      Proto
	Addr       string // host:port for udp/tcp/tls
	ServerName string // TLS server name override (tls only)
	URL        string // https only
	PinIP      string // https only: dial this IP instead of resolving the host
}

// ParseSpec understands:
//
//	1.1.1.1  1.1.1.1:5353  [2606:4700::1111]:53        plain UDP (TCP on truncation)
//	tcp://1.1.1.1                                     plain TCP
//	tls://1.1.1.1:853#cloudflare-dns.com              DNS-over-TLS, optional server name
//	https://dns.google/dns-query#8.8.8.8              DNS-over-HTTPS, optional pinned IP
func ParseSpec(s string) (Spec, error) {
	raw := strings.TrimSpace(s)
	if raw == "" {
		return Spec{}, errors.New("empty upstream")
	}
	sp := Spec{Raw: raw, Proto: UDP}
	rest := raw
	if i := strings.Index(raw, "://"); i >= 0 {
		sp.Proto = Proto(strings.ToLower(raw[:i]))
		rest = raw[i+3:]
	}
	switch sp.Proto {
	case HTTPS:
		u, err := url.Parse(raw)
		if err != nil || u.Host == "" {
			return Spec{}, fmt.Errorf("upstream %q: bad https URL", raw)
		}
		sp.PinIP = u.Fragment
		u.Fragment = ""
		if u.Path == "" {
			u.Path = "/dns-query"
		}
		sp.URL = u.String()
		return sp, nil
	case UDP, TCP, TLS:
	default:
		return Spec{}, fmt.Errorf("upstream %q: unknown scheme %q", raw, sp.Proto)
	}
	if sp.Proto == TLS {
		if i := strings.IndexByte(rest, '#'); i >= 0 {
			sp.ServerName = rest[i+1:]
			rest = rest[:i]
		}
	}
	port := "53"
	if sp.Proto == TLS {
		port = "853"
	}
	addr, err := withDefaultPort(rest, port)
	if err != nil {
		return Spec{}, fmt.Errorf("upstream %q: %w", raw, err)
	}
	sp.Addr = addr
	return sp, nil
}

func withDefaultPort(addr, port string) (string, error) {
	if addr == "" {
		return "", errors.New("missing host")
	}
	if host, p, err := net.SplitHostPort(addr); err == nil {
		if host == "" {
			return "", errors.New("missing host")
		}
		if n, err := strconv.Atoi(p); err != nil || n < 1 || n > 65535 {
			return "", fmt.Errorf("bad port %q", p)
		}
		return addr, nil
	}
	return net.JoinHostPort(strings.Trim(addr, "[]"), port), nil
}

// DisplayName is safe to show in a dashboard: it never includes URL paths
// or queries, which may carry secrets.
func (s Spec) DisplayName() string {
	if s.Proto == HTTPS {
		if u, err := url.Parse(s.URL); err == nil {
			return "https://" + u.Host
		}
		return "https://?"
	}
	if s.Proto == UDP {
		return s.Addr
	}
	return string(s.Proto) + "://" + s.Addr
}

// Option customises an Upstream.
type Option func(*Upstream)

// WithInsecure disables certificate verification (tests and the query tool).
func WithInsecure() Option { return func(u *Upstream) { u.insecure = true } }

// Upstream is one resolver endpoint.
type Upstream struct {
	spec     Spec
	timeout  time.Duration
	insecure bool
	pool     *connPool
	client   *http.Client

	queries  atomic.Uint64
	failures atomic.Uint64
	consec   atomic.Int32
	rttNS    atomic.Int64 // EWMA of successful round trips
	lastErr  atomic.Pointer[string]
}

// New creates an Upstream.
func New(spec Spec, timeout time.Duration, opts ...Option) *Upstream {
	if timeout <= 0 {
		timeout = 2 * time.Second
	}
	u := &Upstream{spec: spec, timeout: timeout}
	for _, o := range opts {
		o(u)
	}
	switch spec.Proto {
	case TCP, TLS:
		u.pool = &connPool{max: 4, ttl: 20 * time.Second}
	case HTTPS:
		u.client = u.newHTTPClient()
	}
	return u
}

// Name returns the display name.
func (u *Upstream) Name() string { return u.spec.DisplayName() }

func (u *Upstream) tlsConfig(serverName string) *tls.Config {
	return &tls.Config{ServerName: serverName, MinVersion: tls.VersionTLS12, InsecureSkipVerify: u.insecure}
}

func (u *Upstream) newHTTPClient() *http.Client {
	tr := &http.Transport{
		ForceAttemptHTTP2:   true,
		TLSClientConfig:     u.tlsConfig(""),
		MaxIdleConns:        4,
		MaxIdleConnsPerHost: 4,
		IdleConnTimeout:     60 * time.Second,
		TLSHandshakeTimeout: u.timeout,
	}
	if pin := u.spec.PinIP; pin != "" {
		tr.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
			_, port, err := net.SplitHostPort(addr)
			if err != nil {
				return nil, err
			}
			d := net.Dialer{Timeout: u.timeout}
			return d.DialContext(ctx, network, net.JoinHostPort(pin, port))
		}
	}
	return &http.Client{Transport: tr}
}

// Exchange sends query q and returns the upstream's response. The query's
// transaction ID is replaced with a fresh random one on the wire; the
// response carries that wire ID and callers should SetID before relaying it.
func (u *Upstream) Exchange(ctx context.Context, q []byte) ([]byte, error) {
	if len(q) < dnsmsg.HeaderLen {
		return nil, dnsmsg.ErrShort
	}
	wire := bytes.Clone(q)
	if u.spec.Proto == HTTPS {
		dnsmsg.SetID(wire, 0) // RFC 8484: ID 0 keeps HTTP caches effective
	} else {
		dnsmsg.SetID(wire, uint16(mrand.Uint32()))
	}
	start := time.Now()
	var (
		resp []byte
		err  error
	)
	switch u.spec.Proto {
	case UDP:
		resp, err = u.exchangeUDP(ctx, wire)
	case TCP, TLS:
		resp, err = u.exchangeStream(ctx, wire)
	case HTTPS:
		resp, err = u.exchangeHTTPS(ctx, wire)
	default:
		err = fmt.Errorf("unsupported protocol %q", u.spec.Proto)
	}
	u.record(time.Since(start), err)
	return resp, err
}

func (u *Upstream) record(d time.Duration, err error) {
	if err != nil && errors.Is(err, context.Canceled) {
		return // lost a race; not the upstream's fault
	}
	u.queries.Add(1)
	if err != nil {
		u.failures.Add(1)
		u.consec.Add(1)
		msg := err.Error()
		u.lastErr.Store(&msg)
		return
	}
	u.consec.Store(0)
	old := u.rttNS.Load()
	if old == 0 {
		u.rttNS.Store(int64(d))
	} else {
		u.rttNS.Store(old*8/10 + int64(d)*2/10)
	}
}

// score orders upstreams for hedging: lower is better.
func (u *Upstream) score() time.Duration {
	return time.Duration(u.rttNS.Load()) + time.Duration(u.consec.Load())*500*time.Millisecond
}

func (u *Upstream) deadline(ctx context.Context) time.Time {
	dl := time.Now().Add(u.timeout)
	if cd, ok := ctx.Deadline(); ok && cd.Before(dl) {
		dl = cd
	}
	return dl
}

func wrapCtx(ctx context.Context, err error) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	return err
}

// matches reports whether r is a plausible answer to q (same ID and question).
func matches(q, r []byte) bool {
	if len(r) < dnsmsg.HeaderLen || r[0] != q[0] || r[1] != q[1] || r[2]&0x80 == 0 {
		return false
	}
	a, _, e1 := dnsmsg.ParseQuestion(q)
	b, _, e2 := dnsmsg.ParseQuestion(r)
	return e1 == nil && e2 == nil && a == b
}

var udpBufs = sync.Pool{New: func() any { b := make([]byte, 65535); return &b }}

func (u *Upstream) exchangeUDP(ctx context.Context, q []byte) ([]byte, error) {
	var d net.Dialer
	conn, err := d.DialContext(ctx, "udp", u.spec.Addr)
	if err != nil {
		return nil, wrapCtx(ctx, err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(u.deadline(ctx))
	stop := context.AfterFunc(ctx, func() { _ = conn.SetDeadline(time.Unix(1, 0)) })
	defer stop()

	if _, err := conn.Write(q); err != nil {
		return nil, wrapCtx(ctx, err)
	}
	bp := udpBufs.Get().(*[]byte)
	defer udpBufs.Put(bp)
	for {
		n, err := conn.Read(*bp)
		if err != nil {
			return nil, wrapCtx(ctx, err)
		}
		r := (*bp)[:n]
		if !matches(q, r) {
			continue // ignore stray or spoofed datagrams until the deadline
		}
		resp := bytes.Clone(r)
		if h, _ := dnsmsg.ParseHeader(resp); h.Truncated() {
			return u.exchangeTCPOnce(ctx, q)
		}
		return resp, nil
	}
}

// exchangeTCPOnce is the TC-bit fallback of a UDP upstream.
func (u *Upstream) exchangeTCPOnce(ctx context.Context, q []byte) ([]byte, error) {
	d := net.Dialer{Timeout: u.timeout}
	c, err := d.DialContext(ctx, "tcp", u.spec.Addr)
	if err != nil {
		return nil, wrapCtx(ctx, err)
	}
	defer c.Close()
	return streamRoundTrip(ctx, c, q, u.deadline(ctx))
}

func (u *Upstream) dialStream(ctx context.Context) (net.Conn, error) {
	d := &net.Dialer{Timeout: u.timeout}
	if u.spec.Proto == TLS {
		td := &tls.Dialer{NetDialer: d, Config: u.tlsConfig(u.spec.ServerName)}
		return td.DialContext(ctx, "tcp", u.spec.Addr)
	}
	return d.DialContext(ctx, "tcp", u.spec.Addr)
}

func (u *Upstream) exchangeStream(ctx context.Context, q []byte) ([]byte, error) {
	for {
		c := u.pool.get()
		reused := c != nil
		if c == nil {
			var err error
			if c, err = u.dialStream(ctx); err != nil {
				return nil, wrapCtx(ctx, err)
			}
		}
		resp, err := streamRoundTrip(ctx, c, q, u.deadline(ctx))
		if err == nil {
			_ = c.SetDeadline(time.Time{})
			u.pool.put(c)
			return resp, nil
		}
		_ = c.Close()
		if !reused || ctx.Err() != nil {
			return nil, wrapCtx(ctx, err) // a fresh connection failed: real error
		}
		// A pooled connection may have been closed by the server while idle;
		// retry once on a new one.
	}
}

func streamRoundTrip(ctx context.Context, c net.Conn, q []byte, deadline time.Time) ([]byte, error) {
	_ = c.SetDeadline(deadline)
	stop := context.AfterFunc(ctx, func() { _ = c.SetDeadline(time.Unix(1, 0)) })
	defer stop()

	buf := make([]byte, 2+len(q))
	binary.BigEndian.PutUint16(buf, uint16(len(q)))
	copy(buf[2:], q)
	if _, err := c.Write(buf); err != nil {
		return nil, err
	}
	var lb [2]byte
	if _, err := io.ReadFull(c, lb[:]); err != nil {
		return nil, err
	}
	n := int(binary.BigEndian.Uint16(lb[:]))
	if n < dnsmsg.HeaderLen {
		return nil, errors.New("short DNS message from upstream")
	}
	resp := make([]byte, n)
	if _, err := io.ReadFull(c, resp); err != nil {
		return nil, err
	}
	if !matches(q, resp) {
		return nil, errors.New("mismatched response from upstream")
	}
	return resp, nil
}

func (u *Upstream) exchangeHTTPS(ctx context.Context, q []byte) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u.spec.URL, bytes.NewReader(q))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/dns-message")
	req.Header.Set("Accept", "application/dns-message")
	resp, err := u.client.Do(req)
	if err != nil {
		return nil, wrapCtx(ctx, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("DoH upstream returned HTTP %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 65536))
	if err != nil {
		return nil, wrapCtx(ctx, err)
	}
	if !matches(q, body) {
		return nil, errors.New("mismatched DoH response")
	}
	return body, nil
}

// Close releases idle connections.
func (u *Upstream) Close() {
	if u.pool != nil {
		u.pool.closeAll()
	}
	if u.client != nil {
		u.client.CloseIdleConnections()
	}
}

// Stats is a dashboard-friendly view of one upstream.
type Stats struct {
	Name      string  `json:"name"`
	Queries   uint64  `json:"queries"`
	Failures  uint64  `json:"failures"`
	AvgRTTMS  float64 `json:"avg_rtt_ms"`
	Up        bool    `json:"up"`
	LastError string  `json:"last_error,omitempty"`
}

// Stats returns the current counters.
func (u *Upstream) Stats() Stats {
	s := Stats{
		Name:     u.Name(),
		Queries:  u.queries.Load(),
		Failures: u.failures.Load(),
		AvgRTTMS: float64(u.rttNS.Load()) / 1e6,
		Up:       u.consec.Load() < 3,
	}
	if p := u.lastErr.Load(); p != nil {
		s.LastError = *p
	}
	return s
}

// connPool keeps a few idle stream connections for reuse.
type connPool struct {
	mu     sync.Mutex
	idle   []idleConn
	max    int
	ttl    time.Duration
	closed bool
}

type idleConn struct {
	c  net.Conn
	at time.Time
}

func (p *connPool) get() net.Conn {
	p.mu.Lock()
	defer p.mu.Unlock()
	for len(p.idle) > 0 {
		last := p.idle[len(p.idle)-1]
		p.idle = p.idle[:len(p.idle)-1]
		if time.Since(last.at) > p.ttl {
			_ = last.c.Close()
			continue
		}
		return last.c
	}
	return nil
}

func (p *connPool) put(c net.Conn) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		_ = c.Close()
		return
	}
	for len(p.idle) > 0 && time.Since(p.idle[0].at) > p.ttl {
		_ = p.idle[0].c.Close()
		p.idle = p.idle[1:]
	}
	if len(p.idle) >= p.max {
		_ = c.Close()
		return
	}
	p.idle = append(p.idle, idleConn{c, time.Now()})
}

func (p *connPool) closeAll() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.closed = true
	for _, ic := range p.idle {
		_ = ic.c.Close()
	}
	p.idle = nil
}
