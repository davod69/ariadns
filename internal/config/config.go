// Package config loads and validates the JSON configuration.
package config

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"os"
	"strings"
	"time"

	"ariadns/internal/rules"
)

type ListenConfig struct {
	UDP string `json:"udp"` // "" disables
	TCP string `json:"tcp"`
	DoT string `json:"dot"`
	DoH string `json:"doh"`
}

type TLSConfig struct {
	CertFile   string   `json:"cert_file"`
	KeyFile    string   `json:"key_file"`
	SelfSigned bool     `json:"self_signed"` // generate an ephemeral certificate (testing only)
	Hosts      []string `json:"hosts"`       // names/IPs for the self-signed certificate
}

type DoHConfig struct {
	Path              string `json:"path"`
	InsecureHTTP      bool   `json:"insecure_http"`       // plain HTTP, for use behind a TLS-terminating proxy
	TrustProxyHeaders bool   `json:"trust_proxy_headers"` // take the client IP from X-Forwarded-For
}

type CacheConfig struct {
	Enabled        bool   `json:"enabled"`
	MaxEntries     int    `json:"max_entries"`
	MinTTL         uint32 `json:"min_ttl"`
	MaxTTL         uint32 `json:"max_ttl"`
	NegativeTTL    uint32 `json:"negative_ttl"`     // cap for NXDOMAIN/NODATA
	ServeStaleSecs int    `json:"serve_stale_secs"` // 0 disables serve-stale
}

type AccessConfig struct {
	Allow        []string `json:"allow"`          // CIDRs or IPs; loopback is always allowed
	AllowAll     bool     `json:"allow_all"`      // explicitly run as an open resolver
	RateLimitQPS float64  `json:"rate_limit_qps"` // per client, 0 disables
	RateBurst    int      `json:"rate_burst"`
}

type LimitsConfig struct {
	MaxInflight int `json:"max_inflight"` // concurrent UDP queries
	MaxTCPConns int `json:"max_tcp_conns"`
	UDPMaxSize  int `json:"udp_max_size"`
	TCPIdleSecs int `json:"tcp_idle_secs"`
	DoTIdleSecs int `json:"dot_idle_secs"`
}

type WebConfig struct {
	Listen string `json:"listen"` // "" disables
	Token  string `json:"token"`  // required when not bound to loopback
}

type PrivacyConfig struct {
	AnonymizeClientIPs bool `json:"anonymize_client_ips"`
	DisableQueryLog    bool `json:"disable_query_log"`
}

type LogConfig struct {
	Level  string `json:"level"`  // debug | info | warn | error
	Format string `json:"format"` // text | json
}

// Config is the whole configuration file.
type Config struct {
	Listen    ListenConfig  `json:"listen"`
	TLS       TLSConfig     `json:"tls"`
	DoH       DoHConfig     `json:"doh"`
	Upstreams []string      `json:"upstreams"`
	Strategy  string        `json:"strategy"`   // fastest | race | failover
	TimeoutMS int           `json:"timeout_ms"` // per upstream query
	HedgeMS   int           `json:"hedge_ms"`   // delay before asking the next upstream (fastest)
	Cache     CacheConfig   `json:"cache"`
	Rules     rules.Config  `json:"rules"`
	Access    AccessConfig  `json:"access"`
	Limits    LimitsConfig  `json:"limits"`
	Web       WebConfig     `json:"web"`
	Privacy   PrivacyConfig `json:"privacy"`
	Log       LogConfig     `json:"log"`
}

// Default returns a safe configuration: loopback only, encrypted upstreams.
func Default() *Config {
	return &Config{
		Listen: ListenConfig{UDP: "127.0.0.1:5353", TCP: "127.0.0.1:5353"},
		DoH:    DoHConfig{Path: "/dns-query"},
		Upstreams: []string{
			"tls://1.1.1.1:853#cloudflare-dns.com",
			"tls://9.9.9.9:853#dns.quad9.net",
		},
		Strategy:  "fastest",
		TimeoutMS: 2000,
		HedgeMS:   80,
		Cache:     CacheConfig{Enabled: true, MaxEntries: 100000, MaxTTL: 86400, NegativeTTL: 300},
		Rules:     rules.Config{BlockMode: "nxdomain", BlockTTL: 60, LocalTTL: 60},
		Access:    AccessConfig{RateLimitQPS: 100, RateBurst: 200},
		Limits:    LimitsConfig{MaxInflight: 4096, MaxTCPConns: 512, UDPMaxSize: 1232, TCPIdleSecs: 10, DoTIdleSecs: 60},
		Web:       WebConfig{Listen: "127.0.0.1:8080"},
		Log:       LogConfig{Level: "info", Format: "text"},
	}
}

// Load reads path (strict: unknown fields are errors), applies environment
// overrides and validates the result.
func Load(path string) (*Config, error) {
	cfg := Default()
	if path != "" {
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		dec := json.NewDecoder(bytes.NewReader(data))
		dec.DisallowUnknownFields()
		if err := dec.Decode(cfg); err != nil {
			return nil, fmt.Errorf("%s: %w", path, err)
		}
	}
	if v := os.Getenv("ARIADNS_WEB_TOKEN"); v != "" {
		cfg.Web.Token = v
	}
	if v := os.Getenv("ARIADNS_LOG_LEVEL"); v != "" {
		cfg.Log.Level = v
	}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return cfg, nil
}

func (c *Config) Timeout() time.Duration { return time.Duration(c.TimeoutMS) * time.Millisecond }
func (c *Config) Hedge() time.Duration   { return time.Duration(c.HedgeMS) * time.Millisecond }

// IsLoopbackAddr reports whether a listen address only accepts local
// connections. An empty host (":53") or a wildcard counts as non-loopback.
func IsLoopbackAddr(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}
	if host == "localhost" {
		return true
	}
	ip, err := netip.ParseAddr(host)
	return err == nil && ip.IsLoopback()
}

// Validate checks the configuration and refuses unsafe combinations.
func (c *Config) Validate() error {
	listeners := map[string]string{
		"listen.udp": c.Listen.UDP, "listen.tcp": c.Listen.TCP,
		"listen.dot": c.Listen.DoT, "listen.doh": c.Listen.DoH, "web.listen": c.Web.Listen,
	}
	for name, a := range listeners {
		if a == "" {
			continue
		}
		if _, _, err := net.SplitHostPort(a); err != nil {
			return fmt.Errorf("%s %q: %w", name, a, err)
		}
	}
	if c.Listen.UDP == "" && c.Listen.TCP == "" && c.Listen.DoT == "" && c.Listen.DoH == "" {
		return fmt.Errorf("no DNS listener is enabled (listen.udp/tcp/dot/doh are all empty)")
	}
	if len(c.Upstreams) == 0 {
		return fmt.Errorf("upstreams must not be empty")
	}
	switch c.Strategy {
	case "fastest", "race", "failover":
	default:
		return fmt.Errorf("strategy %q: want fastest, race or failover", c.Strategy)
	}
	if c.TimeoutMS < 100 || c.TimeoutMS > 30000 {
		return fmt.Errorf("timeout_ms %d out of range 100..30000", c.TimeoutMS)
	}
	if c.HedgeMS < 0 {
		return fmt.Errorf("hedge_ms must be >= 0")
	}
	if c.Limits.MaxInflight < 1 || c.Limits.MaxTCPConns < 1 || c.Limits.TCPIdleSecs < 1 || c.Limits.DoTIdleSecs < 1 {
		return fmt.Errorf("limits.* must be positive")
	}
	if c.Limits.UDPMaxSize < 512 || c.Limits.UDPMaxSize > 4096 {
		return fmt.Errorf("limits.udp_max_size %d out of range 512..4096", c.Limits.UDPMaxSize)
	}
	if c.Cache.ServeStaleSecs < 0 {
		return fmt.Errorf("cache.serve_stale_secs must be >= 0")
	}
	if c.Access.RateLimitQPS < 0 || (c.Access.RateLimitQPS > 0 && c.Access.RateBurst < 1) {
		return fmt.Errorf("access.rate_limit_qps needs a positive access.rate_burst")
	}
	for _, a := range c.Access.Allow {
		if _, err := ParseAllow(a); err != nil {
			return fmt.Errorf("access.allow %q: %w", a, err)
		}
	}
	switch strings.ToLower(c.Log.Level) {
	case "debug", "info", "warn", "error":
	default:
		return fmt.Errorf("log.level %q: want debug, info, warn or error", c.Log.Level)
	}
	switch c.Log.Format {
	case "text", "json":
	default:
		return fmt.Errorf("log.format %q: want text or json", c.Log.Format)
	}
	if !strings.HasPrefix(c.DoH.Path, "/") {
		return fmt.Errorf("doh.path must start with /")
	}

	// Safety: never become an open resolver by accident.
	exposed := false
	for _, a := range []string{c.Listen.UDP, c.Listen.TCP, c.Listen.DoT, c.Listen.DoH} {
		if a != "" && !IsLoopbackAddr(a) {
			exposed = true
		}
	}
	if exposed && len(c.Access.Allow) == 0 && !c.Access.AllowAll {
		return fmt.Errorf("a DNS listener is reachable from the network but access.allow is empty: " +
			"list the client networks in access.allow (e.g. [\"192.168.0.0/16\"]) or set access.allow_all=true to run an open resolver on purpose")
	}
	if c.Web.Listen != "" && !IsLoopbackAddr(c.Web.Listen) && c.Web.Token == "" {
		return fmt.Errorf("web.listen is reachable from the network: set web.token (or ARIADNS_WEB_TOKEN)")
	}
	if c.Web.Token != "" && len(c.Web.Token) < 16 {
		return fmt.Errorf("web.token must be at least 16 characters")
	}
	needTLS := c.Listen.DoT != "" || (c.Listen.DoH != "" && !c.DoH.InsecureHTTP)
	if needTLS {
		hasFiles := c.TLS.CertFile != "" && c.TLS.KeyFile != ""
		if !hasFiles && !c.TLS.SelfSigned {
			return fmt.Errorf("DoT/DoH need tls.cert_file and tls.key_file (or tls.self_signed=true for testing)")
		}
		if (c.TLS.CertFile == "") != (c.TLS.KeyFile == "") {
			return fmt.Errorf("tls.cert_file and tls.key_file must be set together")
		}
	}
	if _, err := rules.Build(rules.Config{BlockMode: c.Rules.BlockMode}); err != nil {
		return err
	}
	return nil
}

// ParseAllow parses a CIDR or a single address.
func ParseAllow(s string) (netip.Prefix, error) {
	s = strings.TrimSpace(s)
	if strings.Contains(s, "/") {
		return netip.ParsePrefix(s)
	}
	a, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Prefix{}, err
	}
	return netip.PrefixFrom(a, a.BitLen()), nil
}
