// Package rules decides what happens to a query before it reaches an
// upstream: answer locally, block, send to a dedicated upstream group, or
// pass through.
package rules

import (
	"bufio"
	"fmt"
	"net/netip"
	"os"
	"strings"
)

// Kind is the action chosen for a name.
type Kind int

const (
	Pass Kind = iota
	Block
	Local
	Forward
)

// Config is the JSON shape of the "rules" section.
type Config struct {
	Block          []string            `json:"block"`
	Allow          []string            `json:"allow"`
	BlocklistFiles []string            `json:"blocklist_files"`
	Hosts          map[string][]string `json:"hosts"`
	Forward        map[string][]string `json:"forward"`
	BlockMode      string              `json:"block_mode"` // nxdomain | null | refused
	BlockTTL       uint32              `json:"block_ttl"`
	LocalTTL       uint32              `json:"local_ttl"`
}

// Decision is the outcome of Match.
type Decision struct {
	Kind Kind
	IPs  []netip.Addr // Local
	Zone string       // Forward
	Rule string       // the rule that matched, for logs
}

// Engine is immutable after Build and safe for concurrent use.
type Engine struct {
	block     map[string]struct{}
	allow     map[string]struct{}
	hosts     map[string][]netip.Addr
	forward   map[string][]string
	BlockMode string
	BlockTTL  uint32
	LocalTTL  uint32
}

// Counts summarises what was loaded.
type Counts struct {
	Blocked int `json:"blocked_domains"`
	Allowed int `json:"allowed_domains"`
	Hosts   int `json:"local_hosts"`
	Zones   int `json:"forward_zones"`
}

// Normalize lower-cases a domain and strips whitespace, wildcards and dots.
func Normalize(d string) string {
	d = strings.ToLower(strings.TrimSpace(d))
	d = strings.TrimPrefix(d, "*.")
	return strings.Trim(d, ".")
}

// Build compiles cfg, reading any blocklist files.
func Build(cfg Config) (*Engine, error) {
	e := &Engine{
		block:     make(map[string]struct{}),
		allow:     make(map[string]struct{}),
		hosts:     make(map[string][]netip.Addr),
		forward:   make(map[string][]string),
		BlockMode: strings.ToLower(cfg.BlockMode),
		BlockTTL:  cfg.BlockTTL,
		LocalTTL:  cfg.LocalTTL,
	}
	switch e.BlockMode {
	case "", "nxdomain":
		e.BlockMode = "nxdomain"
	case "null", "refused":
	default:
		return nil, fmt.Errorf("rules.block_mode %q: want nxdomain, null or refused", cfg.BlockMode)
	}
	for _, d := range cfg.Block {
		if d = Normalize(d); d != "" {
			e.block[d] = struct{}{}
		}
	}
	for _, d := range cfg.Allow {
		if d = Normalize(d); d != "" {
			e.allow[d] = struct{}{}
		}
	}
	for _, path := range cfg.BlocklistFiles {
		if err := e.loadList(path); err != nil {
			return nil, err
		}
	}
	for name, ips := range cfg.Hosts {
		n := Normalize(name)
		if n == "" {
			return nil, fmt.Errorf("rules.hosts: empty name")
		}
		for _, s := range ips {
			ip, err := netip.ParseAddr(strings.TrimSpace(s))
			if err != nil {
				return nil, fmt.Errorf("rules.hosts[%q]: %w", name, err)
			}
			e.hosts[n] = append(e.hosts[n], ip.Unmap())
		}
	}
	// RFC 6761: localhost is always local.
	if _, ok := e.hosts["localhost"]; !ok {
		e.hosts["localhost"] = []netip.Addr{netip.MustParseAddr("127.0.0.1"), netip.MustParseAddr("::1")}
	}
	for zone, ups := range cfg.Forward {
		z := Normalize(zone)
		if z == "" || len(ups) == 0 {
			return nil, fmt.Errorf("rules.forward[%q]: need a zone and at least one upstream", zone)
		}
		e.forward[z] = ups
	}
	return e, nil
}

func (e *Engine) loadList(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("blocklist %s: %w", path, err)
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
	for sc.Scan() {
		if d, ok := ParseListLine(sc.Text()); ok {
			e.block[d] = struct{}{}
		}
	}
	if err := sc.Err(); err != nil {
		return fmt.Errorf("blocklist %s: %w", path, err)
	}
	return nil
}

var ignoredHostsNames = map[string]bool{
	"localhost": true, "localhost.localdomain": true, "local": true, "broadcasthost": true,
	"ip6-localhost": true, "ip6-loopback": true, "ip6-localnet": true, "ip6-mcastprefix": true,
	"ip6-allnodes": true, "ip6-allrouters": true, "ip6-allhosts": true, "0.0.0.0": true,
}

// ParseListLine extracts a domain from one line of a blocklist. It
// understands hosts files ("0.0.0.0 ads.example"), plain domain lists and
// the common "||domain^" adblock form. Comments are ignored.
func ParseListLine(line string) (string, bool) {
	if i := strings.IndexByte(line, '#'); i >= 0 {
		line = line[:i]
	}
	line = strings.TrimSpace(line)
	if line == "" || line[0] == '!' || line[0] == '[' || line[0] == '@' {
		return "", false
	}
	var d string
	if rest, ok := strings.CutPrefix(line, "||"); ok {
		if i := strings.IndexAny(rest, "^/$:"); i >= 0 {
			rest = rest[:i]
		}
		d = rest
	} else {
		fields := strings.Fields(line)
		switch {
		case len(fields) >= 2:
			if _, err := netip.ParseAddr(fields[0]); err != nil {
				return "", false
			}
			d = fields[1]
		case len(fields) == 1:
			d = fields[0]
		}
	}
	d = Normalize(d)
	if d == "" || len(d) > 253 || ignoredHostsNames[d] {
		return "", false
	}
	if _, err := netip.ParseAddr(d); err == nil {
		return "", false
	}
	for i := 0; i < len(d); i++ {
		c := d[i]
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '_' || c == '.') {
			return "", false
		}
	}
	return d, true
}

// walk calls fn for name and each of its parent domains, most specific
// first, until fn returns true.
func walk(name string, fn func(string) bool) {
	for {
		if fn(name) {
			return
		}
		i := strings.IndexByte(name, '.')
		if i < 0 {
			return
		}
		name = name[i+1:]
	}
}

// Match returns the action for a (lower-case, dot-less) query name.
// Order: local hosts, allow-list, block-list, forward zones.
func (e *Engine) Match(name string) Decision {
	if ips, ok := e.hosts[name]; ok {
		return Decision{Kind: Local, IPs: ips, Rule: "hosts:" + name}
	}
	if name == "localhost" || strings.HasSuffix(name, ".localhost") {
		return Decision{Kind: Local, IPs: e.hosts["localhost"], Rule: "hosts:localhost"}
	}
	allowed := false
	if len(e.allow) > 0 {
		walk(name, func(s string) bool {
			_, allowed = e.allow[s]
			return allowed
		})
	}
	if !allowed && len(e.block) > 0 {
		var hit string
		walk(name, func(s string) bool {
			if _, ok := e.block[s]; ok {
				hit = s
				return true
			}
			return false
		})
		if hit != "" {
			return Decision{Kind: Block, Rule: "block:" + hit}
		}
	}
	if len(e.forward) > 0 {
		var zone string
		walk(name, func(s string) bool {
			if _, ok := e.forward[s]; ok {
				zone = s
				return true
			}
			return false
		})
		if zone != "" {
			return Decision{Kind: Forward, Zone: zone, Rule: "forward:" + zone}
		}
	}
	return Decision{Kind: Pass}
}

// ForwardZones returns zone -> upstream specs.
func (e *Engine) ForwardZones() map[string][]string { return e.forward }

// Counts reports how many rules are loaded.
func (e *Engine) Counts() Counts {
	return Counts{Blocked: len(e.block), Allowed: len(e.allow), Hosts: len(e.hosts), Zones: len(e.forward)}
}
