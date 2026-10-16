package cache

import (
	"encoding/binary"
	"net/netip"
	"testing"
	"time"

	"ariadns/internal/dnsmsg"
)

func answer(t *testing.T, name string, ttl uint32) []byte {
	t.Helper()
	q, err := dnsmsg.NewQuery(1, name, dnsmsg.TypeA, false, false)
	if err != nil {
		t.Fatal(err)
	}
	qq, _, _ := dnsmsg.ParseQuestion(q)
	return dnsmsg.AddrReply(q, qq, []netip.Addr{netip.MustParseAddr("192.0.2.1")}, ttl, false)
}

// negative builds an NXDOMAIN reply carrying an SOA in the authority section.
func negative(t *testing.T, name string, soaTTL, minimum uint32) []byte {
	t.Helper()
	q, _ := dnsmsg.NewQuery(1, name, dnsmsg.TypeA, false, false)
	_, qend, _ := dnsmsg.ParseQuestion(q)
	out := dnsmsg.BeginReply(q, qend, dnsmsg.RcodeNameError, false)
	out = append(out, 0xC0, 0x0C)
	out = binary.BigEndian.AppendUint16(out, dnsmsg.TypeSOA)
	out = binary.BigEndian.AppendUint16(out, dnsmsg.ClassIN)
	out = binary.BigEndian.AppendUint32(out, soaTTL)
	rdata, _ := dnsmsg.AppendName(nil, "ns.test")
	rdata, _ = dnsmsg.AppendName(rdata, "hostmaster.test")
	rdata = binary.BigEndian.AppendUint32(rdata, 1)
	rdata = binary.BigEndian.AppendUint32(rdata, 3600)
	rdata = binary.BigEndian.AppendUint32(rdata, 600)
	rdata = binary.BigEndian.AppendUint32(rdata, 86400)
	rdata = binary.BigEndian.AppendUint32(rdata, minimum)
	out = binary.BigEndian.AppendUint16(out, uint16(len(rdata)))
	out = append(out, rdata...)
	dnsmsg.SetCount(out, dnsmsg.SectionAuthority, 1)
	return out
}

func firstTTL(t *testing.T, msg []byte) uint32 {
	t.Helper()
	rrs, err := dnsmsg.WalkRRs(msg)
	if err != nil || len(rrs) == 0 {
		t.Fatalf("walk: %v", err)
	}
	return rrs[0].TTL
}

func newClocked(cfg Config) (*Cache, *time.Time) {
	c := New(cfg)
	now := time.Unix(1_700_000_000, 0)
	c.now = func() time.Time { return now }
	return c, &now
}

func TestHitCountsDownTTL(t *testing.T) {
	c, now := newClocked(Config{MaxEntries: 1000})
	if !c.Put("k", answer(t, "a.test", 60)) {
		t.Fatal("put refused")
	}
	msg, st := c.Get("k")
	if st != Hit || firstTTL(t, msg) != 60 {
		t.Fatalf("state=%v ttl=%d", st, firstTTL(t, msg))
	}
	*now = now.Add(25 * time.Second)
	msg, st = c.Get("k")
	if st != Hit || firstTTL(t, msg) != 35 {
		t.Fatalf("state=%v ttl=%d", st, firstTTL(t, msg))
	}
	*now = now.Add(40 * time.Second)
	if _, st = c.Get("k"); st != Miss {
		t.Fatalf("expected miss after expiry, got %v", st)
	}
}

func TestReturnedCopyIsPrivate(t *testing.T) {
	c, _ := newClocked(Config{})
	c.Put("k", answer(t, "a.test", 60))
	a, _ := c.Get("k")
	a[0], a[1] = 0xFF, 0xFF
	b, _ := c.Get("k")
	if b[0] == 0xFF {
		t.Fatal("mutating a returned message corrupted the cache")
	}
}

func TestServeStale(t *testing.T) {
	c, now := newClocked(Config{StaleFor: time.Hour, StaleTTL: 15})
	c.Put("k", answer(t, "a.test", 10))
	*now = now.Add(30 * time.Second)
	msg, st := c.Get("k")
	if st != Stale || firstTTL(t, msg) != 15 {
		t.Fatalf("state=%v ttl=%d", st, firstTTL(t, msg))
	}
	*now = now.Add(2 * time.Hour)
	if _, st = c.Get("k"); st != Miss {
		t.Fatalf("expected miss past stale window, got %v", st)
	}
}

func TestNegativeCachingUsesSOA(t *testing.T) {
	c, _ := newClocked(Config{})
	if !c.Put("k", negative(t, "nope.test", 300, 120)) {
		t.Fatal("negative answer with SOA must be cacheable")
	}
	c2, _ := newClocked(Config{NegTTL: 30})
	c2.Put("k", negative(t, "nope.test", 300, 120))
	if c2.shardFor("k").items["k"].Value.(*entry).life != 30*time.Second {
		t.Fatal("NegTTL cap not applied")
	}
}

func TestRefusesUncacheable(t *testing.T) {
	c, _ := newClocked(Config{})
	servfail := dnsmsg.HeaderReply(answer(t, "a.test", 60), dnsmsg.RcodeServerFailure)
	if c.Put("k", servfail) {
		t.Fatal("SERVFAIL must not be cached")
	}
	// NXDOMAIN without SOA: no TTL basis, not cached.
	q, _ := dnsmsg.NewQuery(1, "a.test", dnsmsg.TypeA, false, false)
	if c.Put("k", dnsmsg.NewReply(q, dnsmsg.RcodeNameError)) {
		t.Fatal("NXDOMAIN without SOA must not be cached")
	}
	tc := dnsmsg.Truncate(append(answer(t, "a.test", 60), make([]byte, 600)...), 100)
	if c.Put("k", tc) {
		t.Fatal("truncated response must not be cached")
	}
	if c.Put("k", answer(t, "a.test", 0)) {
		t.Fatal("zero TTL must not be cached")
	}
}

func TestTTLClamping(t *testing.T) {
	c, _ := newClocked(Config{MinTTL: 30, MaxTTL: 100})
	c.Put("lo", answer(t, "a.test", 5))
	c.Put("hi", answer(t, "b.test", 5000))
	if c.shardFor("lo").items["lo"].Value.(*entry).life != 30*time.Second {
		t.Fatal("min ttl not applied")
	}
	if c.shardFor("hi").items["hi"].Value.(*entry).life != 100*time.Second {
		t.Fatal("max ttl not applied")
	}
}

func TestEvictionBoundsSize(t *testing.T) {
	c, _ := newClocked(Config{MaxEntries: 128}) // 2 per shard
	msg := answer(t, "a.test", 60)
	for i := 0; i < 5000; i++ {
		c.Put(Key("", "n"+string(rune('a'+i%26))+time.Duration(i).String(), 1, 1, false), msg)
	}
	if n := c.Len(); n > 128 {
		t.Fatalf("cache holds %d entries, cap is 128", n)
	}
	if c.Stats().Evictions == 0 {
		t.Fatal("expected evictions")
	}
	c.Flush()
	if c.Len() != 0 {
		t.Fatal("flush left entries behind")
	}
}

func TestKeySeparatesDNSSECAndZone(t *testing.T) {
	if Key("", "a.test", 1, 1, false) == Key("", "a.test", 1, 1, true) {
		t.Fatal("DO bit must change the key")
	}
	if Key("corp", "a.test", 1, 1, false) == Key("", "a.test", 1, 1, false) {
		t.Fatal("zone must change the key")
	}
}
