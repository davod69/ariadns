package dnsmsg

import (
	"net/netip"
	"testing"
)

func TestQueryRoundTrip(t *testing.T) {
	q, err := NewQuery(0xBEEF, "WWW.Example.COM.", TypeAAAA, true, true)
	if err != nil {
		t.Fatal(err)
	}
	h, err := ParseHeader(q)
	if err != nil || h.ID != 0xBEEF || !h.RecursionDesired() || h.QDCount != 1 || h.ARCount != 1 {
		t.Fatalf("bad header %+v err=%v", h, err)
	}
	qq, end, err := ParseQuestion(q)
	if err != nil {
		t.Fatal(err)
	}
	if qq.Name != "www.example.com" || qq.Type != TypeAAAA || qq.Class != ClassIN {
		t.Fatalf("bad question %+v", qq)
	}
	if end >= len(q) {
		t.Fatalf("question end %d should be before OPT (len %d)", end, len(q))
	}
	e := EDNS(q)
	if !e.Present || !e.DO || e.UDPSize != 1232 {
		t.Fatalf("bad edns %+v", e)
	}
}

func TestNameEscapes(t *testing.T) {
	b, err := AppendName(nil, `a\046b.example`)
	if err != nil {
		t.Fatal(err)
	}
	name, _, err := ReadName(b, 0)
	if err != nil || name != `a\046b.example` {
		t.Fatalf("got %q err=%v", name, err)
	}
}

func TestNameLimits(t *testing.T) {
	long := make([]byte, 64)
	for i := range long {
		long[i] = 'a'
	}
	if _, err := AppendName(nil, string(long)+".com"); err == nil {
		t.Fatal("expected error for 64-byte label")
	}
}

func TestPointerLoopRejected(t *testing.T) {
	msg := make([]byte, HeaderLen+2)
	put16(msg[4:], 1)
	msg[HeaderLen] = 0xC0
	msg[HeaderLen+1] = HeaderLen // points at itself
	if _, _, err := ReadName(msg, HeaderLen); err == nil {
		t.Fatal("self-referencing pointer must be rejected")
	}
}

func TestTruncatedInputsNeverPanic(t *testing.T) {
	q, _ := NewQuery(1, "example.com", TypeA, true, false)
	for i := 0; i < len(q); i++ {
		_, _, _ = ParseQuestion(q[:i])
		_, _ = WalkRRs(q[:i])
		_ = EDNS(q[:i])
	}
}

func TestAddrReply(t *testing.T) {
	q, _ := NewQuery(7, "host.lan", TypeA, true, false)
	qq, _, _ := ParseQuestion(q)
	ips := []netip.Addr{netip.MustParseAddr("10.0.0.1"), netip.MustParseAddr("fd00::1"), netip.MustParseAddr("10.0.0.2")}
	resp := AddrReply(q, qq, ips, 120, true)

	h, _ := ParseHeader(resp)
	if !h.Response() || h.ID != 7 || h.Rcode() != 0 || h.ANCount != 2 || h.ARCount != 1 {
		t.Fatalf("bad response header %+v", h)
	}
	rrs, err := WalkRRs(resp)
	if err != nil || len(rrs) != 3 {
		t.Fatalf("walk: %v %v", rrs, err)
	}
	if got := FormatRData(resp, rrs[0]); got != "10.0.0.1" {
		t.Fatalf("rdata = %s", got)
	}
	if rrs[0].TTL != 120 {
		t.Fatalf("ttl = %d", rrs[0].TTL)
	}

	// AAAA query against the same list only yields the v6 address.
	q6, _ := NewQuery(8, "host.lan", TypeAAAA, false, false)
	qq6, _, _ := ParseQuestion(q6)
	r6 := AddrReply(q6, qq6, ips, 60, false)
	h6, _ := ParseHeader(r6)
	if h6.ANCount != 1 {
		t.Fatalf("want 1 AAAA answer, got %d", h6.ANCount)
	}
	// A TXT query yields NODATA.
	qt, _ := NewQuery(9, "host.lan", TypeTXT, false, false)
	qqt, _, _ := ParseQuestion(qt)
	rt := AddrReply(qt, qqt, ips, 60, false)
	ht, _ := ParseHeader(rt)
	if ht.ANCount != 0 || ht.Rcode() != RcodeSuccess {
		t.Fatalf("want NODATA, got %+v", ht)
	}
}

func TestMapTTLsSkipsOPT(t *testing.T) {
	q, _ := NewQuery(1, "x.test", TypeA, true, true)
	qq, _, _ := ParseQuestion(q)
	resp := AddrReply(q, qq, []netip.Addr{netip.MustParseAddr("1.2.3.4")}, 300, false)
	if err := MapTTLs(resp, func(_ uint16, ttl uint32) uint32 { return ttl - 100 }); err != nil {
		t.Fatal(err)
	}
	rrs, _ := WalkRRs(resp)
	if rrs[0].TTL != 200 {
		t.Fatalf("answer ttl = %d", rrs[0].TTL)
	}
	if rrs[1].Type != TypeOPT || rrs[1].TTL != 0 {
		t.Fatalf("OPT must be untouched: %+v", rrs[1])
	}
}

func TestTruncate(t *testing.T) {
	q, _ := NewQuery(1, "big.test", TypeA, false, false)
	qq, _, _ := ParseQuestion(q)
	var ips []netip.Addr
	for i := 0; i < 60; i++ {
		ips = append(ips, netip.AddrFrom4([4]byte{10, 0, 0, byte(i)}))
	}
	resp := AddrReply(q, qq, ips, 60, false)
	if len(resp) <= 512 {
		t.Fatalf("test response too small: %d", len(resp))
	}
	tr := Truncate(resp, 512)
	h, _ := ParseHeader(tr)
	if !h.Truncated() || h.ANCount != 0 || h.QDCount != 1 || len(tr) > 512 {
		t.Fatalf("bad truncation: %+v len=%d", h, len(tr))
	}
	if same := Truncate(resp, 4096); len(same) != len(resp) {
		t.Fatal("must not truncate when it fits")
	}
}

func TestStripOPT(t *testing.T) {
	q, _ := NewQuery(1, "x.test", TypeA, true, false)
	qq, _, _ := ParseQuestion(q)
	resp := AddrReply(q, qq, []netip.Addr{netip.MustParseAddr("1.2.3.4")}, 60, false)
	if !EDNS(resp).Present {
		t.Fatal("expected OPT in reply to EDNS query")
	}
	stripped := StripOPT(resp)
	if EDNS(stripped).Present {
		t.Fatal("OPT should be gone")
	}
	h, _ := ParseHeader(stripped)
	if h.ARCount != 0 || h.ANCount != 1 {
		t.Fatalf("counts wrong: %+v", h)
	}
}

func TestRestoreQuestionKeepsClientCase(t *testing.T) {
	req, _ := NewQuery(1, "example.com", TypeA, false, false)
	// Client used mixed case on the wire.
	mixed := append([]byte(nil), req...)
	mixed[HeaderLen+1] = 'E'
	qq, _, _ := ParseQuestion(req)
	resp := AddrReply(req, qq, []netip.Addr{netip.MustParseAddr("1.2.3.4")}, 60, false)
	RestoreQuestion(resp, mixed)
	if resp[HeaderLen+1] != 'E' {
		t.Fatal("question case was not restored")
	}
}

func TestParseType(t *testing.T) {
	if v, ok := ParseType("aaaa"); !ok || v != TypeAAAA {
		t.Fatal("aaaa")
	}
	if v, ok := ParseType("TYPE65"); !ok || v != TypeHTTPS {
		t.Fatal("TYPE65")
	}
	if _, ok := ParseType("bogus"); ok {
		t.Fatal("bogus should not parse")
	}
}
