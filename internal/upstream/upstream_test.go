package upstream

import (
	"context"
	"testing"
	"time"

	"ariadns/internal/dnsmsg"
	"ariadns/internal/testutil"
)

func TestParseSpec(t *testing.T) {
	cases := []struct {
		in      string
		proto   Proto
		addr    string
		sni     string
		wantErr bool
	}{
		{"1.1.1.1", UDP, "1.1.1.1:53", "", false},
		{"8.8.8.8:5353", UDP, "8.8.8.8:5353", "", false},
		{"2606:4700::1111", UDP, "[2606:4700::1111]:53", "", false},
		{"[2606:4700::1111]:5353", UDP, "[2606:4700::1111]:5353", "", false},
		{"tcp://9.9.9.9", TCP, "9.9.9.9:53", "", false},
		{"tls://1.1.1.1", TLS, "1.1.1.1:853", "", false},
		{"tls://1.1.1.1:853#cloudflare-dns.com", TLS, "1.1.1.1:853", "cloudflare-dns.com", false},
		{"ftp://1.1.1.1", "", "", "", true},
		{"", "", "", "", true},
		{"1.1.1.1:99999", "", "", "", true},
	}
	for _, c := range cases {
		sp, err := ParseSpec(c.in)
		if (err != nil) != c.wantErr {
			t.Errorf("%q: err=%v wantErr=%v", c.in, err, c.wantErr)
			continue
		}
		if err == nil && (sp.Proto != c.proto || sp.Addr != c.addr || sp.ServerName != c.sni) {
			t.Errorf("%q: got %+v", c.in, sp)
		}
	}
	sp, err := ParseSpec("https://dns.google/dns-query?token=secret#8.8.8.8")
	if err != nil || sp.PinIP != "8.8.8.8" || sp.Proto != HTTPS {
		t.Fatalf("https spec: %+v %v", sp, err)
	}
	if n := sp.DisplayName(); n != "https://dns.google" {
		t.Fatalf("display name leaks path/secret: %q", n)
	}
}

func query(t *testing.T, name string) []byte {
	t.Helper()
	q, err := dnsmsg.NewQuery(1, name, dnsmsg.TypeA, true, false)
	if err != nil {
		t.Fatal(err)
	}
	return q
}

func TestUDPAndTCPFallback(t *testing.T) {
	f := testutil.StartFakeDNS(t, testutil.StandardResponder("192.0.2.7", 60))
	u := New(Spec{Proto: UDP, Addr: f.Addr}, time.Second)
	defer u.Close()

	resp, err := u.Exchange(context.Background(), query(t, "ok.test"))
	if err != nil || dnsmsg.Rcode(resp) != 0 {
		t.Fatalf("udp exchange: %v rcode=%d", err, dnsmsg.Rcode(resp))
	}
	// tc.test is truncated over UDP; the client must retry over TCP.
	resp, err = u.Exchange(context.Background(), query(t, "tc.test"))
	if err != nil {
		t.Fatal(err)
	}
	if h, _ := dnsmsg.ParseHeader(resp); h.Truncated() || h.ANCount != 1 {
		t.Fatalf("TCP fallback not used: %+v", h)
	}
}

func TestStreamPoolReuse(t *testing.T) {
	f := testutil.StartFakeDNS(t, testutil.StandardResponder("192.0.2.7", 60))
	u := New(Spec{Proto: TCP, Addr: f.Addr}, time.Second)
	defer u.Close()
	for i := 0; i < 5; i++ {
		if _, err := u.Exchange(context.Background(), query(t, "ok.test")); err != nil {
			t.Fatalf("query %d: %v", i, err)
		}
	}
	if n := len(u.pool.idle); n != 1 {
		t.Fatalf("expected one pooled connection after sequential queries, got %d", n)
	}
}

func TestGroupStrategies(t *testing.T) {
	good := testutil.StartFakeDNS(t, testutil.StandardResponder("192.0.2.1", 60))
	// "dead" never answers.
	dead := testutil.StartFakeDNS(t, func([]byte, dnsmsg.Question, string) []byte { return nil })

	for _, strategy := range []string{StrategyRace, StrategyFastest, StrategyFailover} {
		g, err := NewGroup([]string{dead.Addr, good.Addr}, strategy, 400*time.Millisecond, 30*time.Millisecond)
		if err != nil {
			t.Fatal(err)
		}
		start := time.Now()
		resp, via, err := g.Exchange(context.Background(), query(t, "ok.test"))
		if err != nil {
			t.Fatalf("%s: %v", strategy, err)
		}
		if dnsmsg.Rcode(resp) != 0 || via != good.Addr {
			t.Fatalf("%s: rcode=%d via=%s", strategy, dnsmsg.Rcode(resp), via)
		}
		t.Logf("%s answered in %v", strategy, time.Since(start))
		g.Close()
	}
}

func TestGroupAllDown(t *testing.T) {
	dead := testutil.StartFakeDNS(t, func([]byte, dnsmsg.Question, string) []byte { return nil })
	g, _ := NewGroup([]string{dead.Addr}, StrategyRace, 150*time.Millisecond, 0)
	defer g.Close()
	if _, _, err := g.Exchange(context.Background(), query(t, "ok.test")); err == nil {
		t.Fatal("expected an error when every upstream is silent")
	}
	if s := g.Stats()[0]; s.Failures != 1 || s.LastError == "" {
		t.Fatalf("failure not recorded: %+v", s)
	}
}

func TestServfailIsNotFinalWhenAnotherUpstreamAnswers(t *testing.T) {
	bad := testutil.StartFakeDNS(t, func(req []byte, _ dnsmsg.Question, _ string) []byte {
		return dnsmsg.NewReply(req, dnsmsg.RcodeServerFailure)
	})
	good := testutil.StartFakeDNS(t, testutil.StandardResponder("192.0.2.1", 60))
	g, _ := NewGroup([]string{bad.Addr, good.Addr}, StrategyRace, time.Second, 0)
	defer g.Close()
	for i := 0; i < 20; i++ {
		resp, _, err := g.Exchange(context.Background(), query(t, "ok.test"))
		if err != nil || dnsmsg.Rcode(resp) != 0 {
			t.Fatalf("iteration %d: err=%v rcode=%d", i, err, dnsmsg.Rcode(resp))
		}
	}
}
