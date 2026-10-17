package server

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"ariadns/internal/config"
	"ariadns/internal/dnsmsg"
	"ariadns/internal/subs"
	"ariadns/internal/testutil"
)

func startSmartServer(t *testing.T) (*Server, string) {
	t.Helper()
	fake := testutil.StartFakeDNS(t, testutil.StandardResponder("10.1.2.3", 60))
	dir := t.TempDir()
	cfg := config.Default()
	cfg.Listen = config.ListenConfig{UDP: "127.0.0.1:0"}
	cfg.Upstreams = []string{fake.Addr}
	cfg.DataDir = dir
	cfg.Smart = config.SmartConfig{Enabled: true, PublicIP: "203.0.113.9", ListenHTTP: "127.0.0.1:0", MaxRelays: 10}
	cfg.Panel = config.PanelConfig{Listen: "127.0.0.1:0"}
	cfg.Web = config.WebConfig{Listen: "127.0.0.1:0"}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	s, err := New(cfg, "", slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	s.h.allowPrivateTargets = true
	if err := s.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Shutdown)
	return s, dir
}

func query(t *testing.T, s *Server, ip, name string, qt uint16) []byte {
	t.Helper()
	q, err := dnsmsg.NewQuery(7, name, qt, false, false)
	if err != nil {
		t.Fatal(err)
	}
	return s.h.Handle(context.Background(), q, netip.MustParseAddr(ip), "udp")
}

func TestSmartRoutingAndAccess(t *testing.T) {
	s, _ := startSmartServer(t)
	const sub = "198.51.100.7"

	if rc := dnsmsg.Rcode(query(t, s, sub, "store.steampowered.com", dnsmsg.TypeA)); rc != dnsmsg.RcodeRefused {
		t.Fatalf("unknown client must be refused, rcode=%d", rc)
	}
	if _, err := s.subs.Add(newSub("ali", sub)); err != nil {
		t.Fatal(err)
	}
	resp := query(t, s, sub, "store.steampowered.com", dnsmsg.TypeA)
	rrs, _ := dnsmsg.WalkRRs(resp)
	if dnsmsg.Rcode(resp) != 0 || len(rrs) != 1 || !bytes.Equal(resp[rrs[0].RDStart:rrs[0].RDEnd], []byte{203, 0, 113, 9}) {
		t.Fatalf("smart domain must resolve to the public IP: %v", resp)
	}
	if rrs, _ := dnsmsg.WalkRRs(query(t, s, sub, "store.steampowered.com", dnsmsg.TypeAAAA)); len(rrs) != 0 {
		t.Fatal("AAAA must be empty for smart domains")
	}
	// unrelated domains go to the upstream (fake answers 10.1.2.3)
	resp = query(t, s, sub, "example.org", dnsmsg.TypeA)
	rrs, _ = dnsmsg.WalkRRs(resp)
	if len(rrs) != 1 || !bytes.Equal(resp[rrs[0].RDStart:rrs[0].RDEnd], []byte{10, 1, 2, 3}) {
		t.Fatal("normal domain should use upstream")
	}
}

func TestResolveAddrsFiltersPrivate(t *testing.T) {
	s, _ := startSmartServer(t)
	ips, err := s.h.ResolveAddrs(context.Background(), "example.org")
	if err != nil || len(ips) != 1 || ips[0].String() != "10.1.2.3" {
		t.Fatalf("test mode should allow private: %v %v", ips, err)
	}
	s.h.allowPrivateTargets = false
	ips, _ = s.h.ResolveAddrs(context.Background(), "example.org")
	if len(ips) != 0 {
		t.Fatalf("private targets must be dropped, got %v", ips)
	}
}

type httpc struct {
	t    *testing.T
	base string
	cl   *http.Client
}

func (c httpc) do(method, path, body string, hdr map[string]string) (int, string) {
	c.t.Helper()
	req, _ := http.NewRequest(method, c.base+path, strings.NewReader(body))
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	resp, err := c.cl.Do(req)
	if err != nil {
		c.t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

func TestPanelAndControlAPI(t *testing.T) {
	s, dir := startSmartServer(t)
	pw, err := s.creds.Reset()
	if err != nil {
		t.Fatal(err)
	}
	jar := &cookieJar{}
	p := httpc{t, "http://" + s.Addr("panel"), &http.Client{Jar: jar, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}
	hdr := map[string]string{"X-Requested-With": "ariadns", "Content-Type": "application/json"}
	base := "/" + s.creds.Path()

	if code, _ := p.do("GET", "/", "", nil); code != 404 {
		t.Fatalf("root must be 404, got %d", code)
	}
	if code, _ := p.do("GET", "/admin", "", nil); code != 404 {
		t.Fatalf("guessable path must be 404, got %d", code)
	}
	if code, _ := p.do("GET", base+"/", "", nil); code != 200 {
		t.Fatalf("panel page: %d", code)
	}
	if code, _ := p.do("GET", base+"/api/subs", "", nil); code != 401 {
		t.Fatalf("api without login: %d", code)
	}
	if code, _ := p.do("POST", base+"/login", `{"password":"nope"}`, hdr); code != 401 {
		t.Fatalf("wrong password: %d", code)
	}
	if code, _ := p.do("POST", base+"/login", `{"password":"`+pw+`"}`, hdr); code != 200 {
		t.Fatalf("login: %d", code)
	}
	if code, _ := p.do("POST", base+"/api/subs", `{"name":"x"}`, map[string]string{"Content-Type": "application/json"}); code != 403 {
		t.Fatalf("missing CSRF header must be refused: %d", code)
	}
	code, body := p.do("POST", base+"/api/subs", `{"name":"sara","limit_gb":2,"days":30,"self_rebind":true}`, hdr)
	if code != 201 {
		t.Fatalf("create sub: %d %s", code, body)
	}
	var v struct{ ID, Token, Status string }
	json.Unmarshal([]byte(body), &v)
	if v.Status != "unbound" {
		t.Fatalf("new sub without IP must be unbound, got %q", v.Status)
	}
	// subscriber portal: open from "their network" (loopback here) and bind
	pc := httpc{t, p.base, &http.Client{}}
	if code, _ := pc.do("GET", "/sub/"+v.Token+"/info", "", nil); code != 200 {
		t.Fatalf("portal info: %d", code)
	}
	if code, _ := pc.do("GET", "/sub/bogus/info", "", nil); code != 404 {
		t.Fatalf("bad token: %d", code)
	}
	if code, _ := pc.do("POST", "/sub/"+v.Token+"/rebind", "", nil); code != 403 {
		t.Fatalf("rebind without header: %d", code)
	}
	code, body = pc.do("POST", "/sub/"+v.Token+"/rebind", "", map[string]string{"X-Requested-With": "ariadns"})
	if code != 200 || !strings.Contains(body, `"status":"active"`) {
		t.Fatalf("rebind: %d %s", code, body)
	}
	// the panel can NOT use the local-only reset path
	if code, _ := p.do("POST", base+"/api/admin/password", `{"reset":true}`, map[string]string{"X-Requested-With": "ariadns", "X-Ariadns-Local": "1", "Content-Type": "application/json"}); code != 403 {
		t.Fatalf("panel must not reset without current password: %d", code)
	}

	// loopback control API: bearer token required
	tokb, _ := os.ReadFile(filepath.Join(dir, "ctl.token"))
	tok := strings.TrimSpace(string(tokb))
	c := httpc{t, "http://" + s.Addr("web"), &http.Client{}}
	if code, _ := c.do("GET", "/api/subs", "", nil); code != 401 {
		t.Fatalf("ctl without token: %d", code)
	}
	auth := map[string]string{"Authorization": "Bearer " + tok, "Content-Type": "application/json"}
	if code, b := c.do("GET", "/api/subs", "", auth); code != 200 || !strings.Contains(b, "sara") {
		t.Fatalf("ctl list: %d %s", code, b)
	}
	code, body = c.do("POST", "/api/admin/password", `{"reset":true}`, auth)
	if code != 200 || !strings.Contains(body, "password") {
		t.Fatalf("local reset: %d %s", code, body)
	}
	if code, _ := p.do("GET", base+"/api/subs", "", nil); code != 401 {
		t.Fatalf("reset must invalidate sessions: %d", code)
	}
}

type cookieJar struct{ cs []*http.Cookie }

func (j *cookieJar) SetCookies(_ *url.URL, c []*http.Cookie) { j.cs = append(j.cs, c...) }
func (j *cookieJar) Cookies(*url.URL) []*http.Cookie {
	// keep only the newest cookie per name
	m := map[string]*http.Cookie{}
	for _, c := range j.cs {
		m[c.Name] = c
	}
	var out []*http.Cookie
	for _, c := range m {
		if c.MaxAge >= 0 && c.Value != "" {
			out = append(out, c)
		}
	}
	return out
}

func newSub(name, ip string) subs.NewSub { return subs.NewSub{Name: name, IP: ip} }
