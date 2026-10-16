package rules

import (
	"os"
	"path/filepath"
	"testing"
)

func TestParseListLine(t *testing.T) {
	cases := []struct {
		in   string
		want string
		ok   bool
	}{
		{"0.0.0.0 ads.example.com", "ads.example.com", true},
		{"127.0.0.1\ttracker.example.net # comment", "tracker.example.net", true},
		{"plain.example.org", "plain.example.org", true},
		{"||adserver.example.com^$third-party", "adserver.example.com", true},
		{"*.wild.example.com", "wild.example.com", true},
		{"# only a comment", "", false},
		{"! adblock comment", "", false},
		{"[Adblock Plus 2.0]", "", false},
		{"127.0.0.1 localhost", "", false},
		{"::1 ip6-localhost", "", false},
		{"192.168.1.1", "", false},
		{"not a hosts line", "", false},
		{"bad_chars!.example.com", "", false},
		{"", "", false},
	}
	for _, c := range cases {
		got, ok := ParseListLine(c.in)
		if got != c.want || ok != c.ok {
			t.Errorf("ParseListLine(%q) = %q,%v want %q,%v", c.in, got, ok, c.want, c.ok)
		}
	}
}

func TestMatchOrder(t *testing.T) {
	e, err := Build(Config{
		Block: []string{"ads.example.com", "tracker.net"},
		Allow: []string{"ok.ads.example.com"},
		Hosts: map[string][]string{"nas.lan": {"192.168.1.2", "fd00::2"}},
		Forward: map[string][]string{
			"corp.example.com":     {"10.0.0.53"},
			"dev.corp.example.com": {"10.0.1.53"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name string
		kind Kind
		zone string
	}{
		{"example.com", Pass, ""},
		{"ads.example.com", Block, ""},
		{"x.y.ads.example.com", Block, ""},
		{"ok.ads.example.com", Pass, ""}, // allow-list beats block
		{"sub.ok.ads.example.com", Pass, ""},
		{"tracker.net", Block, ""},
		{"notracker.net", Pass, ""}, // suffix match is label-aware
		{"nas.lan", Local, ""},
		{"localhost", Local, ""},
		{"foo.localhost", Local, ""},
		{"app.corp.example.com", Forward, "corp.example.com"},
		{"x.dev.corp.example.com", Forward, "dev.corp.example.com"}, // longest suffix wins
	}
	for _, tc := range tests {
		d := e.Match(tc.name)
		if d.Kind != tc.kind || d.Zone != tc.zone {
			t.Errorf("Match(%q) = %+v, want kind=%v zone=%q", tc.name, d, tc.kind, tc.zone)
		}
	}
	if d := e.Match("nas.lan"); len(d.IPs) != 2 {
		t.Errorf("nas.lan ips = %v", d.IPs)
	}
}

func TestBlocklistFile(t *testing.T) {
	p := filepath.Join(t.TempDir(), "list.txt")
	body := "# hosts\n0.0.0.0 a.test\n127.0.0.1 b.test\nc.test\n||d.test^\n"
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	e, err := Build(Config{BlocklistFiles: []string{p}})
	if err != nil {
		t.Fatal(err)
	}
	for _, n := range []string{"a.test", "b.test", "c.test", "d.test", "x.d.test"} {
		if e.Match(n).Kind != Block {
			t.Errorf("%s should be blocked", n)
		}
	}
	if got := e.Counts().Blocked; got != 4 {
		t.Errorf("blocked count = %d, want 4", got)
	}
	if _, err := Build(Config{BlocklistFiles: []string{p + ".missing"}}); err == nil {
		t.Error("missing blocklist file must be an error")
	}
}

func TestBuildValidation(t *testing.T) {
	bad := []Config{
		{BlockMode: "explode"},
		{Hosts: map[string][]string{"x.lan": {"not-an-ip"}}},
		{Forward: map[string][]string{"corp": {}}},
	}
	for i, c := range bad {
		if _, err := Build(c); err == nil {
			t.Errorf("case %d: expected error", i)
		}
	}
}
