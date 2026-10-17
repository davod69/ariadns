package smart

import (
	"path/filepath"
	"testing"
)

func TestMatchAndUpdate(t *testing.T) {
	e, err := Open(filepath.Join(t.TempDir(), "s.json"), "203.0.113.5")
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := e.Match("store.steampowered.com"); !ok {
		t.Fatal("default gaming category should match subdomains")
	}
	if _, ok := e.Match("example.org"); ok {
		t.Fatal("unrelated domain matched")
	}
	if _, ok := e.Match("steamcontent.com"); ok {
		t.Fatal("downloads must be off by default")
	}
	if ip, ok := e.PublicV4(); !ok || ip.String() != "203.0.113.5" {
		t.Fatalf("public ip = %v %v", ip, ok)
	}
	if err := e.Update([]string{"downloads"}, []string{"Example.ORG"}, nil); err != nil {
		t.Fatal(err)
	}
	if _, ok := e.Match("steamcontent.com"); !ok {
		t.Fatal("downloads should now match")
	}
	if id, ok := e.Match("a.example.org"); !ok || id != "custom" {
		t.Fatal("custom domain should match")
	}
	if _, ok := e.Match("store.steampowered.com"); ok {
		t.Fatal("gaming was disabled by Update")
	}
	if err := e.Update([]string{"nope"}, nil, nil); err == nil {
		t.Fatal("unknown category must fail")
	}
	// persisted
	e2, _ := Open(e.path, "")
	if _, ok := e2.Match("a.example.org"); !ok {
		t.Fatal("state not persisted")
	}
}
