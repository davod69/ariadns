package subs

import (
	"net/netip"
	"path/filepath"
	"testing"
	"time"
)

func TestLifecycle(t *testing.T) {
	path := filepath.Join(t.TempDir(), "subs.json")
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	ip := netip.MustParseAddr("198.51.100.7")

	v, err := s.Add(NewSub{Name: "ali", IP: "198.51.100.7", LimitBytes: 1000, Days: 1, SelfRebind: true})
	if err != nil || v.Status != "active" {
		t.Fatalf("add: %v %v", v.Status, err)
	}
	if !s.Allowed(ip) {
		t.Fatal("should be allowed")
	}
	if _, err := s.Add(NewSub{Name: "dup", IP: "198.51.100.7"}); err != ErrIPInUse {
		t.Fatalf("dup ip: %v", err)
	}
	s.AddTraffic(ip, 1000)
	if s.Allowed(ip) {
		t.Fatal("quota exhausted but still allowed")
	}
	if _, err := s.Update(v.ID, Patch{ResetUsed: true}); err != nil || !s.Allowed(ip) {
		t.Fatal("reset should re-enable")
	}
	off := false
	s.Update(v.ID, Patch{Enabled: &off})
	if s.Allowed(ip) {
		t.Fatal("disabled but allowed")
	}
	on := true
	s.Update(v.ID, Patch{Enabled: &on})

	s.now = func() time.Time { return time.Now().Add(48 * time.Hour) }
	if s.Allowed(ip) {
		t.Fatal("expired but allowed")
	}
	s.now = time.Now

	// self rebind with cooldown
	ip2 := netip.MustParseAddr("198.51.100.8")
	if _, err := s.Rebind(v.Token, ip2); err != nil {
		t.Fatal(err)
	}
	if s.Allowed(ip) || !s.Allowed(ip2) {
		t.Fatal("rebind did not move access")
	}
	if _, err := s.Rebind(v.Token, ip); err != ErrCooldown {
		t.Fatalf("want cooldown, got %v", err)
	}
	if _, err := s.Rebind("bad-token", ip); err != ErrNotFound {
		t.Fatal("bad token must fail")
	}

	// persistence incl. traffic
	s.AddTraffic(ip2, 5)
	s.Close()
	s2, _ := Open(path)
	defer s2.Close()
	l := s2.List()
	if len(l) != 1 || l[0].UsedBytes != 5 || l[0].IP != "198.51.100.8" {
		t.Fatalf("not persisted: %+v", l)
	}
	if err := s2.Delete(l[0].ID); err != nil || len(s2.List()) != 0 {
		t.Fatal("delete failed")
	}
}
