package admin

import (
	"testing"
	"time"
)

func TestCreds(t *testing.T) {
	dir := t.TempDir()
	cr, pw, err := OpenCreds(dir)
	if err != nil || pw == "" || len(cr.Path()) < 16 {
		t.Fatalf("create: %v %q", err, pw)
	}
	if !cr.Verify(pw) || cr.Verify(pw+"x") {
		t.Fatal("verify wrong")
	}
	tok := cr.newSession(time.Hour)
	if !cr.validSession(tok) || cr.validSession(tok+"x") || cr.validSession("") {
		t.Fatal("session validation wrong")
	}
	if cr.validSession(cr.newSession(-time.Minute)) {
		t.Fatal("expired session accepted")
	}
	// reload from disk: same path and password, no new password printed
	cr2, pw2, err := OpenCreds(dir)
	if err != nil || pw2 != "" || cr2.Path() != cr.Path() || !cr2.Verify(pw) {
		t.Fatal("reload failed")
	}
	if !cr2.validSession(tok) {
		t.Fatal("session should survive restart")
	}
	// reset invalidates old password and sessions
	npw, _ := cr2.Reset()
	if cr2.Verify(pw) || !cr2.Verify(npw) || cr2.validSession(tok) {
		t.Fatal("reset did not rotate secrets")
	}
	if cr2.Change("short") == nil {
		t.Fatal("short password accepted")
	}
}
