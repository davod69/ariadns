// Package admin implements the hidden-path admin panel, its JSON API, the
// subscriber self-service portal and the credentials that protect them.
package admin

import (
	"crypto/hmac"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"time"
)

const pbkdf2Iter = 200_000

type credFile struct {
	Path string `json:"path"` // hidden URL prefix
	Salt string `json:"salt"`
	Hash string `json:"hash"`
	Key  string `json:"key"` // session signing key
}

// Creds holds the panel's secret URL path, password hash and session key.
type Creds struct {
	file string
	mu   sync.RWMutex
	c    credFile
	key  []byte
}

func randBytes(n int) []byte {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return b
}

const alphabet = "abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789"

func randString(n int) string {
	out := make([]byte, n)
	for i, b := range randBytes(n) {
		out[i] = alphabet[int(b)%len(alphabet)]
	}
	return string(out)
}

// OpenCreds loads credentials from dir/admin.json. On first run it creates
// them and returns the generated password (otherwise "").
func OpenCreds(dir string) (*Creds, string, error) {
	cr := &Creds{file: filepath.Join(dir, "admin.json")}
	data, err := os.ReadFile(cr.file)
	switch {
	case err == nil:
		if err := json.Unmarshal(data, &cr.c); err != nil {
			return nil, "", err
		}
		cr.key, _ = base64.StdEncoding.DecodeString(cr.c.Key)
		if len(cr.key) < 16 || cr.c.Path == "" {
			return nil, "", errors.New("admin.json is corrupt")
		}
		return cr, "", nil
	case errors.Is(err, os.ErrNotExist):
		cr.c.Path = randString(16)
		pw, err := cr.setPassword("")
		return cr, pw, err
	}
	return nil, "", err
}

func (cr *Creds) setPassword(pw string) (string, error) {
	if pw == "" {
		pw = randString(16)
	}
	salt := randBytes(16)
	h, err := pbkdf2.Key(sha256.New, pw, salt, pbkdf2Iter, 32)
	if err != nil {
		return "", err
	}
	cr.mu.Lock()
	defer cr.mu.Unlock()
	cr.key = randBytes(32) // invalidates every existing session
	cr.c.Salt = base64.StdEncoding.EncodeToString(salt)
	cr.c.Hash = base64.StdEncoding.EncodeToString(h)
	cr.c.Key = base64.StdEncoding.EncodeToString(cr.key)
	if err := os.MkdirAll(filepath.Dir(cr.file), 0o750); err != nil {
		return "", err
	}
	b, _ := json.MarshalIndent(cr.c, "", "  ")
	tmp := cr.file + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return "", err
	}
	return pw, os.Rename(tmp, cr.file)
}

// Reset generates and stores a new random password.
func (cr *Creds) Reset() (string, error) { return cr.setPassword("") }

// Change sets a chosen password (minimum 10 characters).
func (cr *Creds) Change(pw string) error {
	if len(pw) < 10 {
		return errors.New("password must be at least 10 characters")
	}
	_, err := cr.setPassword(pw)
	return err
}

// Path is the secret URL prefix (without slashes).
func (cr *Creds) Path() string {
	cr.mu.RLock()
	defer cr.mu.RUnlock()
	return cr.c.Path
}

// Verify checks a password in constant time.
func (cr *Creds) Verify(pw string) bool {
	cr.mu.RLock()
	salt, _ := base64.StdEncoding.DecodeString(cr.c.Salt)
	want, _ := base64.StdEncoding.DecodeString(cr.c.Hash)
	cr.mu.RUnlock()
	got, err := pbkdf2.Key(sha256.New, pw, salt, pbkdf2Iter, 32)
	return err == nil && subtle.ConstantTimeCompare(got, want) == 1
}

// Session tokens: base64(expiry||nonce) "." base64(HMAC).
func (cr *Creds) newSession(ttl time.Duration) string {
	body := make([]byte, 8+8)
	binary.BigEndian.PutUint64(body, uint64(time.Now().Add(ttl).Unix()))
	copy(body[8:], randBytes(8))
	return base64.RawURLEncoding.EncodeToString(body) + "." + base64.RawURLEncoding.EncodeToString(cr.mac(body))
}

func (cr *Creds) mac(body []byte) []byte {
	cr.mu.RLock()
	defer cr.mu.RUnlock()
	m := hmac.New(sha256.New, cr.key)
	m.Write(body)
	return m.Sum(nil)
}

func (cr *Creds) validSession(tok string) bool {
	var a, b string
	for i := 0; i < len(tok); i++ {
		if tok[i] == '.' {
			a, b = tok[:i], tok[i+1:]
			break
		}
	}
	body, err1 := base64.RawURLEncoding.DecodeString(a)
	sig, err2 := base64.RawURLEncoding.DecodeString(b)
	if err1 != nil || err2 != nil || len(body) != 16 {
		return false
	}
	if !hmac.Equal(sig, cr.mac(body)) {
		return false
	}
	return int64(binary.BigEndian.Uint64(body)) > time.Now().Unix()
}
