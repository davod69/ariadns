// Package sni implements a transparent layer-4 relay that routes TLS
// connections by their SNI and HTTP connections by their Host header. TLS is
// never terminated, so the relay cannot read the encrypted traffic.
package sni

import (
	"errors"
	"strings"
)

// ErrNeedMore means the buffer does not yet hold the whole ClientHello.
var ErrNeedMore = errors.New("sni: need more data")

var errNotTLS = errors.New("sni: not a TLS ClientHello")

// ParseClientHello extracts the server name from the start of a TLS stream.
// hostOff is the offset of the name inside b (used for fragmentation).
func ParseClientHello(b []byte) (host string, hostOff int, err error) {
	if len(b) < 5 {
		return "", 0, ErrNeedMore
	}
	if b[0] != 0x16 || b[1] != 3 {
		return "", 0, errNotTLS
	}
	recLen := int(b[3])<<8 | int(b[4])
	if recLen < 42 || recLen > 1<<14 {
		return "", 0, errNotTLS
	}
	if len(b) < 5+recLen {
		return "", 0, ErrNeedMore
	}
	p := b[5 : 5+recLen]
	if p[0] != 1 { // handshake type: client_hello
		return "", 0, errNotTLS
	}
	off := 4 + 2 + 32 // handshake header, version, random
	skip := func(lenBytes int) bool {
		if off+lenBytes > len(p) {
			return false
		}
		n := 0
		for i := 0; i < lenBytes; i++ {
			n = n<<8 | int(p[off+i])
		}
		off += lenBytes + n
		return off <= len(p)
	}
	if !skip(1) || !skip(2) || !skip(1) { // session id, cipher suites, compression
		return "", 0, errNotTLS
	}
	if off+2 > len(p) {
		return "", 0, nil // no extensions, no SNI
	}
	extEnd := off + 2 + (int(p[off])<<8 | int(p[off+1]))
	off += 2
	if extEnd > len(p) {
		return "", 0, errNotTLS
	}
	for off+4 <= extEnd {
		typ := int(p[off])<<8 | int(p[off+1])
		n := int(p[off+2])<<8 | int(p[off+3])
		off += 4
		if off+n > extEnd {
			return "", 0, errNotTLS
		}
		if typ == 0 { // server_name
			e := p[off : off+n]
			if len(e) < 5 || e[2] != 0 {
				return "", 0, errNotTLS
			}
			l := int(e[3])<<8 | int(e[4])
			if 5+l > len(e) {
				return "", 0, errNotTLS
			}
			name := strings.ToLower(string(e[5 : 5+l]))
			return strings.TrimSuffix(name, "."), 5 + off + 5, nil
		}
		off += n
	}
	return "", 0, nil
}

// ParseHTTPHost extracts the Host header from the start of an HTTP request.
func ParseHTTPHost(b []byte) (string, error) {
	end := strings.Index(string(b), "\r\n\r\n")
	if end < 0 {
		if len(b) > 16<<10 {
			return "", errors.New("sni: HTTP header too large")
		}
		return "", ErrNeedMore
	}
	lines := strings.Split(string(b[:end]), "\r\n")
	if len(lines) == 0 || !strings.Contains(lines[0], "HTTP/") {
		return "", errors.New("sni: not an HTTP request")
	}
	for _, l := range lines[1:] {
		if i := strings.IndexByte(l, ':'); i > 0 && strings.EqualFold(strings.TrimSpace(l[:i]), "host") {
			h := strings.ToLower(strings.TrimSpace(l[i+1:]))
			if j := strings.LastIndexByte(h, ':'); j > 0 && !strings.Contains(h[j:], "]") {
				h = h[:j]
			}
			return strings.TrimSuffix(h, "."), nil
		}
	}
	return "", nil
}
