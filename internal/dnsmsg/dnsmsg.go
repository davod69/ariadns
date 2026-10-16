// Package dnsmsg is a small DNS wire-format toolkit built on the standard
// library only. It parses just what a forwarding resolver needs (header,
// question, resource-record boundaries, TTLs, EDNS) and builds the handful
// of synthetic replies the server generates itself.
package dnsmsg

import (
	"encoding/binary"
	"errors"
)

// HeaderLen is the size of the fixed DNS header.
const HeaderLen = 12

// Header flag bits.
const (
	FlagQR uint16 = 1 << 15
	FlagAA uint16 = 1 << 10
	FlagTC uint16 = 1 << 9
	FlagRD uint16 = 1 << 8
	FlagRA uint16 = 1 << 7
)

// Response codes.
const (
	RcodeSuccess        = 0
	RcodeFormatError    = 1
	RcodeServerFailure  = 2
	RcodeNameError      = 3
	RcodeNotImplemented = 4
	RcodeRefused        = 5
)

// Record types and classes used by the server.
const (
	TypeA     uint16 = 1
	TypeNS    uint16 = 2
	TypeCNAME uint16 = 5
	TypeSOA   uint16 = 6
	TypePTR   uint16 = 12
	TypeMX    uint16 = 15
	TypeTXT   uint16 = 16
	TypeAAAA  uint16 = 28
	TypeSRV   uint16 = 33
	TypeOPT   uint16 = 41
	TypeSVCB  uint16 = 64
	TypeHTTPS uint16 = 65
	TypeANY   uint16 = 255

	ClassIN uint16 = 1
)

var (
	ErrShort    = errors.New("dnsmsg: message too short")
	ErrName     = errors.New("dnsmsg: malformed name")
	ErrQuestion = errors.New("dnsmsg: expected exactly one question")
)

func be16(b []byte) uint16     { return binary.BigEndian.Uint16(b) }
func be32(b []byte) uint32     { return binary.BigEndian.Uint32(b) }
func put16(b []byte, v uint16) { binary.BigEndian.PutUint16(b, v) }

// Header is the decoded fixed header.
type Header struct {
	ID      uint16
	Flags   uint16
	QDCount uint16
	ANCount uint16
	NSCount uint16
	ARCount uint16
}

// ParseHeader decodes the first 12 bytes of msg.
func ParseHeader(msg []byte) (Header, error) {
	if len(msg) < HeaderLen {
		return Header{}, ErrShort
	}
	return Header{be16(msg), be16(msg[2:]), be16(msg[4:]), be16(msg[6:]), be16(msg[8:]), be16(msg[10:])}, nil
}

func (h Header) Response() bool         { return h.Flags&FlagQR != 0 }
func (h Header) Truncated() bool        { return h.Flags&FlagTC != 0 }
func (h Header) RecursionDesired() bool { return h.Flags&FlagRD != 0 }
func (h Header) Opcode() int            { return int(h.Flags>>11) & 0xF }
func (h Header) Rcode() int             { return int(h.Flags & 0xF) }

// GetID returns the transaction ID of msg (0 if msg is too short).
func GetID(msg []byte) uint16 {
	if len(msg) < 2 {
		return 0
	}
	return be16(msg)
}

// SetID overwrites the transaction ID in place.
func SetID(msg []byte, id uint16) {
	if len(msg) >= 2 {
		put16(msg, id)
	}
}

// Rcode returns the response code of msg (0 if msg is too short).
func Rcode(msg []byte) int {
	if len(msg) < 4 {
		return 0
	}
	return int(msg[3] & 0xF)
}

func appendEscaped(dst []byte, b byte) []byte {
	if b == '.' || b == '\\' || b <= 0x20 || b >= 0x7f {
		return append(dst, '\\', '0'+b/100, '0'+(b/10)%10, '0'+b%10)
	}
	return append(dst, b)
}

// ReadName decodes the (possibly compressed) domain name at off. The result
// is lower-cased, has no trailing dot (the root is the empty string) and
// escapes unusual bytes as \DDD so it is always safe to log and display.
// It returns the name and the offset just past it in the original position.
func ReadName(msg []byte, off int) (string, int, error) {
	name := make([]byte, 0, 64)
	end := -1
	wire := 0
	jumps := 0
	pos := off
	for {
		if pos < 0 || pos >= len(msg) {
			return "", 0, ErrShort
		}
		c := msg[pos]
		switch c & 0xC0 {
		case 0x00:
			if c == 0 {
				if end < 0 {
					end = pos + 1
				}
				return string(name), end, nil
			}
			l := int(c)
			if pos+1+l > len(msg) {
				return "", 0, ErrShort
			}
			wire += l + 1
			if wire > 254 {
				return "", 0, ErrName
			}
			if len(name) > 0 {
				name = append(name, '.')
			}
			for _, b := range msg[pos+1 : pos+1+l] {
				if b >= 'A' && b <= 'Z' {
					b += 'a' - 'A'
				}
				name = appendEscaped(name, b)
			}
			pos += 1 + l
		case 0xC0:
			if pos+1 >= len(msg) {
				return "", 0, ErrShort
			}
			ptr := int(be16(msg[pos:]) & 0x3FFF)
			if end < 0 {
				end = pos + 2
			}
			jumps++
			// Pointers must point strictly backwards: this alone rules out loops.
			if ptr >= pos || jumps > 16 {
				return "", 0, ErrName
			}
			pos = ptr
		default:
			return "", 0, ErrName
		}
	}
}

// SkipName returns the offset just past the name starting at off without
// decoding it.
func SkipName(msg []byte, off int) (int, error) {
	for {
		if off < 0 || off >= len(msg) {
			return 0, ErrShort
		}
		c := msg[off]
		switch c & 0xC0 {
		case 0x00:
			if c == 0 {
				return off + 1, nil
			}
			off += 1 + int(c)
		case 0xC0:
			if off+1 >= len(msg) {
				return 0, ErrShort
			}
			return off + 2, nil
		default:
			return 0, ErrName
		}
	}
}

// Question is the single question of a query.
type Question struct {
	Name  string
	Type  uint16
	Class uint16
}

// ParseQuestion decodes the only question of msg and returns it together
// with the offset where the question section ends.
func ParseQuestion(msg []byte) (Question, int, error) {
	h, err := ParseHeader(msg)
	if err != nil {
		return Question{}, 0, err
	}
	if h.QDCount != 1 {
		return Question{}, 0, ErrQuestion
	}
	name, off, err := ReadName(msg, HeaderLen)
	if err != nil {
		return Question{}, 0, err
	}
	if off+4 > len(msg) {
		return Question{}, 0, ErrShort
	}
	return Question{Name: name, Type: be16(msg[off:]), Class: be16(msg[off+2:])}, off + 4, nil
}

// Resource-record sections.
const (
	SectionAnswer = iota
	SectionAuthority
	SectionAdditional
)

// RR locates one resource record inside a message.
type RR struct {
	NameOff int
	Type    uint16
	Class   uint16
	TTL     uint32
	TTLOff  int
	RDStart int
	RDEnd   int
	Section int
}

func forEachRR(msg []byte, fn func(RR) bool) error {
	h, err := ParseHeader(msg)
	if err != nil {
		return err
	}
	off := HeaderLen
	for i := 0; i < int(h.QDCount); i++ {
		if off, err = SkipName(msg, off); err != nil {
			return err
		}
		off += 4
		if off > len(msg) {
			return ErrShort
		}
	}
	an, ns := int(h.ANCount), int(h.NSCount)
	total := an + ns + int(h.ARCount)
	for i := 0; i < total; i++ {
		start := off
		if off, err = SkipName(msg, off); err != nil {
			return err
		}
		if off+10 > len(msg) {
			return ErrShort
		}
		rr := RR{
			NameOff: start,
			Type:    be16(msg[off:]),
			Class:   be16(msg[off+2:]),
			TTL:     be32(msg[off+4:]),
			TTLOff:  off + 4,
			RDStart: off + 10,
		}
		rr.RDEnd = rr.RDStart + int(be16(msg[off+8:]))
		if rr.RDEnd > len(msg) {
			return ErrShort
		}
		switch {
		case i < an:
			rr.Section = SectionAnswer
		case i < an+ns:
			rr.Section = SectionAuthority
		default:
			rr.Section = SectionAdditional
		}
		off = rr.RDEnd
		if !fn(rr) {
			return nil
		}
	}
	return nil
}

// WalkRRs returns the location of every resource record in msg.
func WalkRRs(msg []byte) ([]RR, error) {
	var rrs []RR
	err := forEachRR(msg, func(rr RR) bool {
		rrs = append(rrs, rr)
		return true
	})
	if err != nil {
		return nil, err
	}
	return rrs, nil
}

// EDNSInfo describes the OPT pseudo-record of a message.
type EDNSInfo struct {
	Present bool
	UDPSize uint16
	DO      bool
}

// EDNS returns the EDNS(0) parameters of msg, if any.
func EDNS(msg []byte) EDNSInfo {
	var info EDNSInfo
	_ = forEachRR(msg, func(rr RR) bool {
		if rr.Section == SectionAdditional && rr.Type == TypeOPT {
			info = EDNSInfo{Present: true, UDPSize: rr.Class, DO: rr.TTL&0x8000 != 0}
			return false
		}
		return true
	})
	return info
}

// MapTTLs rewrites the TTL of every non-OPT record in place.
func MapTTLs(msg []byte, f func(typ uint16, ttl uint32) uint32) error {
	return forEachRR(msg, func(rr RR) bool {
		if rr.Type != TypeOPT {
			binary.BigEndian.PutUint32(msg[rr.TTLOff:], f(rr.Type, rr.TTL))
		}
		return true
	})
}

// SOAMinimum returns the MINIMUM field of an SOA record.
func SOAMinimum(msg []byte, rr RR) (uint32, bool) {
	if rr.Type != TypeSOA {
		return 0, false
	}
	p, err := SkipName(msg, rr.RDStart)
	if err != nil {
		return 0, false
	}
	if p, err = SkipName(msg, p); err != nil {
		return 0, false
	}
	if p+20 > rr.RDEnd {
		return 0, false
	}
	return be32(msg[p+16:]), true
}

// StripOPT removes a trailing OPT record (used when the client did not
// speak EDNS but the upstream answer carries one). Messages whose OPT is not
// the last record are returned unchanged.
func StripOPT(msg []byte) []byte {
	rrs, err := WalkRRs(msg)
	if err != nil {
		return msg
	}
	for i, rr := range rrs {
		if rr.Type == TypeOPT && rr.Section == SectionAdditional && i == len(rrs)-1 && rr.RDEnd == len(msg) {
			out := msg[:rr.NameOff]
			put16(out[10:], be16(out[10:])-1)
			return out
		}
	}
	return msg
}
