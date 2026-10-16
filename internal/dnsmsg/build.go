package dnsmsg

import (
	"encoding/binary"
	"net/netip"
	"strings"
)

// AppendName appends the uncompressed wire form of name to b. It accepts
// the \DDD escapes produced by ReadName.
func AppendName(b []byte, name string) ([]byte, error) {
	name = strings.TrimSuffix(name, ".")
	if name == "" {
		return append(b, 0), nil
	}
	total := 1
	label := make([]byte, 0, 63)
	flush := func() error {
		if len(label) == 0 || len(label) > 63 {
			return ErrName
		}
		total += len(label) + 1
		b = append(b, byte(len(label)))
		b = append(b, label...)
		label = label[:0]
		return nil
	}
	for i := 0; i < len(name); i++ {
		c := name[i]
		switch c {
		case '.':
			if err := flush(); err != nil {
				return nil, err
			}
		case '\\':
			if i+3 >= len(name) {
				return nil, ErrName
			}
			v := 0
			for _, d := range name[i+1 : i+4] {
				if d < '0' || d > '9' {
					return nil, ErrName
				}
				v = v*10 + int(d-'0')
			}
			if v > 255 {
				return nil, ErrName
			}
			label = append(label, byte(v))
			i += 3
		default:
			label = append(label, c)
		}
		if len(label) > 63 {
			return nil, ErrName
		}
	}
	if err := flush(); err != nil {
		return nil, err
	}
	if total > 255 {
		return nil, ErrName
	}
	return append(b, 0), nil
}

// NewQuery builds a recursive query. With edns set it advertises a 1232-byte
// UDP payload and, if do is true, the DNSSEC-OK bit.
func NewQuery(id uint16, name string, qtype uint16, edns, do bool) ([]byte, error) {
	b := make([]byte, HeaderLen, 64)
	put16(b[0:], id)
	put16(b[2:], FlagRD)
	put16(b[4:], 1)
	b, err := AppendName(b, name)
	if err != nil {
		return nil, err
	}
	b = binary.BigEndian.AppendUint16(b, qtype)
	b = binary.BigEndian.AppendUint16(b, ClassIN)
	if edns {
		put16(b[10:], 1)
		var flags uint16
		if do {
			flags = 0x8000
		}
		b = append(b, 0, 0, 0x29, 0x04, 0xD0, 0, 0)
		b = binary.BigEndian.AppendUint16(b, flags)
		b = append(b, 0, 0)
	}
	return b, nil
}

// HeaderReply builds a header-only reply (used when the question cannot be
// parsed).
func HeaderReply(req []byte, rcode int) []byte {
	out := make([]byte, HeaderLen)
	if len(req) >= 2 {
		copy(out, req[:2])
	}
	flags := FlagQR | FlagRA | uint16(rcode&0xF)
	if len(req) >= 4 {
		rf := be16(req[2:])
		flags |= rf & FlagRD
		flags |= rf & 0x7800
	}
	put16(out[2:], flags)
	return out
}

// BeginReply returns a reply skeleton: header plus the request's question,
// no records. Append records, adjust the counts, then call FinishReply.
func BeginReply(req []byte, qend, rcode int, aa bool) []byte {
	out := make([]byte, qend, qend+96)
	copy(out, req[:qend])
	flags := FlagQR | FlagRA | uint16(rcode&0xF)
	rf := be16(req[2:])
	flags |= rf & FlagRD
	flags |= rf & 0x7800
	if aa {
		flags |= FlagAA
	}
	put16(out[2:], flags)
	put16(out[4:], 1)
	put16(out[6:], 0)
	put16(out[8:], 0)
	put16(out[10:], 0)
	return out
}

// SetCount sets the record count of a section (SectionAnswer, ...).
func SetCount(msg []byte, section int, n int) {
	put16(msg[6+2*section:], uint16(n))
}

// FinishReply echoes an OPT record when the request carried one.
func FinishReply(out, req []byte) []byte {
	if EDNS(req).Present {
		out = append(out, 0, 0, 0x29, 0x04, 0xD0, 0, 0, 0, 0, 0, 0)
		put16(out[10:], be16(out[10:])+1)
	}
	return out
}

// NewReply builds an empty reply with the given response code.
func NewReply(req []byte, rcode int) []byte {
	_, qend, err := ParseQuestion(req)
	if err != nil {
		return HeaderReply(req, rcode)
	}
	return FinishReply(BeginReply(req, qend, rcode, false), req)
}

// AddrReply answers an A or AAAA question with the matching addresses from
// ips. If none match it produces a NODATA reply (NOERROR, no records).
func AddrReply(req []byte, q Question, ips []netip.Addr, ttl uint32, aa bool) []byte {
	_, qend, err := ParseQuestion(req)
	if err != nil {
		return HeaderReply(req, RcodeServerFailure)
	}
	out := BeginReply(req, qend, RcodeSuccess, aa)
	n := 0
	for _, ip := range ips {
		ip = ip.Unmap()
		var rdata []byte
		switch {
		case q.Type == TypeA && ip.Is4():
			a := ip.As4()
			rdata = a[:]
		case q.Type == TypeAAAA && ip.Is6():
			a := ip.As16()
			rdata = a[:]
		default:
			continue
		}
		out = append(out, 0xC0, 0x0C)
		out = binary.BigEndian.AppendUint16(out, q.Type)
		out = binary.BigEndian.AppendUint16(out, ClassIN)
		out = binary.BigEndian.AppendUint32(out, ttl)
		out = binary.BigEndian.AppendUint16(out, uint16(len(rdata)))
		out = append(out, rdata...)
		n++
	}
	SetCount(out, SectionAnswer, n)
	return FinishReply(out, req)
}

// Truncate shrinks resp to a header plus question with TC set when it does
// not fit in max bytes.
func Truncate(resp []byte, max int) []byte {
	if len(resp) <= max {
		return resp
	}
	_, qend, err := ParseQuestion(resp)
	if err != nil {
		qend = HeaderLen
	}
	out := make([]byte, qend)
	copy(out, resp[:qend])
	put16(out[2:], be16(out[2:])|FlagTC)
	if qend == HeaderLen {
		put16(out[4:], 0)
	}
	put16(out[6:], 0)
	put16(out[8:], 0)
	put16(out[10:], 0)
	return out
}

// PatchFlags makes a cached or shared response fit the asking client: RD is
// copied from the request and RA is set.
func PatchFlags(resp, req []byte) {
	if len(resp) < HeaderLen || len(req) < HeaderLen {
		return
	}
	f := be16(resp[2:])
	f = (f &^ FlagRD) | (be16(req[2:]) & FlagRD) | FlagRA
	put16(resp[2:], f)
}

// RestoreQuestion copies the client's question bytes (with their original
// letter case, which "0x20" resolvers verify) into resp.
func RestoreQuestion(resp, req []byte) {
	_, rend, err1 := ParseQuestion(resp)
	_, qend, err2 := ParseQuestion(req)
	if err1 != nil || err2 != nil || rend != qend {
		return
	}
	copy(resp[HeaderLen:qend], req[HeaderLen:qend])
}
