package dnsmsg

import (
	"fmt"
	"net/netip"
	"strconv"
	"strings"
)

var typeNames = map[uint16]string{
	TypeA: "A", TypeNS: "NS", TypeCNAME: "CNAME", TypeSOA: "SOA", TypePTR: "PTR",
	TypeMX: "MX", TypeTXT: "TXT", TypeAAAA: "AAAA", TypeSRV: "SRV", TypeOPT: "OPT",
	TypeSVCB: "SVCB", TypeHTTPS: "HTTPS", TypeANY: "ANY",
	43: "DS", 46: "RRSIG", 47: "NSEC", 48: "DNSKEY", 50: "NSEC3", 257: "CAA",
}

// TypeName returns the mnemonic of a record type ("A", "AAAA", "TYPE999").
func TypeName(t uint16) string {
	if s, ok := typeNames[t]; ok {
		return s
	}
	return "TYPE" + strconv.Itoa(int(t))
}

// ParseType is the inverse of TypeName.
func ParseType(s string) (uint16, bool) {
	s = strings.ToUpper(strings.TrimSpace(s))
	for t, n := range typeNames {
		if n == s {
			return t, true
		}
	}
	if rest, ok := strings.CutPrefix(s, "TYPE"); ok {
		if v, err := strconv.ParseUint(rest, 10, 16); err == nil {
			return uint16(v), true
		}
	}
	return 0, false
}

// RcodeName returns the mnemonic of a response code.
func RcodeName(rc int) string {
	switch rc {
	case RcodeSuccess:
		return "NOERROR"
	case RcodeFormatError:
		return "FORMERR"
	case RcodeServerFailure:
		return "SERVFAIL"
	case RcodeNameError:
		return "NXDOMAIN"
	case RcodeNotImplemented:
		return "NOTIMP"
	case RcodeRefused:
		return "REFUSED"
	}
	return "RCODE" + strconv.Itoa(rc)
}

// FQDN renders a name as a fully-qualified domain name with a trailing dot.
func FQDN(name string) string {
	if name == "" {
		return "."
	}
	return name + "."
}

// FormatRData renders the data of rr in presentation format.
func FormatRData(msg []byte, rr RR) string {
	rd := msg[rr.RDStart:rr.RDEnd]
	switch rr.Type {
	case TypeA:
		if len(rd) == 4 {
			return netip.AddrFrom4([4]byte(rd)).String()
		}
	case TypeAAAA:
		if len(rd) == 16 {
			return netip.AddrFrom16([16]byte(rd)).String()
		}
	case TypeCNAME, TypeNS, TypePTR:
		if n, _, err := ReadName(msg, rr.RDStart); err == nil {
			return FQDN(n)
		}
	case TypeMX:
		if len(rd) >= 3 {
			if n, _, err := ReadName(msg, rr.RDStart+2); err == nil {
				return fmt.Sprintf("%d %s", be16(rd), FQDN(n))
			}
		}
	case TypeTXT:
		var parts []string
		for i := 0; i < len(rd); {
			l := int(rd[i])
			i++
			if i+l > len(rd) {
				break
			}
			parts = append(parts, strconv.Quote(string(rd[i:i+l])))
			i += l
		}
		return strings.Join(parts, " ")
	case TypeSOA:
		m, p, err := ReadName(msg, rr.RDStart)
		if err != nil {
			break
		}
		r, p2, err := ReadName(msg, p)
		if err != nil || p2+20 > rr.RDEnd {
			break
		}
		return fmt.Sprintf("%s %s %d %d %d %d %d", FQDN(m), FQDN(r),
			be32(msg[p2:]), be32(msg[p2+4:]), be32(msg[p2+8:]), be32(msg[p2+12:]), be32(msg[p2+16:]))
	}
	return fmt.Sprintf("\\# %d %x", len(rd), rd)
}
