// Package testutil provides an in-process fake DNS server for tests.
package testutil

import (
	"encoding/binary"
	"net"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"ariadns/internal/dnsmsg"
)

// Responder produces the reply to req (nil = stay silent). transport is
// "udp" or "tcp".
type Responder func(req []byte, q dnsmsg.Question, transport string) []byte

// FakeDNS is a UDP+TCP DNS server on one loopback port.
type FakeDNS struct {
	Addr    string
	Queries atomic.Int64
	udp     *net.UDPConn
	tcp     net.Listener
	wg      sync.WaitGroup
}

// StartFakeDNS starts a fake server that is stopped when the test ends.
func StartFakeDNS(t testing.TB, r Responder) *FakeDNS {
	t.Helper()
	var (
		f   = &FakeDNS{}
		err error
	)
	for attempt := 0; attempt < 10; attempt++ {
		f.tcp, err = net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			continue
		}
		port := f.tcp.Addr().(*net.TCPAddr).Port
		f.udp, err = net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: port})
		if err == nil {
			break
		}
		_ = f.tcp.Close()
	}
	if err != nil {
		t.Fatalf("fake dns: %v", err)
	}
	f.Addr = f.tcp.Addr().String()

	f.wg.Add(2)
	go func() {
		defer f.wg.Done()
		buf := make([]byte, 65535)
		for {
			n, addr, err := f.udp.ReadFromUDPAddrPort(buf)
			if err != nil {
				return
			}
			req := append([]byte(nil), buf[:n]...)
			go func() {
				if resp := f.answer(r, req, "udp"); resp != nil {
					_, _ = f.udp.WriteToUDPAddrPort(resp, addr)
				}
			}()
		}
	}()
	go func() {
		defer f.wg.Done()
		for {
			c, err := f.tcp.Accept()
			if err != nil {
				return
			}
			go f.serveTCP(r, c)
		}
	}()
	t.Cleanup(func() {
		_ = f.udp.Close()
		_ = f.tcp.Close()
		f.wg.Wait()
	})
	return f
}

func (f *FakeDNS) answer(r Responder, req []byte, transport string) []byte {
	q, _, err := dnsmsg.ParseQuestion(req)
	if err != nil {
		return nil
	}
	f.Queries.Add(1)
	return r(req, q, transport)
}

func (f *FakeDNS) serveTCP(r Responder, c net.Conn) {
	defer c.Close()
	for {
		_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
		var lb [2]byte
		if _, err := readFull(c, lb[:]); err != nil {
			return
		}
		req := make([]byte, binary.BigEndian.Uint16(lb[:]))
		if _, err := readFull(c, req); err != nil {
			return
		}
		resp := f.answer(r, req, "tcp")
		if resp == nil {
			return
		}
		out := binary.BigEndian.AppendUint16(nil, uint16(len(resp)))
		_, _ = c.Write(append(out, resp...))
	}
}

func readFull(c net.Conn, b []byte) (int, error) {
	n := 0
	for n < len(b) {
		m, err := c.Read(b[n:])
		n += m
		if err != nil {
			return n, err
		}
	}
	return n, nil
}

// StandardResponder answers like a tiny authoritative server:
//
//	*.nxd.test   NXDOMAIN with an SOA (negative-cacheable)
//	fail.test    SERVFAIL
//	big.test     60 A records (needs TCP or EDNS for clients)
//	tc.test      TC=1 over UDP, full answer over TCP
//	slow.test    answers after 150ms
//	anything else  A record ip with the given ttl
func StandardResponder(ip string, ttl uint32) Responder {
	addr := netip.MustParseAddr(ip)
	return func(req []byte, q dnsmsg.Question, transport string) []byte {
		switch {
		case q.Name == "nxd.test" || strings.HasSuffix(q.Name, ".nxd.test"):
			return NXDomain(req, 300, 120)
		case q.Name == "fail.test":
			return dnsmsg.NewReply(req, dnsmsg.RcodeServerFailure)
		case q.Name == "big.test":
			var ips []netip.Addr
			for i := 0; i < 60; i++ {
				ips = append(ips, netip.AddrFrom4([4]byte{10, 9, 0, byte(i)}))
			}
			return dnsmsg.AddrReply(req, q, ips, ttl, false)
		case q.Name == "tc.test" && transport == "udp":
			resp := dnsmsg.NewReply(req, dnsmsg.RcodeSuccess)
			resp[2] |= 0x02 // TC
			return resp
		case q.Name == "slow.test":
			time.Sleep(150 * time.Millisecond)
		}
		return dnsmsg.AddrReply(req, q, []netip.Addr{addr}, ttl, false)
	}
}

// NXDomain builds an NXDOMAIN reply with an SOA in the authority section.
func NXDomain(req []byte, soaTTL, minimum uint32) []byte {
	_, qend, err := dnsmsg.ParseQuestion(req)
	if err != nil {
		return nil
	}
	out := dnsmsg.BeginReply(req, qend, dnsmsg.RcodeNameError, false)
	out = append(out, 0xC0, 0x0C)
	out = binary.BigEndian.AppendUint16(out, dnsmsg.TypeSOA)
	out = binary.BigEndian.AppendUint16(out, dnsmsg.ClassIN)
	out = binary.BigEndian.AppendUint32(out, soaTTL)
	rdata, _ := dnsmsg.AppendName(nil, "ns.test")
	rdata, _ = dnsmsg.AppendName(rdata, "hostmaster.test")
	for _, v := range []uint32{1, 3600, 600, 86400, minimum} {
		rdata = binary.BigEndian.AppendUint32(rdata, v)
	}
	out = binary.BigEndian.AppendUint16(out, uint16(len(rdata)))
	out = append(out, rdata...)
	dnsmsg.SetCount(out, dnsmsg.SectionAuthority, 1)
	return dnsmsg.FinishReply(out, req)
}
