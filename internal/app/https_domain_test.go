package app

import (
	"encoding/binary"
	"net/netip"
	"strings"
	"testing"

	"github.com/jimyag/socktrail/internal/capture"
	"github.com/jimyag/socktrail/internal/domain"
	"github.com/jimyag/socktrail/internal/tlsprobe"
)

func testClientHello(host string, ech bool) []byte {
	name := []byte(host)
	ext := binary.BigEndian.AppendUint16([]byte{0, 0}, uint16(5+len(name)))
	ext = binary.BigEndian.AppendUint16(ext, uint16(3+len(name)))
	ext = binary.BigEndian.AppendUint16(append(ext, 0), uint16(len(name)))
	ext = append(ext, name...)
	if ech {
		ext = append(ext, 0xfe, 0x0d, 0, 1, 0)
	}
	body := append(make([]byte, 34), 0, 0, 2, 0x13, 1, 1, 0)
	body[0], body[1] = 3, 3
	body = append(binary.BigEndian.AppendUint16(body, uint16(len(ext))), ext...)
	hello := append([]byte{1, 0, byte(len(body) >> 8), byte(len(body))}, body...)
	return append([]byte{22, 3, 3, byte(len(hello) >> 8), byte(len(hello))}, hello...)
}

func testDNSAnswer(name string, addr netip.Addr) []byte {
	msg := []byte{0, 1, 0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0}
	for label := range strings.SplitSeq(name, ".") {
		msg = append(append(msg, byte(len(label))), label...)
	}
	msg = append(msg, 0, 0, 1, 0, 1, 0xc0, 12, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4)
	return append(msg, addr.AsSlice()...)
}

func newTestCollector() *collector {
	return &collector{flows: make(map[flowKey]*flow), maxFlows: 10}
}

func tcpPacket(src, dst netip.AddrPort, seq uint32, payload []byte) capture.Packet {
	return capture.Packet{Source: src, Destination: dst, Protocol: 6, ACK: true, TCPSeq: seq, Payload: payload, IPBytes: uint32(52 + len(payload)), Outgoing: true}
}

func domainLabels(c *collector) []string {
	var labels []string
	for _, row := range (&terminalUI{}).rows(c, viewDomain) {
		labels = append(labels, row.label)
	}
	return labels
}

func TestTSOSegmentAfterClientHelloIsNotAParseFailure(t *testing.T) {
	client, server := netip.MustParseAddrPort("192.0.2.10:50000"), netip.MustParseAddrPort("192.0.2.20:443")
	c := newTestCollector()
	c.packet(capture.Packet{Source: client, Destination: server, Protocol: 6, SYN: true, TCPSeq: 100, IPBytes: 60, Outgoing: true})
	hello := testClientHello("upload.example.test", false)
	c.packet(tcpPacket(client, server, 101, hello))
	upload := tcpPacket(client, server, 101+uint32(len(hello)), make([]byte, 16*1024))
	upload.PayloadLen, upload.PayloadTruncated = 64*1024, true
	c.packet(upload)
	e := c.flows[keyFor(client, server, 6)].Domain.Evidence()
	if e.Group() != "upload.example.test" || e.ParseError != "" {
		t.Fatalf("upload after the ClientHello marked the flow incomplete: %+v", e)
	}
}

func TestECHOuterNameYieldsToProcessSNI(t *testing.T) {
	client, server := netip.MustParseAddrPort("192.0.2.10:50000"), netip.MustParseAddrPort("192.0.2.20:443")
	c := newTestCollector()
	c.packet(capture.Packet{Source: client, Destination: server, Protocol: 6, SYN: true, TCPSeq: 100, IPBytes: 60, Outgoing: true})
	c.packet(tcpPacket(client, server, 101, testClientHello("public.example.test", true)))
	if labels := domainLabels(c); len(labels) != 1 || labels[0] != "TLS public.example.test [ECH]" {
		t.Fatalf("ECH-offering ClientHello lost its on-wire name: %v", labels)
	}
	c.tlsEvent(tlsprobe.Event{PID: 7, Local: client, Remote: server, Hostname: "inner.example.test", Source: "openssl_set_sni"})
	f := c.flows[keyFor(client, server, 6)]
	if f.Domain.Evidence().Label() != "OPENSSL inner.example.test" || f.DomainConflict {
		t.Fatalf("process SNI should replace an ECH outer name without a conflict: %s conflict=%t", f.Domain.Evidence().Label(), f.DomainConflict)
	}
}

func TestLoopbackProxyCONNECTNamesTunnel(t *testing.T) {
	client, proxy := netip.MustParseAddrPort("127.0.0.1:51000"), netip.MustParseAddrPort("127.0.0.1:7890")
	c := newTestCollector()
	c.packet(capture.Packet{Source: client, Destination: proxy, Protocol: 6, SYN: true, TCPSeq: 100, IPBytes: 60, Outgoing: true})
	request := []byte("CONNECT github.com:443 HTTP/1.1\r\nHost: github.com:443\r\n\r\n")
	c.packet(tcpPacket(client, proxy, 101, request))
	c.packet(tcpPacket(client, proxy, 101+uint32(len(request)), testClientHello("github.com", false)))
	f := c.flows[keyFor(client, proxy, 6)]
	if labels := domainLabels(c); len(labels) != 1 || labels[0] != "TLS github.com" || f.AppSource != "ClientHello via CONNECT" {
		t.Fatalf("proxied HTTPS lost its name: rows=%v app=%s (%s)", labels, f.AppProtocol, f.AppSource)
	}
}

func TestClientHelloWithoutCapturedSYNIsParsed(t *testing.T) {
	client, server := netip.MustParseAddrPort("192.0.2.10:50000"), netip.MustParseAddrPort("192.0.2.20:443")
	other := netip.MustParseAddrPort("192.0.2.10:50001")
	c := newTestCollector()
	c.packet(tcpPacket(client, server, 5000, testClientHello("late.example.test", false)))
	c.packet(tcpPacket(other, server, 9000, append([]byte{23, 3, 3, 0, 32}, make([]byte, 32)...)))
	labels := strings.Join(domainLabels(c), "|")
	if !strings.Contains(labels, "TLS late.example.test") || !strings.Contains(labels, "TLS handshake not captured") {
		t.Fatalf("SYN-less ClientHello or pre-existing TLS flow missing: %s", labels)
	}
}

func TestDNSAnswerOnLoopbackNamesFlowOnOtherInterface(t *testing.T) {
	serverAddr := netip.MustParseAddr("198.51.100.7")
	dns := new(domain.DNSCache)
	lo, eth := newTestCollector(), newTestCollector()
	lo.dns, eth.dns = dns, dns
	lo.packet(capture.Packet{Source: netip.MustParseAddrPort("127.0.0.1:53"), Destination: netip.MustParseAddrPort("127.0.0.1:40000"), Protocol: 17, Payload: testDNSAnswer("api.example.test", serverAddr), IPBytes: 100})
	server := netip.AddrPortFrom(serverAddr, 443)
	existing := netip.MustParseAddrPort("192.0.2.10:50000")
	eth.packet(tcpPacket(existing, server, 9000, append([]byte{23, 3, 3, 0, 32}, make([]byte, 32)...)))
	fresh := netip.MustParseAddrPort("192.0.2.10:50001")
	eth.packet(capture.Packet{Source: fresh, Destination: server, Protocol: 6, SYN: true, TCPSeq: 100, IPBytes: 60, Outgoing: true})
	eth.packet(tcpPacket(fresh, server, 101, testClientHello("sni.example.test", false)))
	eth.attachDNSHints()
	labels := strings.Join(domainLabels(eth), "|")
	if !strings.Contains(labels, "DNS api.example.test") || !strings.Contains(labels, "TLS sni.example.test") {
		t.Fatalf("DNS hint missing or replaced SNI: %s", labels)
	}
	coverage := httpsCoverage(eth.allFlows())
	if !strings.HasPrefix(coverage, "TLS/QUIC named 100% of") || !strings.Contains(coverage, "DNS hint") {
		t.Fatalf("coverage line: %s", coverage)
	}
	f := eth.flows[keyFor(existing, server, 6)]
	f.Preexisting = true
	if coverage := httpsCoverage(eth.allFlows()); !strings.HasPrefix(coverage, "TLS/QUIC named 100% of") || !strings.Contains(coverage, "B on connections open before start") {
		t.Fatalf("connection open before start not counted apart: %s", coverage)
	}
	if line := evidenceLine(f, eth); !strings.Contains(line, "DNS names for 198.51.100.7: api.example.test") {
		t.Fatalf("evidence line: %s", line)
	}
}

func TestEncryptedDNSClassification(t *testing.T) {
	client := netip.MustParseAddrPort("192.0.2.10:50000")
	for _, tc := range []struct {
		name, target, kind string
		protocol           uint8
	}{
		{"DoT", "192.0.2.20:853", "DoT", 6},
		{"DoQ", "192.0.2.20:853", "DoQ", 17},
	} {
		t.Run(tc.name, func(t *testing.T) {
			target := netip.MustParseAddrPort(tc.target)
			f := &flow{Key: keyFor(client, target, tc.protocol), Initiator: client, Target: target, AppProtocol: "TLS"}
			chooseDomain(f)
			first := f.Domain
			chooseDomain(f)
			if e := f.Domain.Evidence(); f.Domain != first || e.EncryptedDNS == nil || *e.EncryptedDNS != tc.kind || e.Named() {
				t.Fatalf("encrypted DNS evidence: %+v", e)
			}
		})
	}
	opaqueTarget := netip.MustParseAddrPort("192.0.2.20:853")
	opaque := domain.New(1)
	opaque.Add(1, []byte("opaque application bytes"))
	fOpaque := &flow{Key: keyFor(client, opaqueTarget, 6), Initiator: client, Target: opaqueTarget, WireDomain: opaque, WireClient: client}
	chooseDomain(fOpaque)
	if e := fOpaque.Domain.Evidence(); !e.Listed() || e.Label() != "TLS encrypted DNS [DoT]" {
		t.Fatalf("opaque DoT evidence: %+v, label %q", e, e.Label())
	}
	target := netip.MustParseAddrPort("192.0.2.20:443")
	f := &flow{Key: keyFor(client, target, 6), Initiator: client, Target: target, ProcessDomain: domain.NewOpenSSLSNI("dns.google")}
	chooseDomain(f)
	if e := f.Domain.Evidence(); e.EncryptedDNS == nil || *e.EncryptedDNS != "DoH" || e.Group() != "dns.google" {
		t.Fatalf("built-in DoH evidence: %+v", e)
	}
	extraDoHNames = []string{"resolver.example.test"}
	t.Cleanup(func() { extraDoHNames = nil })
	f.ProcessDomain = domain.NewOpenSSLSNI("resolver.example.test")
	chooseDomain(f)
	if e := f.Domain.Evidence(); e.EncryptedDNS == nil || *e.EncryptedDNS != "DoH" {
		t.Fatalf("custom DoH evidence: %+v", e)
	}
}
