package main

import (
	"encoding/binary"
	"net/netip"
	"strings"
	"testing"

	"github.com/jimyag/socktrail/internal/capture"
	"github.com/jimyag/socktrail/internal/domain"
)

func dnsQuery(name string, qtype uint16) []byte {
	msg := []byte{0, 2, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0}
	for label := range strings.SplitSeq(name, ".") {
		msg = append(append(msg, byte(len(label))), label...)
	}
	return binary.BigEndian.AppendUint16(append(msg, 0), qtype)
}

func TestDNSFlowShowsQuestionAndAnswer(t *testing.T) {
	client, resolver := netip.MustParseAddrPort("192.0.2.10:40000"), netip.MustParseAddrPort("192.0.2.53:53")
	c := newTestCollector()
	c.packet(capture.Packet{Source: client, Destination: resolver, Protocol: 17, HasPorts: true, Payload: append(dnsQuery("missing.example.test", 28), 0, 1), IPBytes: 60, Outgoing: true})
	nxdomain := append(dnsQuery("missing.example.test", 28), 0, 1)
	nxdomain[2], nxdomain[3] = 0x81, 0x83
	c.packet(capture.Packet{Source: resolver, Destination: client, Protocol: 17, HasPorts: true, Payload: nxdomain, IPBytes: 60})
	f := c.flows[keyFor(client, resolver, 17)]
	if got := flowName(f); got != "AAAA missing.example.test NXDOMAIN failed=1" {
		t.Fatalf("DNS flow detail %q", got)
	}
}

// DNS over TCP carries each message after a two-byte length; its answers
// also name later connections.
func TestDNSOverTCP(t *testing.T) {
	client, resolver := netip.MustParseAddrPort("192.0.2.10:40001"), netip.MustParseAddrPort("192.0.2.53:53")
	server := netip.MustParseAddr("198.51.100.7")
	c := newTestCollector()
	c.dns = new(domain.DNSCache)
	frame := func(msg []byte) []byte { return append(binary.BigEndian.AppendUint16(nil, uint16(len(msg))), msg...) }
	c.packet(capture.Packet{Source: client, Destination: resolver, Protocol: 6, HasPorts: true, SYN: true, TCPSeq: 1, IPBytes: 60, Outgoing: true})
	c.packet(tcpPacket(client, resolver, 2, frame(append(dnsQuery("tcp.example.test", 1), 0, 1))))
	c.packet(capture.Packet{Source: resolver, Destination: client, Protocol: 6, HasPorts: true, ACK: true, TCPSeq: 900, Payload: frame(testDNSAnswer("tcp.example.test", server)), IPBytes: 120})
	if f := c.flows[keyFor(client, resolver, 6)]; f.AppProtocol != "DNS" || flowName(f) != "A tcp.example.test NOERROR" {
		t.Fatalf("TCP DNS flow: app=%s detail=%q", f.AppProtocol, flowName(f))
	}
	if name := c.dns.Lookup(server, c.flows[keyFor(client, resolver, 6)].First, true); name != "tcp.example.test" {
		t.Fatalf("TCP DNS answer did not reach the name hints: %q", name)
	}
}

// The client's identification string often names the tool behind a login
// attempt; control bytes in it never reach the terminal.
func TestSSHBannersOfBothSides(t *testing.T) {
	client, server := netip.MustParseAddrPort("203.0.113.5:50000"), netip.MustParseAddrPort("192.0.2.10:22")
	c := newTestCollector()
	c.packet(capture.Packet{Source: client, Destination: server, Protocol: 6, HasPorts: true, SYN: true, TCPSeq: 1, IPBytes: 60})
	c.packet(capture.Packet{Source: server, Destination: client, Protocol: 6, HasPorts: true, ACK: true, TCPSeq: 700, Payload: []byte("SSH-2.0-OpenSSH_8.9p1 Ubuntu-3\r\n"), IPBytes: 84, Outgoing: true})
	c.packet(capture.Packet{Source: client, Destination: server, Protocol: 6, HasPorts: true, ACK: true, TCPSeq: 2, Payload: []byte("SSH-2.0-Go\x1b[31m\r\n"), IPBytes: 70})
	f := c.flows[keyFor(client, server, 6)]
	if got := flowName(f); f.AppProtocol != "SSH" || got != "client=Go[31m server=OpenSSH_8.9p1 Ubuntu-3" {
		t.Fatalf("SSH detail %q (app %s)", got, f.AppProtocol)
	}
}
