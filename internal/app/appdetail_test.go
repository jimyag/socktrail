package app

import (
	"encoding/binary"
	"fmt"
	"net/netip"
	"strings"
	"testing"
	"time"

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

// A response pairs with its query by transaction ID; the flow keeps the
// latest and the fastest round trip.
func TestDNSRoundTrip(t *testing.T) {
	client, resolver := netip.MustParseAddrPort("192.0.2.10:40002"), netip.MustParseAddrPort("192.0.2.53:53")
	c := newTestCollector()
	start := time.Now()
	exchange := func(at, rtt time.Duration) {
		query := append(dnsQuery("rtt.example.test", 1), 0, 1)
		c.packet(capture.Packet{Source: client, Destination: resolver, Protocol: 17, HasPorts: true, Payload: query, IPBytes: 60, Outgoing: true, CapturedAt: start.Add(at)})
		answer := append(dnsQuery("rtt.example.test", 1), 0, 1)
		answer[2], answer[3] = 0x81, 0x80
		c.packet(capture.Packet{Source: resolver, Destination: client, Protocol: 17, HasPorts: true, Payload: answer, IPBytes: 60, CapturedAt: start.Add(at + rtt)})
	}
	exchange(0, 8*time.Millisecond)
	exchange(time.Second, 15200*time.Microsecond)
	if got := flowName(c.flows[keyFor(client, resolver, 17)]); got != "A rtt.example.test NOERROR queries=2 rtt=15.2ms min=8ms" {
		t.Fatalf("DNS flow detail %q", got)
	}
}

func TestDNSRecentQueriesBoundedAndJSON(t *testing.T) {
	client, resolver := netip.MustParseAddrPort("192.0.2.10:40003"), netip.MustParseAddrPort("192.0.2.53:53")
	answerAddr := netip.MustParseAddr("198.51.100.7")
	c := newTestCollector()
	c.dns = new(domain.DNSCache)
	start := time.Now()
	for i := range 10 {
		name := fmt.Sprintf("name%d.example.test", i)
		query := append(dnsQuery(name, 1), 0, 1)
		at := start.Add(time.Duration(i) * time.Second)
		c.packet(capture.Packet{Source: client, Destination: resolver, Protocol: 17, HasPorts: true, Payload: query, IPBytes: 60, Outgoing: true, CapturedAt: at})
		answer := testDNSAnswer(name, answerAddr)
		answer[1] = 2
		if i == 9 {
			answer = append(dnsQuery(name, 1), 0, 1)
			answer[2], answer[3] = 0x81, 0x83
		}
		c.packet(capture.Packet{Source: resolver, Destination: client, Protocol: 17, HasPorts: true, Payload: answer, IPBytes: 100, CapturedAt: at.Add(12 * time.Millisecond)})
	}
	f := c.flows[keyFor(client, resolver, 17)]
	if f.DNS.Queries != 10 || len(f.DNS.recentQueries()) != 8 || f.DNS.recentQueries()[0].name != "name9.example.test" {
		t.Fatalf("recent queries: %+v", f.DNS)
	}
	row := jsonFlowFor(f, 1, nil, nil)
	if row.DNS == nil || len(row.DNS.Recent) != 8 || row.DNS.Recent[0].RCode != "NXDOMAIN" || row.DNS.Recent[0].RTTMicros != 12000 || row.DNS.Recent[1].Addresses[0] != answerAddr.String() {
		t.Fatalf("structured DNS history: %+v", row.DNS)
	}
	if got := c.dns.Lookup(answerAddr, start.Add(8*time.Second), false); got != "name8.example.test" {
		t.Fatalf("DNS hint from shared response parse: %q", got)
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
