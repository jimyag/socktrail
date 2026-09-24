package main

import (
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/jimyag/socktrail/internal/capture"
)

// A scan against closed, filtered and UDP ports becomes one summary line for
// its source, and fills the flow table with disposable flows that the next
// connections evict instead of being dropped.
func TestScanIsSummarizedAndEvicted(t *testing.T) {
	scanner, local := netip.MustParseAddr("203.0.113.9"), netip.MustParseAddr("192.0.2.10")
	c := &collector{flows: make(map[flowKey]*flow), maxFlows: 50}
	now := time.Now()
	for port := range uint16(30) { // Closed ports answer with a reset.
		probe := netip.AddrPortFrom(scanner, 40000+port)
		target := netip.AddrPortFrom(local, 1000+port)
		c.packet(capture.Packet{Source: probe, Destination: target, Protocol: 6, HasPorts: true, SYN: true, TCPSeq: 1, IPBytes: 44, CapturedAt: now})
		c.packet(capture.Packet{Source: target, Destination: probe, Protocol: 6, HasPorts: true, RST: true, ACK: true, IPBytes: 40, Outgoing: true, CapturedAt: now})
	}
	for port := range uint16(15) { // Filtered ports never answer.
		c.packet(capture.Packet{Source: netip.AddrPortFrom(scanner, 41000+port), Destination: netip.AddrPortFrom(local, 2000+port), Protocol: 6, HasPorts: true, SYN: true, TCPSeq: 1, IPBytes: 44, CapturedAt: now})
	}
	udpProbe := capture.Packet{Source: netip.AddrPortFrom(scanner, 42000), Destination: netip.AddrPortFrom(local, 3000), Protocol: 17, HasPorts: true, IPBytes: 28, CapturedAt: now}
	c.packet(udpProbe)
	c.packet(capture.Packet{Source: netip.AddrPortFrom(local, 0), Destination: netip.AddrPortFrom(scanner, 0), Protocol: 1, ICMPType: 3, ICMPCode: 3, QuotedProtocol: 17,
		QuotedSource: udpProbe.Source, QuotedDestination: udpProbe.Destination, IPBytes: 56, Outgoing: true, CapturedAt: now})

	// The table is full: a real connection evicts old attempts instead of
	// being dropped, and the unanswered ones evicted count as such.
	client, server := netip.MustParseAddrPort("198.51.100.4:50000"), netip.AddrPortFrom(local, 443)
	for i := range uint16(10) {
		c.packet(capture.Packet{Source: netip.AddrPortFrom(client.Addr(), client.Port()+i), Destination: server, Protocol: 6, HasPorts: true, SYN: true, TCPSeq: 1, IPBytes: 60})
	}
	if c.droppedFlow != 0 || c.flows[keyFor(client, server, 6)] == nil {
		t.Fatalf("new connections dropped instead of evicting scan flows: dropped=%d", c.droppedFlow)
	}
	a := c.attempts[scanner]
	if a == nil || a.Refused != 31 || len(a.Ports) < 31 {
		t.Fatalf("scan summary: %+v", a)
	}
	c.expire(now.Add(10 * time.Minute))
	if a.Unanswered != 15 || len(a.Ports) != 46 {
		t.Fatalf("unanswered attempts: %+v", a)
	}
	var labels []string
	for _, row := range (&terminalUI{}).rows(c, viewSource) {
		labels = append(labels, row.label)
	}
	if got := strings.Join(labels, "|"); !strings.Contains(got, "203.0.113.9  tried 46 ports: refused 31, unanswered 15") {
		t.Fatalf("source view: %s", got)
	}
}
