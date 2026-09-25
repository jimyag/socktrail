package app

import (
	"net/netip"
	"testing"

	"github.com/jimyag/socktrail/internal/capture"
)

// A fragmented datagram from outside, such as a large DNS answer, must count
// toward one flow even though only its first fragment carries the ports.
func TestLaterFragmentsJoinTheFirstFragmentsFlow(t *testing.T) {
	remote, local := netip.MustParseAddrPort("203.0.113.5:53"), netip.MustParseAddrPort("192.0.2.10:40000")
	c := newTestCollector()
	c.packet(capture.Packet{Source: remote, Destination: local, Protocol: 17, HasPorts: true, Fragmented: true, FragmentID: 77, IPBytes: 1500})
	c.packet(capture.Packet{Source: netip.AddrPortFrom(remote.Addr(), 0), Destination: netip.AddrPortFrom(local.Addr(), 0), Protocol: 17, Fragmented: true, FragmentID: 77, FragmentOffset: 185, IPBytes: 700})
	if len(c.flows) != 1 {
		t.Fatalf("fragments split into %d flows", len(c.flows))
	}
	if f := c.flows[keyFor(remote, local, 17)]; f == nil || f.Packets != 2 || f.RX != 2200 {
		t.Fatalf("fragment bytes not joined: %+v", f)
	}
}

// A large ping is one echo request in several fragments; only the first
// carries the ICMP header that keys the echo flow.
func TestLaterFragmentsJoinTheirEchoFlow(t *testing.T) {
	remote, local := netip.AddrPortFrom(netip.MustParseAddr("203.0.113.5"), 0), netip.AddrPortFrom(netip.MustParseAddr("192.0.2.10"), 0)
	c := newTestCollector()
	c.packet(capture.Packet{Source: remote, Destination: local, Protocol: 1, ICMPType: 8, ICMPID: 7, ICMPSeq: 1, ICMPHasEcho: true, Fragmented: true, FragmentID: 9, IPBytes: 1500})
	c.packet(capture.Packet{Source: remote, Destination: local, Protocol: 1, Fragmented: true, FragmentID: 9, FragmentOffset: 185, IPBytes: 1500})
	if len(c.flows) != 1 {
		t.Fatalf("echo fragments split into %d flows", len(c.flows))
	}
	for _, f := range c.flows {
		if f.Packets != 2 || f.ICMP.Requests != 1 {
			t.Fatalf("fragment counted as another request or not joined: packets=%d requests=%d", f.Packets, f.ICMP.Requests)
		}
	}
}
