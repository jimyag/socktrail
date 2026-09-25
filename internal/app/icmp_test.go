package app

import (
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/jimyag/socktrail/internal/capture"
	"github.com/jimyag/socktrail/internal/probe"
)

func echo(source, target netip.AddrPort, request bool, seq uint16, at time.Time) capture.Packet {
	kind := uint8(0)
	if request {
		kind = 8
	}
	return capture.Packet{Source: source, Destination: target, Protocol: 1, ICMPType: kind, ICMPHasEcho: true, ICMPID: 7, ICMPSeq: seq, IPBytes: 84, CapturedAt: at}
}

// A local ping names its process whether the probe event or the captured
// request is processed first; the identifier ties them together.
func TestLocalPingNamesItsProcess(t *testing.T) {
	local, remote := netip.MustParseAddrPort("192.0.2.10:0"), netip.MustParseAddrPort("198.51.100.7:0")
	sent := probe.Event{
		Protocol: 1, Role: "out", Operation: "send", PID: 4242, StartNS: 1000, Process: "ping",
		Local: netip.AddrPortFrom(netip.IPv4Unspecified(), 7), Remote: remote,
	}
	for _, eventFirst := range []bool{true, false} {
		c := newTestCollector()
		request := echo(local, remote, true, 1, time.Now())
		request.Outgoing = true
		if eventFirst {
			c.event(sent)
		}
		c.packet(request)
		if !eventFirst {
			c.event(sent)
		}
		for _, f := range c.flows {
			if f.Client.PID != 4242 || f.Client.Name != "ping" {
				t.Fatalf("eventFirst=%t: echo flow client %+v", eventFirst, f.Client)
			}
		}
		// Another process pinging the same host uses another identifier.
		other := echo(local, remote, true, 1, time.Now())
		other.ICMPID, other.Outgoing = 8, true
		c.packet(other)
		if f := c.flows[packetKey(other)]; f == nil || f.Client.PID != 0 {
			t.Fatalf("eventFirst=%t: unrelated echo flow took the process: %+v", eventFirst, f)
		}
	}
}

// A ping flood from outside must stay one flow, not one per packet, so it
// cannot exhaust the flow index that other inbound traffic needs.
func TestEchoSessionIsOneFlowWithRTT(t *testing.T) {
	remote, local := netip.MustParseAddrPort("203.0.113.5:0"), netip.MustParseAddrPort("192.0.2.10:0")
	c := newTestCollector()
	start := time.Now()
	for seq := range uint16(100) {
		at := start.Add(time.Duration(seq) * time.Second)
		c.packet(echo(remote, local, true, seq, at))
		c.packet(echo(local, remote, false, seq, at.Add(3*time.Millisecond)))
	}
	if len(c.flows) != 1 || c.droppedFlow != 0 {
		t.Fatalf("ping session used %d flows (%d dropped)", len(c.flows), c.droppedFlow)
	}
	for _, f := range c.flows {
		name := icmpDescription(f)
		if f.Direction != "inbound" || f.Initiator != remote || !strings.Contains(name, "requests=100 replies=100") || !strings.Contains(name, "rtt=3ms") {
			t.Fatalf("echo summary: direction=%s initiator=%s %s", f.Direction, f.Initiator, name)
		}
	}
}

func TestICMPErrorMarksTheFlowItQuotes(t *testing.T) {
	scanner, local := netip.MustParseAddrPort("203.0.113.5:40000"), netip.MustParseAddrPort("192.0.2.10:9999")
	c := newTestCollector()
	c.packet(capture.Packet{Source: scanner, Destination: local, Protocol: 17, HasPorts: true, Payload: []byte("probe"), IPBytes: 33})
	c.packet(capture.Packet{
		Source: netip.AddrPortFrom(local.Addr(), 0), Destination: netip.AddrPortFrom(scanner.Addr(), 0), Protocol: 1, Outgoing: true,
		ICMPType: 3, ICMPCode: 3, QuotedProtocol: 17, QuotedSource: scanner, QuotedDestination: local, IPBytes: 61,
	})
	udp := c.flows[keyFor(scanner, local, 17)]
	if udp == nil || flowState(udp) != "port-unreachable" {
		t.Fatalf("inbound datagram to a closed port not marked: %+v", udp)
	}
	var names []string
	for _, f := range c.flows {
		if f.Key.Protocol == 1 {
			names = append(names, icmpDescription(f))
		}
	}
	if len(names) != 1 || names[0] != "port-unreachable for UDP 203.0.113.5:40000→192.0.2.10:9999" {
		t.Fatalf("ICMP error description: %v", names)
	}
}

func TestICMPNames(t *testing.T) {
	for _, tc := range []struct {
		protocol, kind, code uint8
		want                 string
	}{
		{1, 3, 4, "frag-needed"},
		{1, 3, 13, "admin-prohibited"},
		{1, 11, 0, "ttl-exceeded"},
		{1, 11, 1, "reassembly-timeout"},
		{58, 1, 4, "port-unreachable"},
		{58, 2, 0, "packet-too-big"},
		{58, 135, 0, "neighbor-solicitation"},
		{1, 42, 0, "type=42 code=0"},
	} {
		if got := icmpName(tc.protocol, tc.kind, tc.code); got != tc.want {
			t.Fatalf("icmpName(%d,%d,%d) = %q, want %q", tc.protocol, tc.kind, tc.code, got, tc.want)
		}
	}
}
