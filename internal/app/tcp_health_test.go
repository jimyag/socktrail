package app

import (
	"net/netip"
	"testing"
	"time"

	"github.com/jimyag/socktrail/internal/capture"
	"github.com/jimyag/socktrail/internal/probe"
)

func TestTCPHealthHandshakeAndSequenceOverlap(t *testing.T) {
	local := netip.MustParseAddrPort("192.0.2.10:40000")
	remote := netip.MustParseAddrPort("198.51.100.20:443")
	start := time.Unix(100, 0)
	var health tcpHealth
	health.observe(capture.Packet{Protocol: 6, Source: local, Destination: remote, Outgoing: true, SYN: true, TCPSeq: 1000, CapturedAt: start}, false)
	health.observe(capture.Packet{Protocol: 6, Source: local, Destination: remote, Outgoing: true, SYN: true, TCPSeq: 1000, CapturedAt: start.Add(50 * time.Millisecond)}, false)
	health.observe(capture.Packet{Protocol: 6, Source: remote, Destination: local, SYN: true, ACK: true, TCPAck: 1001, CapturedAt: start.Add(100 * time.Millisecond)}, false)
	if health.SynRTT != 100*time.Millisecond || health.Retransmits != 1 {
		t.Fatalf("SYN sample or retransmission count wrong: %+v", health)
	}
	for _, seq := range []uint32{1001, 1101, 1041, 1001} {
		health.observe(capture.Packet{Protocol: 6, Source: local, Destination: remote, TCPSeq: seq, Payload: make([]byte, 50)}, false)
	}
	if health.Retransmits != 3 { // The 1041 overlap and repeated 1001 segment.
		t.Fatalf("out-of-order or repeated data classified incorrectly: %d", health.Retransmits)
	}
	health.observe(capture.Packet{Protocol: 6, Source: remote, Destination: local, TCPSeq: 1001, Payload: make([]byte, 50)}, false)
	if health.Retransmits != 3 {
		t.Fatalf("opposite direction confused with retransmission: %d", health.Retransmits)
	}
}

func TestTCPHealthUnknownWhenHandshakeNotSeen(t *testing.T) {
	var health tcpHealth
	health.observe(capture.Packet{Protocol: 6, SYN: true, ACK: true, TCPAck: 1001}, false)
	if health.SynRTT != 0 || formatSYNRTT(health.SynRTT) != "-" {
		t.Fatalf("unobserved handshake produced RTT: %+v", health)
	}
}

// A local socket's TCP events carry the kernel's view of it: its RTT
// replaces the handshake sample, and its counters never go back when events
// from different CPUs arrive out of order.
func TestKernelTCPStateOfLocalEnds(t *testing.T) {
	client, server := netip.MustParseAddrPort("127.0.0.1:40000"), netip.MustParseAddrPort("127.0.0.1:8080")
	c := newTestCollector()
	c.packet(capture.Packet{Source: client, Destination: server, Protocol: 6, HasPorts: true, SYN: true, TCPSeq: 1, IPBytes: 60, Outgoing: true})
	f := c.flows[keyFor(client, server, 6)]
	send := func(local, remote netip.AddrPort, info probe.TCPInfo) {
		c.event(probe.Event{Protocol: 6, Role: "out", Operation: "send", AppBytes: 10, PID: 7, StartNS: 1, Local: local, Remote: remote, TCP: info})
	}
	send(client, server, probe.TCPInfo{RTT: 2 * time.Millisecond, RTTVar: time.Millisecond, Cwnd: 10, SegsOut: 200, Retransmits: 4})
	send(client, server, probe.TCPInfo{RTT: 3 * time.Millisecond, RTTVar: time.Millisecond, Cwnd: 12, SegsOut: 150, Retransmits: 3})
	send(server, client, probe.TCPInfo{RTT: 5 * time.Millisecond, Cwnd: 10, SegsOut: 10, Retransmits: 1})
	if rtt, source := flowRTT(f); rtt != 3*time.Millisecond || source != "kernel" {
		t.Fatalf("RTT %s from %q, want the client's latest 3ms from the kernel", rtt, source)
	}
	if retx, source := retransmits(f); retx != 5 || source != "kernel" {
		t.Fatalf("retransmits %d from %q, want both ends' 4+1", retx, source)
	}
	if got := kernelDetail(f); got != "127.0.0.1:40000 rtt 3ms±1ms cwnd 12 sent 200 retrans 4 (2.00%); 127.0.0.1:8080 rtt 5ms±- cwnd 10 sent 10 retrans 1 (10.00%)" {
		t.Fatalf("kernel detail %q", got)
	}
}

func TestKernelTCPStateArrivesBeforeCapturedPacket(t *testing.T) {
	client, server := netip.MustParseAddrPort("127.0.0.1:40000"), netip.MustParseAddrPort("127.0.0.1:8080")
	c := newTestCollector()
	c.roles = make(map[flowKey]roles)
	c.roleSeen = make(map[flowKey]time.Time)
	c.event(probe.Event{Protocol: 6, Role: "out", Operation: "connect", PID: 7, StartNS: 1, Process: "curl", Local: client, Remote: server})
	c.event(probe.Event{Protocol: 6, Role: "out", Operation: "send", AppBytes: 10, PID: 7, StartNS: 1, Process: "curl", Local: client, Remote: server, TCP: probe.TCPInfo{RTT: 2 * time.Millisecond}})
	c.packet(capture.Packet{Source: client, Destination: server, Protocol: 6, HasPorts: true, SYN: true, TCPSeq: 1, IPBytes: 60, Outgoing: true})
	f := c.flows[keyFor(client, server, 6)]
	if f.Client.Name != "curl" {
		t.Fatalf("client = %+v, want curl", f.Client)
	}
	if rtt, source := flowRTT(f); rtt != 2*time.Millisecond || source != "kernel" {
		t.Fatalf("RTT %s from %q, want the earlier kernel sample", rtt, source)
	}
}

func TestTCPLimitFromKernelCounters(t *testing.T) {
	base := probe.TCPInfo{
		RTT: 20 * time.Millisecond, SegsOut: 100,
		Metrics: probe.TCPMetrics{SampledNS: 1, HZ: 1000, Busy: 1000, DeliveryRate: 1_000_000},
	}
	if got := tcpLimit(probe.TCPInfo{}); got != "" {
		t.Fatalf("idle socket limit = %q", got)
	}
	base.Metrics.RwndLimited = 630
	if got := tcpLimit(base); got != "peer window" {
		t.Fatalf("receiver window limit = %q", got)
	}
	base.Metrics.Busy, base.Metrics.RwndLimited = 1, 1
	if got := tcpLimit(base); got != "" {
		t.Fatalf("one jiffy of window pressure classified as %q", got)
	}
	base.Metrics.Busy = 1000
	base.Metrics.RwndLimited, base.Metrics.SndbufLimited = 0, 400
	if got := tcpLimit(base); got != "send buffer" {
		t.Fatalf("sender buffer limit = %q", got)
	}
	base.Metrics.SndbufLimited, base.Metrics.Busy, base.Metrics.AppLimited = 0, 10, true
	if got := tcpLimit(base); got != "application" {
		t.Fatalf("application limit = %q", got)
	}
	base.Metrics.AppLimited, base.Retransmits = false, 6
	if got := tcpLimit(base); got != "network" {
		t.Fatalf("network limit = %q", got)
	}
}

func TestTCPMetricKeepsKernelState(t *testing.T) {
	var h tcpHealth
	h.observeKernel(0, probe.TCPInfo{RTT: 2 * time.Millisecond, SegsOut: 10})
	h.observeKernel(0, probe.TCPInfo{Metrics: probe.TCPMetrics{SampledNS: 1_000_000_000, Jiffies: 1000, Busy: 100}})
	h.observeKernel(0, probe.TCPInfo{Metrics: probe.TCPMetrics{SampledNS: 2_000_000_000, Jiffies: 2000, Busy: 300}})
	h.observeKernel(0, probe.TCPInfo{RTT: 3 * time.Millisecond, SegsOut: 12})
	if got := h.Kernel[0]; got.RTT != 3*time.Millisecond || got.Metrics.HZ != 1000 || got.Metrics.Busy != 300 {
		t.Fatalf("merged kernel state = %+v", got)
	}
}

func TestTCPHealthCountsRepeatedInboundSYNWithoutRTT(t *testing.T) {
	local := netip.MustParseAddrPort("192.0.2.10:443")
	remote := netip.MustParseAddrPort("198.51.100.20:40000")
	var health tcpHealth
	for range 2 {
		health.observe(capture.Packet{Protocol: 6, Source: remote, Destination: local, SYN: true, TCPSeq: 99}, false)
	}
	if health.Retransmits != 1 || health.SynRTT != 0 {
		t.Fatalf("inbound SYN health: %+v", health)
	}
}
