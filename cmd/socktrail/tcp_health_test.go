package main

import (
	"net/netip"
	"testing"
	"time"

	"github.com/jimyag/socktrail/internal/capture"
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
