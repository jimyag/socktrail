package app

import (
	"net/netip"
	"testing"
	"time"

	"github.com/jimyag/socktrail/internal/capture"
)

// BenchmarkSteadyPacket measures one data packet of an established flow, the
// bulk of a busy host's traffic, across 1000 flows: an identified TLS
// connection and TCP and UDP flows whose protocol stays unknown.
func BenchmarkSteadyPacket(b *testing.B) {
	hello := testClientHello("api.example.test", false)
	serverHello := []byte{22, 3, 3, 0, 4, 2, 0, 0, 0}
	cases := []struct {
		name     string
		port     uint16
		protocol uint8
		open     func(c *collector, client, server netip.AddrPort) uint32 // Returns the server's next sequence number.
	}{
		{"TLS", 443, 6, func(c *collector, client, server netip.AddrPort) uint32 {
			c.packet(capture.Packet{Source: client, Destination: server, Protocol: 6, HasPorts: true, SYN: true, TCPSeq: 1, IPBytes: 60, Outgoing: true})
			c.packet(capture.Packet{Source: server, Destination: client, Protocol: 6, HasPorts: true, SYN: true, ACK: true, TCPSeq: 1000, IPBytes: 60})
			c.packet(tcpPacket(client, server, 2, hello))
			c.packet(capture.Packet{Source: server, Destination: client, Protocol: 6, HasPorts: true, ACK: true, TCPSeq: 1001, Payload: serverHello, PayloadLen: len(serverHello), IPBytes: 61})
			return 1001 + uint32(len(serverHello))
		}},
		{"UnknownTCP", 9000, 6, func(c *collector, client, server netip.AddrPort) uint32 {
			c.packet(capture.Packet{Source: client, Destination: server, Protocol: 6, HasPorts: true, SYN: true, TCPSeq: 1, IPBytes: 60, Outgoing: true})
			c.packet(capture.Packet{Source: server, Destination: client, Protocol: 6, HasPorts: true, SYN: true, ACK: true, TCPSeq: 1000, IPBytes: 60})
			return 1001
		}},
		{"UnknownUDP", 9000, 17, func(*collector, netip.AddrPort, netip.AddrPort) uint32 { return 0 }},
	}
	payload := make([]byte, 1400)
	for i := range payload {
		payload[i] = byte(i*131 + 7)
	}
	payload[0], payload[1], payload[2] = 23, 3, 3 // A TLS application data record.
	for _, tc := range cases {
		b.Run(tc.name, func(b *testing.B) {
			const flows = 1000
			c := newTestCollector()
			c.maxFlows = 2 * flows
			server := netip.AddrPortFrom(netip.MustParseAddr("192.0.2.1"), tc.port)
			clients := make([]netip.AddrPort, flows)
			seqs := make([]uint32, flows)
			for i := range flows {
				clients[i] = netip.AddrPortFrom(netip.AddrFrom4([4]byte{10, 0, byte(i >> 8), byte(i)}), 40000)
				seqs[i] = tc.open(c, clients[i], server)
			}
			now := time.Now()
			b.ReportAllocs()
			i := 0
			for b.Loop() {
				n := i % flows
				c.packetAt(capture.Packet{Source: server, Destination: clients[n], Protocol: tc.protocol, HasPorts: true, ACK: tc.protocol == 6, TCPSeq: seqs[n], Payload: payload, PayloadLen: len(payload), IPBytes: 1452, CapturedAt: now}, now)
				seqs[n] += uint32(len(payload))
				i++
			}
		})
	}
}

// A flow none of whose first packets named a protocol is retried only on
// every appRetryPackets-th packet.
func TestUnknownFlowRetriesDetectionPeriodically(t *testing.T) {
	c := newTestCollector()
	client := netip.MustParseAddrPort("10.0.0.1:40000")
	server := netip.MustParseAddrPort("192.0.2.1:9000")
	binary, sip := make([]byte, 64), []byte("SIP/2.0 200 OK\r\nVia: x\r\n\r\n")
	send := func(payload []byte) string {
		c.packet(capture.Packet{Source: client, Destination: server, Protocol: 17, HasPorts: true, Payload: payload, PayloadLen: len(payload), IPBytes: uint32(28 + len(payload))})
		return c.flows[keyFor(client, server, 17)].AppProtocol
	}
	for n := 1; n < 50; n++ {
		if got := send(binary); got != "" {
			t.Fatalf("packet %d: protocol %q from zero bytes", n, got)
		}
	}
	if got := send(sip); got != "" { // Packet 50: between retries.
		t.Fatalf("packet 50 was detected as %q; want a retry only every %d packets", got, appRetryPackets)
	}
	for n := 51; n < 2*appRetryPackets; n++ {
		send(binary)
	}
	if got := send(sip); got != "SIP" { // Packet 64: a retry.
		t.Fatalf("packet %d = %q, want SIP", 2*appRetryPackets, got)
	}
}
