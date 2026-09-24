package main

import (
	"net/netip"
	"runtime"
	"testing"

	"github.com/jimyag/socktrail/internal/capture"
)

// BenchmarkFlowMemory reports the live heap a flow keeps: a TLS connection
// with its handshake, as most flows on a busy host are.
func BenchmarkFlowMemory(b *testing.B) {
	const flows = 10000
	hello := testClientHello("api.example.test", false)
	server := netip.MustParseAddrPort("192.0.2.1:443")
	serverHello := []byte{22, 3, 3, 0, 4, 2, 0, 0, 0}
	for b.Loop() {
		c := newTestCollector()
		c.maxFlows = flows
		var before, after runtime.MemStats
		runtime.GC()
		runtime.ReadMemStats(&before)
		for i := range flows {
			client := netip.AddrPortFrom(netip.AddrFrom4([4]byte{10, 0, byte(i >> 8), byte(i)}), 40000)
			c.packet(capture.Packet{Source: client, Destination: server, Protocol: 6, HasPorts: true, SYN: true, TCPSeq: 1, IPBytes: 60, Outgoing: true})
			c.packet(capture.Packet{Source: server, Destination: client, Protocol: 6, HasPorts: true, SYN: true, ACK: true, TCPSeq: 1000, IPBytes: 60})
			c.packet(tcpPacket(client, server, 2, hello))
			c.packet(capture.Packet{Source: server, Destination: client, Protocol: 6, HasPorts: true, ACK: true, TCPSeq: 1001, Payload: serverHello, PayloadLen: len(serverHello), IPBytes: 61})
		}
		runtime.GC()
		runtime.ReadMemStats(&after)
		b.ReportMetric(float64(after.HeapAlloc-before.HeapAlloc)/flows, "B/flow")
		runtime.KeepAlive(c)
	}
}
