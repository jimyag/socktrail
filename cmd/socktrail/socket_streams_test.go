package main

import (
	"bytes"
	"encoding/hex"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/jimyag/socktrail/internal/capture"
	"github.com/jimyag/socktrail/internal/sockstream"
	"github.com/jimyag/socktrail/internal/tlsprobe"
)

// With a transparent proxy the captured interface may carry only the return
// direction; the socket-layer copy of the ClientHello still names it.
func TestSocketStreamNamesFlowSeenInOneDirection(t *testing.T) {
	client, server := netip.MustParseAddrPort("192.0.2.10:50000"), netip.MustParseAddrPort("198.51.100.7:443")
	c := newTestCollector()
	reply := capture.Packet{Source: server, Destination: client, Protocol: 6, ACK: true, TCPSeq: 7000, Payload: append([]byte{23, 3, 3, 0, 32}, make([]byte, 32)...), IPBytes: 89}
	c.packet(reply)
	hello := testClientHello("github.com", false)
	streams := make(socketStreams)
	now := time.Now()
	if got := streams.add(sockstream.Chunk{Cookie: 1, Sent: true, Local: client, Remote: server, Data: hello[:40]}, now); got != nil {
		t.Fatal("a partial ClientHello was attached")
	}
	stream := streams.add(sockstream.Chunk{Cookie: 1, Sent: true, Local: client, Remote: server, Offset: 40, Data: hello[40:]}, now)
	if stream == nil {
		t.Fatal("complete ClientHello was not reported")
	}
	c.socketEvidence(stream)
	f := c.flows[keyFor(client, server, 6)]
	if labels := domainLabels(c); len(labels) != 1 || labels[0] != "TLS github.com" || f.AppSource != "ClientHello (socket)" {
		t.Fatalf("socket evidence did not name the flow: %v app=%s", labels, f.AppSource)
	}
}

func TestSocketStreamIgnoresServerDirection(t *testing.T) {
	serverHello := testClientHello("github.com", false)
	serverHello[5] = 2 // ServerHello, as a client socket receives it.
	streams := make(socketStreams)
	if got := streams.add(sockstream.Chunk{Cookie: 2, Data: serverHello}, time.Now()); got != nil {
		t.Fatalf("server direction named the connection: %+v", got.parser.Evidence())
	}
	if got := streams.add(sockstream.Chunk{Cookie: 3, Data: []byte("HTTP/1.1 200 OK\r\nServer: x\r\n\r\n")}, time.Now()); got != nil {
		t.Fatalf("HTTP response named the connection: %+v", got.parser.Evidence())
	}
}

// A SQL Server pre-login response reads as a SOCKS4 CONNECT request. Once
// the connection's initiator is known, only its bytes can name it: those
// its socket sent, or the server's socket received.
func TestSocketStreamServerReplyLikeARequest(t *testing.T) {
	client, server := netip.MustParseAddrPort("127.0.0.1:57559"), netip.MustParseAddrPort("127.0.0.1:1433")
	c := newTestCollector()
	c.packet(capture.Packet{Source: client, Destination: server, Protocol: 6, HasPorts: true, SYN: true, TCPSeq: 1, IPBytes: 60, Outgoing: true})
	preloginResponse := []byte{4, 1, 0, 48, 0, 0, 1, 0, 0, 0, 36, 0, 6, 1, 0, 42}
	streams := make(socketStreams)
	for i, chunk := range []sockstream.Chunk{
		{Cookie: 6, Sent: true, Local: server, Remote: client, Data: preloginResponse},  // The server socket's reply.
		{Cookie: 7, Sent: false, Local: client, Remote: server, Data: preloginResponse}, // The same reply, as the client receives it.
	} {
		stream := streams.add(chunk, time.Now())
		if stream == nil {
			t.Fatalf("chunk %d did not parse as a request, so the test checks nothing", i)
		}
		c.socketEvidence(stream)
	}
	if f := c.flows[keyFor(client, server, 6)]; f.SocketDomain != nil {
		t.Fatalf("the server's reply named the connection: %+v", f.SocketDomain.Evidence())
	}
}

func TestSocketEvidenceWaitsForFlow(t *testing.T) {
	client, server := netip.MustParseAddrPort("192.0.2.10:50001"), netip.MustParseAddrPort("198.51.100.7:443")
	c := newTestCollector()
	streams := make(socketStreams)
	stream := streams.add(sockstream.Chunk{Cookie: 4, Sent: true, Local: client, Remote: server, Data: testClientHello("early.example.test", false)}, time.Now())
	c.socketEvidence(stream)
	c.packet(capture.Packet{Source: client, Destination: server, Protocol: 6, SYN: true, TCPSeq: 1, IPBytes: 60, Outgoing: true})
	if labels := domainLabels(c); len(labels) != 1 || labels[0] != "TLS early.example.test" {
		t.Fatalf("socket evidence was lost before the flow appeared: %v", labels)
	}
}

// Kernels before 5.12 key socket streams by the socket's address, which a
// new socket can reuse; its first chunk, at offset 0, starts a new stream.
func TestSocketStreamRestartsAtOffsetZero(t *testing.T) {
	client, server := netip.MustParseAddrPort("192.0.2.10:50002"), netip.MustParseAddrPort("198.51.100.7:443")
	streams := make(socketStreams)
	if streams.add(sockstream.Chunk{Cookie: 5, Sent: true, Local: client, Remote: server, Data: testClientHello("old.example.test", false)}, time.Now()) == nil {
		t.Fatal("first ClientHello was not parsed")
	}
	stream := streams.add(sockstream.Chunk{Cookie: 5, Sent: true, Local: client, Remote: server, Data: testClientHello("new.example.test", false)}, time.Now())
	if stream == nil || stream.parser.Evidence().SNI != "new.example.test" {
		t.Fatalf("reused key kept the old stream: %+v", stream)
	}
}

// A QUIC client behind a local transparent proxy: the Initial never crosses
// a captured interface, only the socket sees it. An unconnected socket gives
// no local address, before or after its flow appears.
func TestSocketDatagramNamesQUICFlow(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "internal", "quicinitial", "testdata", "rfc9001-client-initial.hex"))
	if err != nil {
		t.Fatal(err)
	}
	initial, err := hex.DecodeString(string(bytes.Join(bytes.Fields(data), nil)))
	if err != nil {
		t.Fatal(err)
	}
	server := netip.MustParseAddrPort("198.51.100.7:443")
	for i, flowFirst := range []bool{true, false} {
		client := netip.AddrPortFrom(netip.MustParseAddr("192.0.2.10"), uint16(51000+i))
		c := newTestCollector()
		streams := make(socketStreams)
		shortHeader := capture.Packet{Source: client, Destination: server, Protocol: 17, HasPorts: true, Outgoing: true, Payload: []byte{0x40, 1, 2, 3}, IPBytes: 32}
		if flowFirst {
			c.packet(shortHeader)
		}
		chunk := sockstream.Chunk{Cookie: 9, Protocol: 17, Sent: true, Local: netip.AddrPortFrom(netip.IPv6Unspecified(), client.Port()), Remote: server, Data: initial}
		stream := streams.add(chunk, time.Now())
		if stream == nil {
			t.Fatal("QUIC Initial from the socket was not parsed")
		}
		c.socketEvidence(stream)
		if !flowFirst {
			c.packet(shortHeader)
		}
		f := c.flows[keyFor(client, server, 17)]
		if f == nil || f.Domain == nil || f.Domain.Evidence().Label() != "QUIC example.com" || f.AppSource != "QUIC Initial ClientHello (socket)" {
			t.Fatalf("flowFirst=%t: socket Initial did not name the flow: %+v", flowFirst, f)
		}
	}
}

func TestMergedViewPrefersClientHelloOverProcessSNI(t *testing.T) {
	client, server := netip.MustParseAddrPort("192.0.2.10:50002"), netip.MustParseAddrPort("198.51.100.7:443")
	withProbe, withWire := newTestCollector(), newTestCollector()
	withProbe.packet(capture.Packet{Source: server, Destination: client, Protocol: 6, ACK: true, TCPSeq: 7000, Payload: []byte{23, 3, 3, 0, 1, 0}, IPBytes: 900})
	withProbe.tlsEvent(tlsprobe.Event{PID: 9, Local: client, Remote: server, Hostname: "github.com", Source: "openssl_set_sni"})
	withWire.packet(capture.Packet{Source: client, Destination: server, Protocol: 6, SYN: true, TCPSeq: 1, IPBytes: 60, Outgoing: true})
	withWire.packet(tcpPacket(client, server, 2, testClientHello("github.com", false)))
	for _, order := range [][]string{{"br0", "dae0"}, {"dae0", "br0"}} {
		host, _, _ := hostCollector(order, map[string]*collector{"br0": withProbe, "dae0": withWire})
		if flows := host.allFlows(); len(flows) != 1 || flows[0].Domain.Evidence().Label() != "TLS github.com" {
			t.Fatalf("order %v: merged evidence %s", order, flows[0].Domain.Evidence().Label())
		}
	}
}
