package main

import (
	"net/netip"
	"testing"

	"github.com/jimyag/socktrail/internal/capture"
	"github.com/jimyag/socktrail/internal/tlsprobe"
)

func TestOpenSSLProcessSNIForMissedWireHandshake(t *testing.T) {
	client := netip.MustParseAddrPort("192.0.2.10:50000")
	server := netip.MustParseAddrPort("192.0.2.20:443")
	c := &collector{flows: make(map[flowKey]*flow), maxFlows: 10}
	event := tlsprobe.Event{PID: 123, StartNS: 456, Process: "client", Local: client, Remote: server, Hostname: "process.example.test", Source: "openssl_set_sni"}
	if c.tlsEvent(event) {
		t.Fatal("event without a captured flow was prematurely matched")
	}
	c.packet(capture.Packet{Source: client, Destination: server, Protocol: 6, TCPSeq: 9000, Payload: []byte("encrypted application data"), IPBytes: 72, Outgoing: true})
	f := c.flows[keyFor(client, server, 6)]
	if f == nil || f.Domain == nil || f.Domain.Evidence().Kind != "openssl" || f.Domain.Evidence().Group() != event.Hostname {
		t.Fatalf("OpenSSL evidence missing after midstream packet: %+v", f)
	}
	rows := (&terminalUI{}).rows(c, viewDomain)
	if len(rows) != 1 || rows[0].label != "OPENSSL process.example.test" || rows[0].reqs != 0 || rows[0].rx+rows[0].tx != 72 {
		t.Fatalf("process domain bytes/count wrong: %+v", rows)
	}
	pidRows := (&terminalUI{}).rows(c, viewPID)
	if len(pidRows) != 1 || pidRows[0].label != "123 client" {
		t.Fatalf("OpenSSL observer PID missing: %+v", pidRows)
	}
}

func TestWireHostnameWinsOnProcessConflict(t *testing.T) {
	client := netip.MustParseAddrPort("192.0.2.10:50000")
	server := netip.MustParseAddrPort("192.0.2.20:80")
	c := &collector{flows: make(map[flowKey]*flow), maxFlows: 10}
	c.packet(capture.Packet{Source: client, Destination: server, Protocol: 6, SYN: true, TCPSeq: 1, IPBytes: 40, Outgoing: true})
	c.packet(capture.Packet{Source: client, Destination: server, Protocol: 6, TCPSeq: 2, Payload: []byte("GET / HTTP/1.1\r\nHost: wire.example.test\r\n\r\n"), IPBytes: 89, Outgoing: true})
	if !c.tlsEvent(tlsprobe.Event{Local: client, Remote: server, Hostname: "different.example.test", Source: "openssl_set_sni"}) {
		t.Fatal("process event did not match the socket tuple")
	}
	f := c.flows[keyFor(client, server, 6)]
	if f.Domain.Evidence().Group() != "wire.example.test" || !f.DomainConflict {
		t.Fatalf("conflicting hostname incorrectly replaced wire Host: %+v", f)
	}
}
