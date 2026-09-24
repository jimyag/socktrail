package main

import (
	"net/netip"
	"testing"
	"time"

	"github.com/jimyag/socktrail/internal/capture"
	"github.com/jimyag/socktrail/internal/conntrack"
	"github.com/jimyag/socktrail/internal/probe"
)

func natCollector(nat *natTable) *collector {
	return &collector{flows: make(map[flowKey]*flow), nat: nat, roles: make(map[flowKey]roles), roleSeen: make(map[flowKey]time.Time), maxFlows: 10}
}

// A gateway sees one connection on its LAN side before SNAT and on its WAN
// side after. The overview counts it once.
func TestNATLinksGatewaySides(t *testing.T) {
	client, server := netip.MustParseAddrPort("192.168.1.10:50000"), netip.MustParseAddrPort("198.51.100.7:443")
	masquerade := netip.MustParseAddrPort("203.0.113.5:61000")
	nat := &natTable{entries: make(map[flowKey]*natEntry)}
	lan, wan := natCollector(nat), natCollector(nat)
	lan.packet(capture.Packet{Source: client, Destination: server, Protocol: 6, SYN: true, TCPSeq: 100, IPBytes: 60})
	wan.packet(capture.Packet{Source: masquerade, Destination: server, Protocol: 6, SYN: true, TCPSeq: 100, IPBytes: 60, Outgoing: true})
	if nat.skipped.Load() != 2 {
		t.Fatalf("lookups asked: %d", nat.skipped.Load()) // No resolver runs, so both were skipped.
	}
	entry := nat.add(conntrack.Entry{Protocol: 6, Orig: [2]netip.AddrPort{client, server}, Reply: [2]netip.AddrPort{server, masquerade}}, time.Now())
	lan.linkNAT(entry)
	wan.linkNAT(entry)
	if lan.flows[keyFor(client, server, 6)].NAT != entry || wan.flows[keyFor(masquerade, server, 6)].NAT != entry {
		t.Fatal("flows not linked to their NAT entry")
	}
	host, _, _ := hostCollector([]string{"lan", "wan"}, map[string]*collector{"lan": lan, "wan": wan})
	if flows := host.allFlows(); len(flows) != 1 || host.bytes != 60 || flows[0].Direction != "forwarded" || evidenceLine(flows[0], host) != "EVIDENCE SNAT 192.168.1.10:50000 as 203.0.113.5:61000" {
		t.Fatalf("overview: %d flows, %d bytes", len(flows), host.bytes)
	}
}

// A local process connects to a service address that DNAT sends to a
// backend. Its socket keeps the service tuple; the wire carries the backend's.
func TestNATGivesCapturedFlowTheSocketProcess(t *testing.T) {
	local, service := netip.MustParseAddrPort("10.0.0.5:40000"), netip.MustParseAddrPort("10.96.0.10:443")
	backend := netip.MustParseAddrPort("10.0.0.20:6443")
	nat := &natTable{entries: make(map[flowKey]*natEntry)}
	c := natCollector(nat)
	c.event(probe.Event{Protocol: 6, Operation: "connect", Role: "out", PID: 101, StartNS: 1000, Process: "client", Local: local, Remote: service})
	c.packet(capture.Packet{Source: local, Destination: backend, Protocol: 6, SYN: true, TCPSeq: 100, IPBytes: 60, Outgoing: true})
	c.linkNAT(nat.add(conntrack.Entry{Protocol: 6, Orig: [2]netip.AddrPort{local, service}, Reply: [2]netip.AddrPort{backend, local}}, time.Now()))
	f := c.flows[keyFor(local, backend, 6)]
	if f.Client.PID != 101 {
		t.Fatalf("client %+v", f.Client)
	}
	c.event(probe.Event{Protocol: 6, Operation: "send", Role: "out", AppBytes: 100, PID: 101, StartNS: 1000, Process: "client", Local: local, Remote: service})
	if f.IO[processID{PID: 101, StartNS: 1000}].TX != 100 {
		t.Fatalf("socket I/O not on the captured flow: %+v", f.IO)
	}
}
