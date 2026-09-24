package main

import (
	"net/netip"
	"strings"
	"testing"

	"github.com/jimyag/socktrail/internal/capture"
)

func TestFramesWithoutIPHeaderAreFlows(t *testing.T) {
	host, gateway := netip.MustParseAddrPort("192.0.2.10:0"), netip.MustParseAddrPort("192.0.2.1:0")
	c := newTestCollector()
	c.packet(capture.Packet{EtherType: 0x0806, ARPOp: 1, Source: host, Destination: gateway, HardwareAddr: [6]byte{0x02, 0, 0, 0, 0, 0x10}, IPBytes: 28, Outgoing: true})
	c.packet(capture.Packet{EtherType: 0x0806, ARPOp: 2, Source: gateway, Destination: host, HardwareAddr: [6]byte{0xaa, 0xbb, 0xcc, 0, 0, 1}, IPBytes: 28})
	for range 3 {
		c.packet(capture.Packet{EtherType: 0x88cc, IPBytes: 46})
	}
	if len(c.flows) != 2 {
		t.Fatalf("expected one ARP and one LLDP flow, got %d", len(c.flows))
	}
	arp := c.flows[flowKey{A: gateway, B: host, EtherType: 0x0806}]
	if arp == nil || flowProtocol(arp) != "ARP" {
		t.Fatalf("ARP flow missing: %+v", c.flows)
	}
	name := flowName(arp)
	if !strings.Contains(name, "requests=1 replies=1") || !strings.Contains(name, "192.0.2.10 is-at 02:00:00:00:00:10") || !strings.Contains(name, "192.0.2.1 is-at aa:bb:cc:00:00:01") {
		t.Fatalf("ARP description: %s", name)
	}
	var labels []string
	for _, row := range (&terminalUI{}).rows(c, viewProtocol) {
		labels = append(labels, row.label)
	}
	if got := strings.Join(labels, ","); !strings.Contains(got, "ARP") || !strings.Contains(got, "LLDP") {
		t.Fatalf("protocol view labels: %s", got)
	}
}
