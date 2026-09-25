package app

import (
	"fmt"
	"net"
	"net/netip"
	"strings"

	"github.com/jimyag/socktrail/internal/capture"
)

// arpState summarizes the ARP exchange between two IPv4 addresses and the
// hardware address each one announced.
type arpState struct {
	Requests, Replies uint64
	MACs              map[netip.Addr][6]byte
}

func (s *arpState) observe(p capture.Packet) {
	if p.ARPOp == 2 {
		s.Replies++
	} else {
		s.Requests++
	}
	if s.MACs == nil {
		s.MACs = make(map[netip.Addr][6]byte, 2) // An ARP flow holds its two addresses.
	}
	s.MACs[p.Source.Addr()] = p.HardwareAddr
}

var etherTypeNames = map[uint16]string{
	0x0806: "ARP", 0x8035: "RARP", 0x88cc: "LLDP", 0x888e: "802.1X", 0x8809: "LACP", 0x8847: "MPLS",
	0x8848: "MPLS", 0x8863: "PPPoE discovery", 0x8864: "PPPoE", 0x88f7: "PTP", 0x0842: "Wake-on-LAN",
	0x8137: "IPX", 0x88a2: "AoE", 0x8906: "FCoE", 0x88e5: "MACsec", 0x9000: "loopback test",
	capture.EtherTypeLLC: "802.3 LLC",
}

var ipProtocolNames = map[uint8]string{
	6: "TCP", 17: "UDP", 1: "ICMPv4", 58: "ICMPv6", 2: "IGMP", 4: "IPIP", 41: "IPv6-in-IPv4", 47: "GRE",
	50: "ESP", 51: "AH", 89: "OSPF", 103: "PIM", 112: "VRRP", 115: "L2TP", 132: "SCTP", 136: "UDP-Lite",
}

func protocolName(protocol uint8) string {
	if name, ok := ipProtocolNames[protocol]; ok {
		return name
	}
	return fmt.Sprintf("IP protocol %d", protocol)
}

// flowProtocol names a flow's network protocol: the IP protocol, or the
// EtherType of a frame without an IP header.
func flowProtocol(f *flow) string {
	if f.Key.EtherType == 0 {
		return protocolName(f.Key.Protocol)
	}
	if name, ok := etherTypeNames[f.Key.EtherType]; ok {
		return name
	}
	return fmt.Sprintf("EtherType 0x%04x", f.Key.EtherType)
}

// l2Description names a flow of frames without an IP header.
func l2Description(f *flow) string {
	if f.Key.EtherType != 0x0806 || f.ARP == nil {
		return fmt.Sprintf("%d frames", f.Packets)
	}
	var text strings.Builder
	fmt.Fprintf(&text, "requests=%d replies=%d", f.ARP.Requests, f.ARP.Replies)
	for _, addr := range []netip.Addr{f.Key.A.Addr(), f.Key.B.Addr()} {
		if mac, ok := f.ARP.MACs[addr]; ok {
			fmt.Fprintf(&text, " %s is-at %s", addr, net.HardwareAddr(mac[:]))
		}
	}
	return text.String()
}
