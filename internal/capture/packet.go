package capture

import (
	"encoding/binary"
	"net/netip"
	"time"
)

const (
	ethernetHeader = 14
	etherTypeIPv4  = 0x0800
	etherTypeARP   = 0x0806
	etherTypeIPv6  = 0x86dd
	etherTypeVLAN  = 0x8100
	etherTypeQinQ  = 0x88a8
	etherTypePPPoE = 0x8864
	// EtherTypeLLC groups 802.3 frames, whose type field is a length and whose
	// payload starts with an LLC header, such as spanning tree BPDUs.
	EtherTypeLLC = 1

	// maxTCPPayload is the most of a TCP segment the decoder reads; a
	// ClientHello or an HTTP header block fits within it.
	maxTCPPayload = 16 * 1024
	// SnapLength is the most of each frame the capture keeps while nothing is
	// recorded: the headers and maxTCPPayload bytes of payload.
	SnapLength = maxTCPPayload + 256
	// ipSnapLength is the part of SnapLength left for the IP packet after an
	// Ethernet header with two VLAN tags. A packet cut beyond it lost nothing
	// the decoder reads, so it does not count as truncated.
	ipSnapLength = SnapLength - 22
)

type Packet struct {
	Interface           string
	Source, Destination netip.AddrPort // ARP: sender and target protocol addresses.
	Protocol            uint8
	IPBytes             uint32 // Frames without an IP header: their Ethernet payload length.
	EtherType           uint16 // Set only for frames without an IP header, such as ARP or LLDP.
	ARPOp               uint16
	HardwareAddr        [6]byte // ARP sender hardware address.
	TCPSeq              uint32
	TCPAck              uint32
	Payload             []byte // Points into the capture ring until its Batch is released: copy what you keep.
	PayloadLen          int    // TCP payload length on the wire; Payload may hold only a prefix.
	Frame               []byte // Populated only while an explicit packet recording is active.
	FrameLen            int    // The frame's length on the wire; Frame may hold only a prefix.
	CapturedAt          time.Time
	PayloadTruncated    bool
	Outgoing            bool
	Truncated           bool
	HasPorts            bool
	SYN, ACK, FIN, RST  bool
	// Fragments of one IP datagram: only the first carries transport ports.
	Fragmented         bool
	FragmentID         uint32
	FragmentOffset     uint16 // In 8-byte units; 0 is the first fragment.
	ICMPType, ICMPCode uint8
	ICMPID, ICMPSeq    uint16
	ICMPHasEcho        bool
	ICMPValue          uint32     // MTU a frag-needed or packet-too-big message reports.
	ICMPTarget         netip.Addr // Neighbor discovery target, or the gateway a redirect names.
	// The original packet an ICMP error quotes: the traffic it refers to.
	QuotedProtocol                  uint8
	QuotedSource, QuotedDestination netip.AddrPort
}

// Decode returns one packet from an Ethernet frame. IPBytes uses the IP
// header length even when the capture buffer contains only part of the packet.
func Decode(frame []byte, outgoing bool) (Packet, bool) {
	if len(frame) < ethernetHeader {
		return Packet{}, false
	}
	etherType := binary.BigEndian.Uint16(frame[12:14])
	offset := ethernetHeader
	for range 2 {
		if etherType != etherTypeVLAN && etherType != etherTypeQinQ {
			break
		}
		if len(frame) < offset+4 {
			return Packet{}, false
		}
		etherType = binary.BigEndian.Uint16(frame[offset+2 : offset+4])
		offset += 4
	}
	if etherType == etherTypePPPoE && len(frame) >= offset+8 {
		// A PPPoE session carries PPP; the IPv4 or IPv6 packet inside is decoded.
		switch binary.BigEndian.Uint16(frame[offset+6 : offset+8]) {
		case 0x0021:
			etherType, offset = etherTypeIPv4, offset+8
		case 0x0057:
			etherType, offset = etherTypeIPv6, offset+8
		}
	}
	return DecodeNetwork(frame[offset:], etherType, outgoing)
}

// EthernetFrame wraps a packet from a device without a link-layer header in a
// blank Ethernet header, so one PCAPNG link type fits every interface.
func EthernetFrame(etherType uint16, packet []byte) []byte {
	return append(binary.BigEndian.AppendUint16(make([]byte, 12, 14+len(packet)), etherType), packet...)
}

// DecodeNetwork decodes a packet that starts at its network header, as the
// Ethernet payload does and as frames from a tun device such as a WireGuard
// or Tailscale interface do.
func DecodeNetwork(data []byte, etherType uint16, outgoing bool) (Packet, bool) {
	switch etherType {
	case etherTypeIPv4:
		return decodeIPv4(data, outgoing)
	case etherTypeIPv6:
		return decodeIPv6(data, outgoing)
	case etherTypeARP:
		if p, ok := decodeARP(data, outgoing); ok {
			return p, true
		}
	}
	// Every other frame is still counted, by EtherType, so traffic arriving
	// from the network is never silently ignored.
	if etherType < 0x0600 {
		etherType = EtherTypeLLC
	}
	return Packet{EtherType: etherType, IPBytes: uint32(len(data)), Outgoing: outgoing}, true
}

// decodeARP reads an Ethernet/IPv4 ARP message.
func decodeARP(arp []byte, outgoing bool) (Packet, bool) {
	if len(arp) < 28 || binary.BigEndian.Uint16(arp[0:2]) != 1 || binary.BigEndian.Uint16(arp[2:4]) != etherTypeIPv4 || arp[4] != 6 || arp[5] != 4 {
		return Packet{}, false
	}
	p := Packet{
		EtherType: etherTypeARP, IPBytes: 28, Outgoing: outgoing,
		ARPOp:       binary.BigEndian.Uint16(arp[6:8]),
		Source:      netip.AddrPortFrom(netip.AddrFrom4([4]byte(arp[14:18])), 0),
		Destination: netip.AddrPortFrom(netip.AddrFrom4([4]byte(arp[24:28])), 0),
	}
	copy(p.HardwareAddr[:], arp[8:14])
	return p, true
}

func decodeIPv4(ip []byte, outgoing bool) (Packet, bool) {
	if len(ip) < 20 || ip[0]>>4 != 4 {
		return Packet{}, false
	}
	headerLen := int(ip[0]&0x0f) * 4
	totalLen := int(binary.BigEndian.Uint16(ip[2:4]))
	if headerLen < 20 || totalLen < headerLen || len(ip) < headerLen {
		return Packet{}, false
	}
	src := netip.AddrFrom4([4]byte(ip[12:16]))
	dst := netip.AddrFrom4([4]byte(ip[16:20]))
	p := Packet{
		Source:      netip.AddrPortFrom(src, 0),
		Destination: netip.AddrPortFrom(dst, 0),
		Protocol:    ip[9],
		IPBytes:     uint32(totalLen),
		Outgoing:    outgoing,
		Truncated:   len(ip) < min(totalLen, ipSnapLength),
	}
	if flags := binary.BigEndian.Uint16(ip[6:8]); flags&0x3fff != 0 {
		p.Fragmented, p.FragmentID, p.FragmentOffset = true, uint32(binary.BigEndian.Uint16(ip[4:6])), flags&0x1fff
		if p.FragmentOffset != 0 {
			return p, true // Later fragment: the transport header is in the first one.
		}
	}
	decodeTransport(&p, ip[headerLen:min(len(ip), totalLen)], totalLen-headerLen)
	return p, true
}

func decodeIPv6(ip []byte, outgoing bool) (Packet, bool) {
	if len(ip) < 40 || ip[0]>>4 != 6 {
		return Packet{}, false
	}
	length := 40 + int(binary.BigEndian.Uint16(ip[4:6]))
	src := netip.AddrFrom16([16]byte(ip[8:24]))
	dst := netip.AddrFrom16([16]byte(ip[24:40]))
	p := Packet{
		Source:      netip.AddrPortFrom(src, 0),
		Destination: netip.AddrPortFrom(dst, 0),
		Protocol:    ip[6],
		IPBytes:     uint32(length),
		Outgoing:    outgoing,
		Truncated:   len(ip) < min(length, ipSnapLength),
	}
	next, offset := ip[6], 40
	for range 8 {
		if next != 0 && next != 43 && next != 44 && next != 60 && next != 51 {
			break
		}
		if len(ip) < offset+2 {
			return p, true
		}
		step := (int(ip[offset+1]) + 1) * 8
		if next == 44 {
			step = 8
			if len(ip) < offset+step {
				return p, true
			}
			p.Fragmented, p.FragmentID = true, binary.BigEndian.Uint32(ip[offset+4:offset+8])
			if p.FragmentOffset = binary.BigEndian.Uint16(ip[offset+2:offset+4]) >> 3; p.FragmentOffset != 0 {
				p.Protocol = ip[offset] // Later fragment: no transport header, but its protocol is named here.
				return p, true
			}
		} else if next == 51 {
			step = (int(ip[offset+1]) + 2) * 4
		}
		if len(ip) < offset+step || offset+step > length {
			return p, true
		}
		next = ip[offset]
		offset += step
	}
	p.Protocol = next
	if offset <= len(ip) {
		decodeTransport(&p, ip[offset:min(len(ip), length)], length-offset)
	}
	return p, true
}

// decodeTransport reads the captured transport bytes in data; wireLength is
// the transport length the IP header declares, which TSO/GRO can make larger
// than what is copied.
func decodeTransport(p *Packet, data []byte, wireLength int) {
	switch p.Protocol {
	case 6, 17, 132, 136: // TCP, UDP, SCTP and UDP-Lite all start with the two ports.
		if len(data) < 4 {
			return
		}
		p.Source = netip.AddrPortFrom(p.Source.Addr(), binary.BigEndian.Uint16(data[:2]))
		p.Destination = netip.AddrPortFrom(p.Destination.Addr(), binary.BigEndian.Uint16(data[2:4]))
		p.HasPorts = true
		if p.Protocol == 6 && len(data) >= 20 {
			p.TCPSeq = binary.BigEndian.Uint32(data[4:8])
			p.TCPAck = binary.BigEndian.Uint32(data[8:12])
			p.SYN = data[13]&0x02 != 0
			p.ACK = data[13]&0x10 != 0
			p.FIN = data[13]&0x01 != 0
			p.RST = data[13]&0x04 != 0
			headerLen := int(data[12]>>4) * 4
			if headerLen >= 20 {
				p.PayloadLen = max(0, wireLength-headerLen)
			}
			if headerLen >= 20 && headerLen <= len(data) {
				end := min(len(data), headerLen+maxTCPPayload)
				p.Payload = data[headerLen:end:end]
			}
			p.PayloadTruncated = len(p.Payload) < p.PayloadLen
		} else if p.Protocol == 17 && len(data) >= 8 {
			udpLength := int(binary.BigEndian.Uint16(data[4:6]))
			if udpLength >= 8 {
				limit := 1024
				switch {
				case len(data) >= 8+7 && data[8]&0xc0 == 0xc0 && binary.BigEndian.Uint32(data[9:13]) != 0:
					limit = 16 * 1024 // QUIC Initial needs at least 1200 bytes.
				case p.Source.Port() == 53 || p.Destination.Port() == 53:
					limit = 4096 // EDNS answers exceed 1 KiB; they feed DNS name hints.
				}
				p.PayloadTruncated = udpLength-8 > limit || len(data) < udpLength
				end := min(len(data), udpLength, 8+limit)
				p.Payload = data[8:end:end]
			}
		}
	case 1, 58:
		if len(data) >= 2 {
			p.ICMPType, p.ICMPCode = data[0], data[1]
			if len(data) >= 8 && ((p.Protocol == 1 && (p.ICMPType == 0 || p.ICMPType == 8)) || (p.Protocol == 58 && (p.ICMPType == 128 || p.ICMPType == 129))) {
				p.ICMPID = binary.BigEndian.Uint16(data[4:6])
				p.ICMPSeq = binary.BigEndian.Uint16(data[6:8])
				p.ICMPHasEcho = true
			}
			decodeICMPDetail(p, data)
		}
	}
}

// decodeICMPDetail reads what an ICMP message says about other traffic:
// the packet an error quotes, the MTU a path reports, or the neighbor or
// redirect target.
func decodeICMPDetail(p *Packet, data []byte) {
	if len(data) < 8 {
		return
	}
	v6 := p.Protocol == 58
	switch {
	case !v6 && (p.ICMPType == 3 || p.ICMPType == 4 || p.ICMPType == 11 || p.ICMPType == 12):
		if p.ICMPType == 3 && p.ICMPCode == 4 {
			p.ICMPValue = uint32(binary.BigEndian.Uint16(data[6:8]))
		}
		decodeQuoted(p, data[8:], false)
	case !v6 && p.ICMPType == 5:
		p.ICMPTarget = netip.AddrFrom4([4]byte(data[4:8]))
		decodeQuoted(p, data[8:], false)
	case v6 && p.ICMPType >= 1 && p.ICMPType <= 4:
		if p.ICMPType == 2 {
			p.ICMPValue = binary.BigEndian.Uint32(data[4:8])
		}
		decodeQuoted(p, data[8:], true)
	case v6 && (p.ICMPType == 135 || p.ICMPType == 136 || p.ICMPType == 137) && len(data) >= 24:
		p.ICMPTarget = netip.AddrFrom16([16]byte(data[8:24]))
	}
}

// decodeQuoted reads the IP header and first transport bytes an ICMP error
// carries from the packet that triggered it.
func decodeQuoted(p *Packet, inner []byte, v6 bool) {
	var transport []byte
	switch {
	case !v6 && len(inner) >= 20 && inner[0]>>4 == 4:
		headerLen := int(inner[0]&0x0f) * 4
		if headerLen < 20 || len(inner) < headerLen {
			return
		}
		p.QuotedProtocol = inner[9]
		p.QuotedSource = netip.AddrPortFrom(netip.AddrFrom4([4]byte(inner[12:16])), 0)
		p.QuotedDestination = netip.AddrPortFrom(netip.AddrFrom4([4]byte(inner[16:20])), 0)
		transport = inner[headerLen:]
	case v6 && len(inner) >= 40 && inner[0]>>4 == 6:
		p.QuotedProtocol = inner[6]
		p.QuotedSource = netip.AddrPortFrom(netip.AddrFrom16([16]byte(inner[8:24])), 0)
		p.QuotedDestination = netip.AddrPortFrom(netip.AddrFrom16([16]byte(inner[24:40])), 0)
		transport = inner[40:]
	default:
		return
	}
	if (p.QuotedProtocol == 6 || p.QuotedProtocol == 17) && len(transport) >= 4 {
		p.QuotedSource = netip.AddrPortFrom(p.QuotedSource.Addr(), binary.BigEndian.Uint16(transport[0:2]))
		p.QuotedDestination = netip.AddrPortFrom(p.QuotedDestination.Addr(), binary.BigEndian.Uint16(transport[2:4]))
	}
}
