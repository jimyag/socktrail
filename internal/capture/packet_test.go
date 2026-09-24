package capture

import (
	"encoding/binary"
	"net/netip"
	"testing"
)

func TestDecodeIPv4UDPAndFragment(t *testing.T) {
	frame := make([]byte, 14+20+8+3)
	binary.BigEndian.PutUint16(frame[12:14], etherTypeIPv4)
	ip := frame[14:]
	ip[0] = 0x45
	binary.BigEndian.PutUint16(ip[2:4], 31)
	ip[9] = 17
	copy(ip[12:16], []byte{127, 0, 0, 1})
	copy(ip[16:20], []byte{127, 0, 0, 2})
	binary.BigEndian.PutUint16(ip[20:22], 40000)
	binary.BigEndian.PutUint16(ip[22:24], 443)
	binary.BigEndian.PutUint16(ip[24:26], 11)
	p, ok := Decode(frame, true)
	if !ok || p.IPBytes != 31 || !p.HasPorts || p.Source.String() != "127.0.0.1:40000" || p.Destination.String() != "127.0.0.2:443" || !p.Outgoing {
		t.Fatalf("unexpected UDP packet: %+v, ok=%t", p, ok)
	}
	// A tun interface delivers the same packet without the Ethernet header.
	if tun, ok := DecodeNetwork(ip, etherTypeIPv4, true); !ok || tun.Source != p.Source || tun.Destination != p.Destination || tun.IPBytes != 31 {
		t.Fatalf("tun packet decoded differently: %+v", tun)
	}
	binary.BigEndian.PutUint16(ip[6:8], 1)
	p, ok = Decode(frame, false)
	if !ok || p.HasPorts || p.IPBytes != 31 {
		t.Fatalf("later fragment should retain IP bytes without ports: %+v, ok=%t", p, ok)
	}
}

func TestDecodeUDPPayloadIgnoresEthernetPadding(t *testing.T) {
	frame := make([]byte, 14+20+8+3+20)
	binary.BigEndian.PutUint16(frame[12:14], etherTypeIPv4)
	ip := frame[14:]
	ip[0], ip[9] = 0x45, 17
	binary.BigEndian.PutUint16(ip[2:4], 31)
	binary.BigEndian.PutUint16(ip[24:26], 11)
	copy(ip[28:31], []byte("abc"))
	copy(ip[31:], []byte("padding looks like payload"))
	p, ok := Decode(frame, false)
	if !ok || string(p.Payload) != "abc" {
		t.Fatalf("UDP payload included Ethernet padding: %+v", p)
	}
}

func TestDecodeKeepsFullQUICInitialPayload(t *testing.T) {
	const payloadLength = 1200
	frame := make([]byte, 14+20+8+payloadLength)
	binary.BigEndian.PutUint16(frame[12:14], etherTypeIPv4)
	ip := frame[14:]
	ip[0], ip[9] = 0x45, 17
	binary.BigEndian.PutUint16(ip[2:4], uint16(20+8+payloadLength))
	binary.BigEndian.PutUint16(ip[24:26], uint16(8+payloadLength))
	for i := range ip[28:] {
		ip[28+i] = byte(i)
	}
	ip[28] = 0xc0
	binary.BigEndian.PutUint32(ip[29:33], 1)
	p, ok := Decode(frame, false)
	if !ok || p.PayloadTruncated || len(p.Payload) != payloadLength || p.Payload[1199] != byte(1199%256) {
		t.Fatalf("QUIC Initial capture incomplete: len=%d truncated=%t ok=%t", len(p.Payload), p.PayloadTruncated, ok)
	}
}

func TestDecodeTCPReportsWirePayloadLength(t *testing.T) {
	const payloadLength = 30000 // A TSO/GRO segment above the 16 KiB copy limit.
	frame := make([]byte, 14+20+20+payloadLength)
	binary.BigEndian.PutUint16(frame[12:14], etherTypeIPv4)
	ip := frame[14:]
	ip[0], ip[9] = 0x45, 6
	binary.BigEndian.PutUint16(ip[2:4], uint16(20+20+payloadLength))
	ip[32] = 5 << 4
	p, ok := Decode(frame, true)
	if !ok || p.PayloadLen != payloadLength || len(p.Payload) != 16*1024 || !p.PayloadTruncated {
		t.Fatalf("oversized segment: len=%d wire=%d truncated=%t ok=%t", len(p.Payload), p.PayloadLen, p.PayloadTruncated, ok)
	}
	p, ok = Decode(frame[:14+20+20+100], true) // Frame cut short of the IP length.
	if !ok || p.PayloadLen != payloadLength || len(p.Payload) != 100 || !p.PayloadTruncated {
		t.Fatalf("short frame: len=%d wire=%d truncated=%t ok=%t", len(p.Payload), p.PayloadLen, p.PayloadTruncated, ok)
	}
}

func TestDecodeIPv6ExtensionAndTruncation(t *testing.T) {
	frame := make([]byte, 14+40+8+20)
	binary.BigEndian.PutUint16(frame[12:14], etherTypeIPv6)
	ip := frame[14:]
	ip[0] = 0x60
	binary.BigEndian.PutUint16(ip[4:6], 28)
	ip[6] = 0 // Hop-by-Hop extension.
	ip[8+15] = 1
	ip[24+15] = 2
	ip[40] = 6 // TCP follows.
	ip[41] = 0 // Extension length: 8 bytes.
	tcp := ip[48:]
	binary.BigEndian.PutUint16(tcp[0:2], 50000)
	binary.BigEndian.PutUint16(tcp[2:4], 8443)
	tcp[13] = 0x02
	p, ok := Decode(frame, false)
	if !ok || p.IPBytes != 68 || p.Truncated || !p.HasPorts || !p.SYN || p.ACK || p.Source.String() != "[::1]:50000" || p.Destination.String() != "[::2]:8443" {
		t.Fatalf("unexpected IPv6 packet: %+v, ok=%t", p, ok)
	}
	p, ok = Decode(frame[:len(frame)-3], false)
	if !ok || p.IPBytes != 68 || !p.Truncated || p.SYN {
		t.Fatalf("truncated IPv6 packet should retain length but not incomplete TCP flags: %+v, ok=%t", p, ok)
	}
}

func TestDecodeIPv6LaterFragmentNamesUpperProtocol(t *testing.T) {
	ip := make([]byte, 40+8+16)
	ip[0], ip[6] = 0x60, 44 // Fragment header.
	binary.BigEndian.PutUint16(ip[4:6], 24)
	ip[40] = 58 // ICMPv6 follows.
	binary.BigEndian.PutUint16(ip[42:44], 185<<3)
	binary.BigEndian.PutUint32(ip[44:48], 9)
	p, ok := DecodeNetwork(ip, etherTypeIPv6, false)
	if !ok || p.Protocol != 58 || !p.Fragmented || p.FragmentOffset != 185 || p.FragmentID != 9 {
		t.Fatalf("later IPv6 fragment: %+v, ok=%t", p, ok)
	}
}

func TestDecodeICMPErrorQuotesOriginalPacket(t *testing.T) {
	// Host 192.0.2.1 answers a UDP datagram from 192.0.2.9:40000 to port 9999.
	frame := make([]byte, 14+20+8+20+8)
	binary.BigEndian.PutUint16(frame[12:14], etherTypeIPv4)
	ip := frame[14:]
	ip[0], ip[9] = 0x45, 1
	binary.BigEndian.PutUint16(ip[2:4], uint16(len(ip)))
	copy(ip[12:16], []byte{192, 0, 2, 1})
	copy(ip[16:20], []byte{192, 0, 2, 9})
	icmp := ip[20:]
	icmp[0], icmp[1] = 3, 3 // Destination unreachable, port unreachable.
	quoted := icmp[8:]
	quoted[0], quoted[9] = 0x45, 17
	copy(quoted[12:16], []byte{192, 0, 2, 9})
	copy(quoted[16:20], []byte{192, 0, 2, 1})
	binary.BigEndian.PutUint16(quoted[20:22], 40000)
	binary.BigEndian.PutUint16(quoted[22:24], 9999)
	p, ok := Decode(frame, false)
	if !ok || p.ICMPType != 3 || p.ICMPCode != 3 || p.QuotedProtocol != 17 || p.QuotedSource.String() != "192.0.2.9:40000" || p.QuotedDestination.String() != "192.0.2.1:9999" {
		t.Fatalf("quoted packet not decoded: %+v", p)
	}

	// ICMPv6 packet too big for a TCP segment, and a neighbor solicitation.
	frame6 := make([]byte, 14+40+8+40+20)
	binary.BigEndian.PutUint16(frame6[12:14], etherTypeIPv6)
	ip6 := frame6[14:]
	ip6[0], ip6[6] = 0x60, 58
	binary.BigEndian.PutUint16(ip6[4:6], uint16(8+40+20))
	icmp6 := ip6[40:]
	icmp6[0] = 2
	binary.BigEndian.PutUint32(icmp6[4:8], 1280)
	inner := icmp6[8:]
	inner[0], inner[6] = 0x60, 6
	inner[23], inner[39] = 1, 2
	binary.BigEndian.PutUint16(inner[40:42], 51000)
	binary.BigEndian.PutUint16(inner[42:44], 443)
	p, ok = Decode(frame6, true)
	if !ok || p.ICMPValue != 1280 || p.QuotedProtocol != 6 || p.QuotedSource.String() != "[::1]:51000" || p.QuotedDestination.String() != "[::2]:443" {
		t.Fatalf("packet-too-big not decoded: %+v", p)
	}
	icmp6[0] = 135 // The target address field overlays the former quoted header.
	p, _ = Decode(frame6, true)
	if p.ICMPTarget != netip.AddrFrom16([16]byte(inner[:16])) {
		t.Fatalf("neighbor solicitation target: %s", p.ICMPTarget)
	}
}

func TestDecodeFramesWithoutIPHeader(t *testing.T) {
	arp := make([]byte, 14+28+18) // Padded to the 60-byte Ethernet minimum.
	binary.BigEndian.PutUint16(arp[12:14], etherTypeARP)
	body := arp[14:]
	binary.BigEndian.PutUint16(body[0:2], 1)
	binary.BigEndian.PutUint16(body[2:4], etherTypeIPv4)
	body[4], body[5] = 6, 4
	binary.BigEndian.PutUint16(body[6:8], 1) // Request.
	copy(body[8:14], []byte{0x02, 0, 0, 0, 0, 0x10})
	copy(body[14:18], []byte{192, 0, 2, 10})
	copy(body[24:28], []byte{192, 0, 2, 1})
	p, ok := Decode(arp, false)
	if !ok || p.EtherType != etherTypeARP || p.ARPOp != 1 || p.Source.Addr().String() != "192.0.2.10" || p.Destination.Addr().String() != "192.0.2.1" || p.HardwareAddr[5] != 0x10 || p.IPBytes != 28 {
		t.Fatalf("ARP request: %+v ok=%t", p, ok)
	}

	lldp := make([]byte, 14+46)
	binary.BigEndian.PutUint16(lldp[12:14], 0x88cc)
	if p, ok := Decode(lldp, false); !ok || p.EtherType != 0x88cc || p.IPBytes != 46 {
		t.Fatalf("LLDP frame was not counted: %+v ok=%t", p, ok)
	}
	stp := make([]byte, 14+38)
	binary.BigEndian.PutUint16(stp[12:14], 38) // 802.3 length field.
	if p, ok := Decode(stp, false); !ok || p.EtherType != EtherTypeLLC {
		t.Fatalf("802.3 frame was not counted: %+v ok=%t", p, ok)
	}

	pppoe := make([]byte, 14+8+20+8)
	binary.BigEndian.PutUint16(pppoe[12:14], etherTypePPPoE)
	binary.BigEndian.PutUint16(pppoe[20:22], 0x0021) // PPP protocol: IPv4.
	ip := pppoe[22:]
	ip[0], ip[9] = 0x45, 132 // SCTP.
	binary.BigEndian.PutUint16(ip[2:4], 28)
	binary.BigEndian.PutUint16(ip[20:22], 2905)
	binary.BigEndian.PutUint16(ip[22:24], 36412)
	if p, ok := Decode(pppoe, false); !ok || p.EtherType != 0 || p.Protocol != 132 || !p.HasPorts || p.Destination.Port() != 36412 {
		t.Fatalf("IPv4 inside PPPoE or SCTP ports not decoded: %+v ok=%t", p, ok)
	}
}

func TestDecodeICMPEchoMetadata(t *testing.T) {
	frame := make([]byte, 14+20+8)
	binary.BigEndian.PutUint16(frame[12:14], etherTypeIPv4)
	ip := frame[14:]
	ip[0] = 0x45
	binary.BigEndian.PutUint16(ip[2:4], 28)
	ip[9] = 1
	ip[20] = 8 // Echo request.
	binary.BigEndian.PutUint16(ip[24:26], 321)
	binary.BigEndian.PutUint16(ip[26:28], 7)
	p, ok := Decode(frame, true)
	if !ok || !p.ICMPHasEcho || p.ICMPType != 8 || p.ICMPCode != 0 || p.ICMPID != 321 || p.ICMPSeq != 7 || p.HasPorts {
		t.Fatalf("ICMP Echo metadata: %+v, ok=%t", p, ok)
	}
}
