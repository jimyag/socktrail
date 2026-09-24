package appproto

import (
	"bytes"
	"encoding/binary"
)

// Detection identifies an application protocol from observed bytes. Source
// records whether the signature also needed a well-known port to be credible.
type Detection struct {
	Name   string
	Source string
}

func detected(name, source string) Detection { return Detection{Name: name, Source: source} }

func eitherPort(source, destination, port uint16) bool {
	return source == port || destination == port
}

func TCP(payload []byte, source, destination uint16) Detection {
	if len(payload) == 0 {
		return Detection{}
	}
	if bytes.HasPrefix(payload, []byte("SSH-2.0-")) || bytes.HasPrefix(payload, []byte("SSH-1.99-")) {
		return detected("SSH", "payload")
	}
	if len(payload) >= 20 && payload[0] == 19 && bytes.Equal(payload[1:20], []byte("BitTorrent protocol")) {
		return detected("BitTorrent", "payload")
	}
	if len(payload) >= 8 && payload[0] == 0x10 && payload[1] < 0x80 && bytes.Equal(payload[2:8], []byte{0, 4, 'M', 'Q', 'T', 'T'}) {
		return detected("MQTT", "payload")
	}
	// Any record type counts, so a connection that predates capture and only
	// shows application data is still recognized as TLS.
	if len(payload) >= 5 && payload[0] >= 20 && payload[0] <= 23 && payload[1] == 3 && payload[2] <= 4 {
		if length := binary.BigEndian.Uint16(payload[3:5]); length > 0 && length <= 18432 {
			return detected("TLS", "record-prefix")
		}
	}
	if bytes.HasPrefix(payload, []byte("HTTP/1.")) || httpRequest(payload) {
		return detected("HTTP", "payload")
	}
	if len(payload) >= 14 && eitherPort(source, destination, 53) {
		length := int(binary.BigEndian.Uint16(payload[:2]))
		if length >= 12 && length <= len(payload)-2 && dnsMessage(payload[2:2+length]) {
			return detected("DNS", "payload+port")
		}
	}
	if eitherPort(source, destination, 1194) && len(payload) >= 11 {
		packetLength := int(binary.BigEndian.Uint16(payload[:2]))
		if packetLength >= 9 && packetLength <= len(payload)-2 && openVPNReset(payload[2]) {
			return detected("OpenVPN", "reset+port")
		}
	}
	if eitherPort(source, destination, 21) && (bytes.HasPrefix(payload, []byte("220 ")) || bytes.HasPrefix(payload, []byte("USER ")) || bytes.HasPrefix(payload, []byte("PASS "))) {
		return detected("FTP", "payload+port")
	}
	if (eitherPort(source, destination, 25) || eitherPort(source, destination, 587)) && (bytes.HasPrefix(payload, []byte("220 ")) || bytes.HasPrefix(payload, []byte("EHLO ")) || bytes.HasPrefix(payload, []byte("HELO "))) {
		return detected("SMTP", "payload+port")
	}
	if eitherPort(source, destination, 6379) && len(payload) >= 4 && bytes.Contains(payload[:min(len(payload), 64)], []byte("\r\n")) && bytes.IndexByte([]byte("+-:$*"), payload[0]) >= 0 {
		return detected("Redis", "payload+port")
	}
	if eitherPort(source, destination, 5432) && len(payload) >= 8 && binary.BigEndian.Uint32(payload[:4]) == uint32(len(payload)) && binary.BigEndian.Uint32(payload[4:8]) == 196608 {
		return detected("PostgreSQL", "payload+port")
	}
	if len(payload) >= 8 && payload[0] == 0 && (bytes.Equal(payload[4:8], []byte("\xffSMB")) || bytes.Equal(payload[4:8], []byte("\xfeSMB"))) {
		return detected("SMB", "payload")
	}
	if eitherPort(source, destination, 3389) && len(payload) >= 11 && payload[0] == 3 && payload[1] == 0 && payload[5]&0xf0 == 0xe0 {
		return detected("RDP", "payload+port") // TPKT and an X.224 connection request or confirm.
	}
	if mysqlGreeting(payload) {
		return detected("MySQL", "payload")
	}
	if bytes.HasPrefix(payload, []byte("RFB 00")) {
		return detected("VNC", "payload")
	}
	if eitherPort(source, destination, 23) && len(payload) >= 3 && payload[0] == 0xff && payload[1] >= 0xfb {
		return detected("Telnet", "payload+port") // IAC WILL/WONT/DO/DONT negotiation.
	}
	if eitherPort(source, destination, 27017) && len(payload) >= 16 && binary.LittleEndian.Uint32(payload[:4]) == uint32(len(payload)) && mongoOpCode(binary.LittleEndian.Uint32(payload[12:16])) {
		return detected("MongoDB", "payload+port")
	}
	if name := textProtocol(payload); name != "" {
		return detected(name, "payload")
	}
	return Detection{}
}

// textProtocol recognizes SIP and RTSP, whose requests look like HTTP but
// name their own scheme and version.
func textProtocol(payload []byte) string {
	line, _, _ := bytes.Cut(payload[:min(len(payload), 256)], []byte("\r\n"))
	switch {
	case bytes.HasPrefix(line, []byte("SIP/2.0 ")) || bytes.HasSuffix(line, []byte(" SIP/2.0")) && bytes.Contains(line, []byte(" sip:")):
		return "SIP"
	case bytes.HasPrefix(line, []byte("RTSP/1.")) || bytes.Contains(line, []byte(" rtsp://")) && bytes.Contains(line, []byte(" RTSP/1.")):
		return "RTSP"
	}
	return ""
}

// mysqlGreeting matches the handshake a MySQL server sends first: packet
// sequence 0, protocol version 10, then a NUL-terminated version string.
func mysqlGreeting(payload []byte) bool {
	if len(payload) < 16 || payload[3] != 0 || payload[4] != 0x0a {
		return false
	}
	if length := int(payload[0]) | int(payload[1])<<8 | int(payload[2])<<16; length+4 > len(payload) || length < 20 {
		return false
	}
	end := bytes.IndexByte(payload[5:min(len(payload), 64)], 0)
	if end < 1 {
		return false
	}
	for _, b := range payload[5 : 5+end] {
		if b < 32 || b > 126 {
			return false
		}
	}
	return payload[5] >= '0' && payload[5] <= '9'
}

func mongoOpCode(op uint32) bool {
	switch op {
	case 1, 2001, 2002, 2004, 2005, 2006, 2007, 2010, 2011, 2012, 2013:
		return true
	}
	return false
}

func UDP(payload []byte, source, destination uint16) Detection {
	if len(payload) == 0 {
		return Detection{}
	}
	if len(payload) >= 20 && payload[0]&0xc0 == 0 && binary.BigEndian.Uint32(payload[4:8]) == 0x2112a442 && int(binary.BigEndian.Uint16(payload[2:4]))%4 == 0 {
		return detected("STUN", "payload")
	}
	if len(payload) >= 4 && bytes.Equal(payload[1:4], []byte{0, 0, 0}) {
		size := map[byte]int{1: 148, 2: 92, 3: 64, 4: 32}[payload[0]]
		if size == len(payload) {
			return detected("WireGuard", "payload")
		}
	}
	if eitherPort(source, destination, 1194) && len(payload) >= 9 && openVPNReset(payload[0]) {
		return detected("OpenVPN", "reset+port")
	}
	if len(payload) >= 240 && (eitherPort(source, destination, 67) || eitherPort(source, destination, 68)) && bytes.Equal(payload[236:240], []byte{99, 130, 83, 99}) {
		return detected("DHCP", "payload+port")
	}
	if len(payload) >= 4 && (eitherPort(source, destination, 546) || eitherPort(source, destination, 547)) && payload[0] >= 1 && payload[0] <= 13 {
		return detected("DHCPv6", "payload+port")
	}
	if (eitherPort(source, destination, 53) || eitherPort(source, destination, 5353) || eitherPort(source, destination, 5355) || eitherPort(source, destination, 137)) && dnsMessage(payload) {
		switch {
		case eitherPort(source, destination, 5353):
			return detected("mDNS", "payload+port")
		case eitherPort(source, destination, 5355):
			return detected("LLMNR", "payload+port")
		case eitherPort(source, destination, 137):
			return detected("NetBIOS NS", "payload+port")
		default:
			return detected("DNS", "payload+port")
		}
	}
	// After DNS: a query whose ID has both top bits set also looks like a
	// long header, and only a real QUIC version tells them apart.
	if quicLongHeader(payload) {
		return detected("QUIC", "long-header")
	}
	// WireGuard transport data, the bulk of a tunnel after its handshake: a
	// 16-byte header, plaintext padded to 16 bytes, and a 16-byte tag.
	if len(payload) > 32 && len(payload)%16 == 0 && bytes.Equal(payload[:4], []byte{4, 0, 0, 0}) {
		return detected("WireGuard", "payload")
	}
	if eitherPort(source, destination, 123) && len(payload) >= 48 && payload[0]>>3&7 >= 3 && payload[0]>>3&7 <= 4 && payload[0]&7 >= 1 && payload[0]&7 <= 5 {
		return detected("NTP", "payload+port")
	}
	if eitherPort(source, destination, 1900) && (bytes.HasPrefix(payload, []byte("M-SEARCH * HTTP/1.1")) || bytes.HasPrefix(payload, []byte("NOTIFY * HTTP/1.1")) || bytes.HasPrefix(payload, []byte("HTTP/1.1 200"))) {
		return detected("SSDP", "payload+port")
	}
	if eitherPort(source, destination, 4789) && len(payload) >= 16 && payload[0]&0x08 != 0 && bytes.Equal(payload[1:4], []byte{0, 0, 0}) {
		return detected("VXLAN", "payload+port")
	}
	if eitherPort(source, destination, 6081) && len(payload) >= 8 && payload[0]>>6 == 0 && binary.BigEndian.Uint16(payload[2:4]) == 0x6558 {
		return detected("GENEVE", "payload+port")
	}
	if (eitherPort(source, destination, 500) || eitherPort(source, destination, 4500)) && len(payload) >= 28 {
		ike := payload
		if eitherPort(source, destination, 4500) {
			if !bytes.Equal(payload[:4], []byte{0, 0, 0, 0}) {
				return detected("IPsec ESP", "payload+port") // NAT traversal: ESP without the zero marker.
			}
			ike = payload[4:]
		}
		if len(ike) >= 28 && (ike[17] == 0x20 || ike[17] == 0x10) && binary.BigEndian.Uint32(ike[24:28]) == uint32(len(ike)) {
			return detected("IKE", "payload+port")
		}
	}
	if eitherPort(source, destination, 514) && len(payload) >= 4 && payload[0] == '<' {
		if end := bytes.IndexByte(payload[:min(len(payload), 5)], '>'); end > 1 {
			return detected("Syslog", "payload+port")
		}
	}
	if eitherPort(source, destination, 69) && len(payload) >= 4 && payload[0] == 0 && payload[1] >= 1 && payload[1] <= 6 {
		return detected("TFTP", "payload+port")
	}
	if (eitherPort(source, destination, 1812) || eitherPort(source, destination, 1813)) && len(payload) >= 20 && binary.BigEndian.Uint16(payload[2:4]) == uint16(len(payload)) {
		return detected("RADIUS", "payload+port")
	}
	if name := textProtocol(payload); name == "SIP" {
		return detected(name, "payload")
	}
	if (eitherPort(source, destination, 161) || eitherPort(source, destination, 162)) && len(payload) >= 6 && payload[0] == 0x30 && payload[2] == 0x02 && payload[3] == 1 && payload[4] <= 3 {
		return detected("SNMP", "payload+port")
	}
	return Detection{}
}

func httpRequest(payload []byte) bool {
	for _, method := range [][]byte{[]byte("GET "), []byte("POST "), []byte("PUT "), []byte("HEAD "), []byte("DELETE "), []byte("PATCH "), []byte("OPTIONS "), []byte("CONNECT ")} {
		if bytes.HasPrefix(payload, method) && bytes.Contains(payload[:min(len(payload), 256)], []byte(" HTTP/1.")) {
			return true
		}
	}
	return false
}

func dnsMessage(payload []byte) bool {
	if len(payload) < 12 || payload[2]&0x78 != 0 || payload[3]&0x40 != 0 {
		return false // Unsupported opcode or reserved Z bit.
	}
	questions := binary.BigEndian.Uint16(payload[4:6])
	answers := binary.BigEndian.Uint16(payload[6:8])
	return questions <= 10 && (questions > 0 || answers > 0)
}

// quicVersion accepts published QUIC versions: v1, v2, IETF drafts, the
// reserved GREASE pattern, Google QUIC and mvfst. Other UDP protocols with a
// matching first byte, such as ZeroTier, carry arbitrary bytes here.
func quicVersion(v uint32) bool {
	digit := func(b uint32) bool { return b >= '0' && b <= '9' }
	switch {
	case v == 1, v == 0x6b3343cf, v>>8 == 0xff0000, v>>8 == 0xfaceb0:
		return true
	case v&0x0f0f0f0f == 0x0a0a0a0a:
		return true
	case v>>24 == 'Q' || v>>24 == 'T':
		return v>>16&0xff == '0' && digit(v>>8&0xff) && digit(v&0xff)
	}
	return false
}

func openVPNReset(first byte) bool {
	opcode := first >> 3
	return opcode == 7 || opcode == 8 || opcode == 10
}

func quicLongHeader(payload []byte) bool {
	if len(payload) < 7 || payload[0]&0xc0 != 0xc0 || !quicVersion(binary.BigEndian.Uint32(payload[1:5])) {
		return false
	}
	dcidLength := int(payload[5])
	if dcidLength > 20 || len(payload) < 7+dcidLength {
		return false
	}
	scidLength := int(payload[6+dcidLength])
	return scidLength <= 20 && len(payload) >= 7+dcidLength+scidLength
}
