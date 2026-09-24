package appproto

import (
	"encoding/binary"
	"testing"
)

func TestTCPAndUDPProtocolsNeedPayloadEvidence(t *testing.T) {
	dns := make([]byte, 12)
	binary.BigEndian.PutUint16(dns[4:6], 1)
	stun := make([]byte, 20)
	binary.BigEndian.PutUint32(stun[4:8], 0x2112a442)
	quic := []byte{0xc0, 0, 0, 0, 1, 1, 0xaa, 1, 0xbb}
	openVPN := append([]byte{7 << 3}, make([]byte, 8)...)
	for _, tc := range []struct {
		name, want string
		udp        bool
		payload    []byte
		src, dst   uint16
	}{
		{name: "SSH", want: "SSH", payload: []byte("SSH-2.0-OpenSSH_9.0"), dst: 2222},
		{name: "MQTT", want: "MQTT", payload: []byte{0x10, 0x0c, 0, 4, 'M', 'Q', 'T', 'T'}, dst: 1883},
		{name: "BitTorrent", want: "BitTorrent", payload: append([]byte{19}, []byte("BitTorrent protocol")...), dst: 50000},
		{name: "HTTP", want: "HTTP", payload: []byte("GET / HTTP/1.1\r\n"), dst: 8080},
		{name: "TLS", want: "TLS", payload: []byte{22, 3, 3, 0, 8}, dst: 443},
		{name: "TLS application data", want: "TLS", payload: []byte{23, 3, 3, 0x40, 0}, dst: 443},
		{name: "TLS-like prefix with impossible length", payload: []byte{23, 3, 3, 0xff, 0xff}, dst: 443},
		{name: "OpenVPN TCP", want: "OpenVPN", payload: append([]byte{0, 9}, openVPN...), dst: 1194},
		{name: "STUN", want: "STUN", udp: true, payload: stun, dst: 3478},
		{name: "QUIC", want: "QUIC", udp: true, payload: quic, dst: 443},
		{name: "OpenVPN UDP", want: "OpenVPN", udp: true, payload: openVPN, dst: 1194},
		{name: "OpenVPN-shaped packet on unrelated port", udp: true, payload: openVPN, dst: 40000},
		{name: "DNS", want: "DNS", udp: true, payload: dns, dst: 53},
		{name: "mDNS", want: "mDNS", udp: true, payload: dns, dst: 5353},
		{name: "NTP", want: "NTP", udp: true, payload: append([]byte{0x23}, make([]byte, 47)...), dst: 123},
		{name: "no port-only guess", udp: true, payload: []byte{1, 2, 3}, dst: 443},
		{name: "DNS-looking bytes on unrelated port", udp: true, payload: dns, dst: 9000},
		{name: "invalid QUIC fixed bit", udp: true, payload: []byte{0x80, 0, 0, 0, 1, 1, 0xaa, 1, 0xbb}, dst: 443},
		{name: "QUIC v2", want: "QUIC", udp: true, payload: []byte{0xd0, 0x6b, 0x33, 0x43, 0xcf, 1, 0xaa, 0}, dst: 443},
		{name: "SMB2", want: "SMB", payload: append([]byte{0, 0, 0, 64}, []byte("\xfeSMB")...), dst: 445},
		{name: "RDP connection request", want: "RDP", payload: []byte{3, 0, 0, 11, 6, 0xe0, 0, 0, 0, 0, 0}, dst: 3389},
		{name: "MySQL greeting", want: "MySQL", payload: append([]byte{40, 0, 0, 0, 0x0a}, append([]byte("8.0.36\x00"), make([]byte, 37)...)...), src: 3306},
		{name: "VNC", want: "VNC", payload: []byte("RFB 003.008\n"), src: 5900},
		{name: "Telnet negotiation", want: "Telnet", payload: []byte{0xff, 0xfd, 0x18}, src: 23},
		{name: "SIP over TCP", want: "SIP", payload: []byte("INVITE sip:bob@example.test SIP/2.0\r\nVia: x\r\n\r\n"), dst: 5060},
		{name: "RTSP", want: "RTSP", payload: []byte("DESCRIBE rtsp://192.0.2.1/stream RTSP/1.0\r\nCSeq: 1\r\n\r\n"), dst: 554},
		{name: "VXLAN", want: "VXLAN", udp: true, payload: append([]byte{0x08, 0, 0, 0, 0, 0, 1, 0}, make([]byte, 14)...), dst: 4789},
		{name: "IKEv2", want: "IKE", udp: true, payload: append(append(make([]byte, 17), 0x20, 34, 8, 0, 0, 0, 0), 0, 0, 0, 28), dst: 500},
		{name: "IPsec NAT-T ESP", want: "IPsec ESP", udp: true, payload: append([]byte{0x12, 0x34, 0x56, 0x78}, make([]byte, 40)...), dst: 4500},
		{name: "Syslog", want: "Syslog", udp: true, payload: []byte("<34>Oct 11 22:14:15 host su: fail"), dst: 514},
		{name: "SIP over UDP", want: "SIP", udp: true, payload: []byte("SIP/2.0 200 OK\r\nVia: x\r\n\r\n"), src: 5060},
		{name: "DNS query with a long-header-like ID", want: "DNS", udp: true, payload: append([]byte{0xc3, 0x21, 1, 0, 0, 1}, make([]byte, 6)...), dst: 53},
		{name: "ZeroTier-like packet with unknown version", udp: true, payload: []byte{0xd7, 0x3e, 0x91, 0x02, 0x55, 4, 1, 2, 3, 4, 0}, src: 9993, dst: 9993},
		{name: "WireGuard transport data", want: "WireGuard", udp: true, payload: append([]byte{4, 0, 0, 0}, make([]byte, 60)...), src: 41641, dst: 41641},
		{name: "WireGuard-like data with unpadded length", udp: true, payload: append([]byte{4, 0, 0, 0}, make([]byte, 61)...), dst: 41641},
		{name: "AMQP 0-9-1", want: "AMQP", payload: []byte("AMQP\x00\x00\x09\x01"), dst: 5672},
		{name: "Kafka ApiVersions request", want: "Kafka", payload: []byte{0, 0, 0, 10, 0, 18, 0, 3, 0, 0, 0, 1, 0, 0}, dst: 9092},
		{name: "Kafka-sized bytes elsewhere", payload: []byte{0, 0, 0, 10, 0, 18, 0, 3, 0, 0, 0, 1, 0, 0}, dst: 9000},
		{name: "NATS", want: "NATS", payload: []byte(`INFO {"server_id":"x"}`), src: 4222},
		{name: "NATS client first", want: "NATS", payload: []byte("CONNECT {\"verbose\":false}\r\nPING\r\n"), dst: 4222},
		{name: "ZooKeeper four-letter word", want: "ZooKeeper", payload: []byte("ruok"), dst: 2181},
		{name: "not a ZooKeeper word", payload: []byte("at s"), dst: 2181},
		{name: "Memcached text", want: "Memcached", payload: []byte("get session:42\r\n"), dst: 11211},
		{name: "Memcached command without arguments", want: "Memcached", payload: []byte("stats\r\nquit\r\n"), dst: 11211},
		{name: "SQL Server pre-login", want: "SQL Server", payload: []byte{0x12, 0x01, 0, 10, 0, 0, 0, 0, 0, 0}, dst: 1433},
		{name: "Oracle TNS connect", want: "Oracle TNS", payload: []byte{0, 10, 0, 0, 1, 0, 0, 0, 1, 2}, dst: 1521},
		{name: "LDAP bind request", want: "LDAP", payload: []byte{0x30, 0x0c, 0x02, 0x01, 0x01, 0x60, 0x07, 0x02, 0x01, 0x03, 0x04, 0, 0x80, 0}, dst: 389},
		{name: "Kerberos over TCP", want: "Kerberos", payload: []byte{0, 0, 0, 2, 0x6a, 0x00}, dst: 88},
		{name: "Kerberos over UDP", want: "Kerberos", udp: true, payload: []byte{0x6c, 0x81, 0x00}, dst: 88},
		{name: "Cassandra options", want: "Cassandra", payload: []byte{4, 0, 0, 1, 5, 0, 0, 0, 0}, dst: 9042},
		{name: "NFS call over TCP", want: "NFS", payload: append([]byte{0x80, 0, 0, 40, 0, 0, 0, 7, 0, 0, 0, 0, 0, 0, 0, 2, 0, 1, 0x86, 0xa3}, make([]byte, 24)...), dst: 2049},
		{name: "portmapper call over UDP", want: "RPC portmapper", udp: true, payload: append([]byte{0, 0, 0, 7, 0, 0, 0, 0, 0, 0, 0, 2, 0, 1, 0x86, 0xa0}, make([]byte, 24)...), dst: 111},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var got Detection
			if tc.udp {
				got = UDP(tc.payload, tc.src, tc.dst)
			} else {
				got = TCP(tc.payload, tc.src, tc.dst)
			}
			if got.Name != tc.want {
				t.Fatalf("detected %q (%s), want %q", got.Name, got.Source, tc.want)
			}
		})
	}
}
