package domain

import (
	"encoding/binary"
	"testing"
	"time"
)

func clientHello(host string, ech bool) []byte {
	name := []byte(host)
	sni := make([]byte, 2+1+2+len(name))
	binary.BigEndian.PutUint16(sni[:2], uint16(3+len(name)))
	sni[2] = 0
	binary.BigEndian.PutUint16(sni[3:5], uint16(len(name)))
	copy(sni[5:], name)
	ext := make([]byte, 4+len(sni))
	binary.BigEndian.PutUint16(ext[2:4], uint16(len(sni)))
	copy(ext[4:], sni)
	if ech {
		ext = append(ext, 0xfe, 0x0d, 0, 1, 0)
	}
	body := make([]byte, 34)
	body[0], body[1] = 3, 3            // TLS legacy_version.
	body = append(body, 0)             // Session ID length.
	body = append(body, 0, 2, 0x13, 1) // Cipher suite.
	body = append(body, 1, 0)          // Compression.
	body = append(body, byte(len(ext)>>8), byte(len(ext)))
	body = append(body, ext...)
	handshake := []byte{1, byte(len(body) >> 16), byte(len(body) >> 8), byte(len(body))}
	handshake = append(handshake, body...)
	record := []byte{22, 3, 3, byte(len(handshake) >> 8), byte(len(handshake))}
	return append(record, handshake...)
}

func TestReassemblyGapTimeoutKeepsDomainUnknown(t *testing.T) {
	s := New(1001)
	s.Add(1020, []byte("Host: example.test\r\n\r\n"))
	s.Tick(time.Now().Add(11 * time.Second))
	e := s.Evidence()
	if e.Named() || e.Group() != "parse failed" || e.ParseError != "TCP reassembly gap timeout" {
		t.Fatalf("gap timeout was hidden or assigned a domain: %+v", e)
	}
}

func TestFinishedClientHelloIgnoresLaterCaptureGaps(t *testing.T) {
	hello := clientHello("done.example.test", false)
	next := uint32(1 + len(hello))
	s := New(1)
	s.Add(1, hello)
	for i := range 65 { // One lost application data segment, then more data.
		s.Add(next+1448+uint32(i*1448), make([]byte, 1448))
	}
	s.Tick(time.Now().Add(time.Minute))
	s.AddSegment(next, make([]byte, 16*1024), 64*1024) // TSO segment above the copy limit.
	if e := s.Evidence(); e.Group() != "done.example.test" || e.ParseError != "" || len(s.pending) != 0 {
		t.Fatalf("loss after a complete ClientHello became a parse failure: %+v pending=%d", e, len(s.pending))
	}
}

func TestHTTPSkipsUncapturedBodyBytes(t *testing.T) {
	head := []byte("POST /upload HTTP/1.1\r\nHost: a.example.test\r\nContent-Length: 40000\r\n\r\n")
	next := []byte("GET / HTTP/1.1\r\nHost: b.example.test\r\n\r\n")
	s := New(1)
	s.AddSegment(1, append(head, make([]byte, 100)...), len(head)+40000)
	s.Add(1+uint32(len(head))+40000, next)
	if e := s.Evidence(); e.Hosts["a.example.test"] != 1 || e.Hosts["b.example.test"] != 1 || e.ParseError != "" {
		t.Fatalf("uncaptured body bytes broke request parsing: %+v", e)
	}
	s = New(1)
	s.AddSegment(1, head[:20], len(head)+40000)
	if e := s.Evidence(); e.ParseError != "TCP payload capture truncated" || len(e.Hosts) != 0 {
		t.Fatalf("a header cut by capture truncation was accepted: %+v", e)
	}
}

func TestProxyTunnelsExposeTargetAndInnerClientHello(t *testing.T) {
	connect := "CONNECT api.example.test:443 HTTP/1.1\r\nHost: api.example.test:443\r\n\r\n"
	withAuth := "CONNECT api.example.test:443 HTTP/1.1\r\nHost: api.example.test:443\r\nProxy-Authorization: Basic eDp5\r\n\r\n"
	socksName := []byte("socks.example.test")
	socksRequest := append([]byte{5, 1, 0, 3, byte(len(socksName))}, socksName...)
	socksRequest = append(socksRequest, 1, 187)
	socksAuth := []byte{5, 2, 0, 2, 1, 1, 'u', 1, 'p'} // Greeting, then RFC 1929 user "u", password "p".
	for _, tc := range []struct {
		name       string
		segments   [][]byte
		kind, via  string
		proxy, grp string
	}{
		{name: "CONNECT then TLS", segments: [][]byte{[]byte(connect), clientHello("inner.example.test", false)},
			kind: "tls", via: "CONNECT", proxy: "api.example.test", grp: "inner.example.test"},
		{name: "407 retry on the same connection", segments: [][]byte{[]byte(connect), []byte(withAuth), clientHello("inner.example.test", false)},
			kind: "tls", via: "CONNECT", proxy: "api.example.test", grp: "inner.example.test"},
		{name: "CONNECT carrying SSH", segments: [][]byte{[]byte(connect), []byte("SSH-2.0-OpenSSH_9.6\r\n")},
			kind: "proxy", via: "CONNECT", proxy: "api.example.test", grp: "api.example.test"},
		{name: "SOCKS5 with auth split across segments", segments: [][]byte{socksAuth[:4], socksAuth[4:], socksRequest, clientHello("inner.example.test", false)},
			kind: "tls", via: "SOCKS5", proxy: "socks.example.test", grp: "inner.example.test"},
		{name: "SOCKS5 IPv4 target", segments: [][]byte{{5, 1, 0}, {5, 1, 0, 1, 192, 0, 2, 7, 1, 187}, []byte("GET / HTTP/1.1\r\nHost: plain.example.test\r\n\r\n")},
			kind: "http", via: "SOCKS5", proxy: "192.0.2.7", grp: "plain.example.test"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, seq := New(1), uint32(1)
			for _, segment := range tc.segments {
				s.Add(seq, segment)
				seq += uint32(len(segment))
			}
			e := s.Evidence()
			if e.Kind != tc.kind || e.ProxyVia != tc.via || e.Proxy != tc.proxy || e.Group() != tc.grp || e.ParseError != "" {
				t.Fatalf("unexpected tunnel evidence: %+v group=%q", e, e.Group())
			}
		})
	}
}

func TestSOCKS4AndPROXYProtocolPreambles(t *testing.T) {
	socks4a := append([]byte{4, 1, 1, 187, 0, 0, 0, 1, 'u', 0}, []byte("s4.example.test\x00")...)
	v2 := append([]byte("\r\n\r\n\x00\r\nQUIT\n"), 0x21, 0x11, 0, 12, 203, 0, 113, 9, 192, 0, 2, 10, 0xc8, 0x22, 1, 187)
	for _, tc := range []struct {
		name                     string
		segments                 [][]byte
		kind, via, proxy, client string
		group                    string
	}{
		{name: "SOCKS4a", segments: [][]byte{socks4a[:5], socks4a[5:], clientHello("inner.example.test", false)},
			kind: "tls", via: "SOCKS4", proxy: "s4.example.test", group: "inner.example.test"},
		{name: "PROXY v1 then TLS", segments: [][]byte{[]byte("PROXY TCP4 203.0.113.9 192.0.2.10 51234 443\r"), append([]byte("\n"), clientHello("lb.example.test", false)...)},
			kind: "tls", client: "203.0.113.9:51234", group: "lb.example.test"},
		{name: "PROXY v2 then HTTP", segments: [][]byte{v2[:10], v2[10:], []byte("GET / HTTP/1.1\r\nHost: h.example.test\r\n\r\n")},
			kind: "http", client: "203.0.113.9:51234", group: "h.example.test"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, seq := New(1), uint32(1)
			for _, segment := range tc.segments {
				s.Add(seq, segment)
				seq += uint32(len(segment))
			}
			e := s.Evidence()
			if e.Kind != tc.kind || e.ProxyVia != tc.via || e.Proxy != tc.proxy || e.ProxyClient != tc.client || e.Group() != tc.group || e.ParseError != "" {
				t.Fatalf("unexpected evidence: %+v group=%q", e, e.Group())
			}
		})
	}
}

func TestStartsClientMessage(t *testing.T) {
	for _, tc := range []struct {
		payload []byte
		want    bool
	}{
		{clientHello("a.example.test", false), true},
		{[]byte("GET /x HTTP/1.1\r\nHost: a\r\n\r\n"), true},
		{append([]byte{23, 3, 3, 0, 32}, make([]byte, 32)...), false},
		{[]byte("GET part of a body without a request line"), false},
	} {
		if got := StartsClientMessage(tc.payload); got != tc.want {
			t.Fatalf("StartsClientMessage(%q) = %t", tc.payload[:min(len(tc.payload), 16)], got)
		}
	}
}

func TestHTTPHostRejectsTerminalControlBytes(t *testing.T) {
	s := New(1)
	s.Add(1, []byte("GET / HTTP/1.1\r\nHost: a\x1b]0;x\x07.example.test\r\n\r\n"))
	if e := s.Evidence(); len(e.Hosts) != 0 || e.Named() {
		t.Fatalf("Host with control bytes would reach the terminal: %+v", e)
	}
}

func TestTLSOutOfOrderAndRetransmission(t *testing.T) {
	data := clientHello("API.Example.Test", false)
	s := New(1001)
	s.Add(1031, data[30:])
	s.Add(1001, data[:15])
	s.Add(1001, data[:15])
	s.Add(1016, data[15:30])
	e := s.Evidence()
	if e.Kind != "tls" || e.Group() != "api.example.test" || e.ParseError != "" {
		t.Fatalf("unexpected TLS evidence: %+v", e)
	}
}

func TestTLSClientHelloAcrossRecordsAndLateSNI(t *testing.T) {
	original := clientHello("late.example.test", false)
	body := original[9:]
	extOffset := 34 + 1 + 2 + 2 + 1 + 1
	padding := append([]byte{0, 21, 1, 144}, make([]byte, 400)...)
	extensions := append(padding, body[extOffset+2:]...)
	body = append([]byte(nil), body[:extOffset]...)
	body = append(body, byte(len(extensions)>>8), byte(len(extensions)))
	body = append(body, extensions...)
	hello := append([]byte{1, byte(len(body) >> 16), byte(len(body) >> 8), byte(len(body))}, body...)
	first := append([]byte{22, 3, 3, 0, 10}, hello[:10]...)
	remaining := hello[10:]
	second := append([]byte{22, 3, 3, byte(len(remaining) >> 8), byte(len(remaining))}, remaining...)
	s := New(1)
	s.Add(1, append(first, second...))
	e := s.Evidence()
	if e.Kind != "tls" || e.Group() != "late.example.test" || e.ParseError != "" {
		t.Fatalf("SNI after padding or across records was lost: %+v", e)
	}
}

// Browsers send GREASE ECH on every connection, so the on-wire SNI stays the
// group; the label marks that it may be a provider's public name.
func TestECHOfferKeepsOnWireSNIAndMarksIt(t *testing.T) {
	s := New(1)
	s.Add(1, clientHello("www.example.test", true))
	e := s.Evidence()
	if !e.ECH || !e.Named() || e.Group() != "www.example.test" || e.Label() != "TLS www.example.test [ECH]" {
		t.Fatalf("ECH-offering ClientHello lost its on-wire SNI or marker: %+v", e)
	}
}

func TestQUICClientHelloMarksECH(t *testing.T) {
	for _, ech := range []bool{false, true} {
		stream, err := NewQUICClientHello(clientHello("quic.example.test", ech)[5:])
		if err != nil {
			t.Fatal(err)
		}
		evidence := stream.Evidence()
		want := "QUIC quic.example.test"
		if ech {
			want += " [ECH]"
		}
		if evidence.Kind != "quic" || evidence.ECH != ech || evidence.Group() != "quic.example.test" || evidence.Label() != want {
			t.Fatalf("unexpected QUIC evidence: %+v", evidence)
		}
	}
}

func TestTLS12ClientHelloWithoutExtensionsIsValidButHasUnknownDomain(t *testing.T) {
	body := make([]byte, 34)
	body[0], body[1] = 3, 3            // TLS 1.2 ClientHello version.
	body = append(body, 0)             // Session ID length.
	body = append(body, 0, 2, 0, 0x2f) // TLS 1.2 cipher suite.
	body = append(body, 1, 0)          // Compression; no extensions length follows.
	hello := append([]byte{1, 0, 0, byte(len(body))}, body...)
	record := append([]byte{22, 3, 3, 0, byte(len(hello))}, hello...)
	s := New(1)
	s.Add(1, record)
	e := s.Evidence()
	if e.Kind != "tls" || e.Named() || e.Group() != "no SNI" || e.ParseError != "" {
		t.Fatalf("valid no-extension ClientHello was treated as malformed: %+v", e)
	}
}

func TestTLSDuplicateSNIEvidenceStaysUnknown(t *testing.T) {
	first := clientHello("first.example.test", false)
	second := clientHello("second.example.test", false)
	firstBody := first[9:]
	secondBody := second[9:]
	extOffset := 34 + 1 + 2 + 2 + 1 + 1
	firstExt := firstBody[extOffset+2:]
	secondExt := secondBody[extOffset+2:]
	body := append([]byte(nil), firstBody[:extOffset]...)
	body = append(body, byte((len(firstExt)+len(secondExt))>>8), byte(len(firstExt)+len(secondExt)))
	body = append(body, firstExt...)
	body = append(body, secondExt...)
	hello := append([]byte{1, byte(len(body) >> 16), byte(len(body) >> 8), byte(len(body))}, body...)
	record := append([]byte{22, 3, 3, byte(len(hello) >> 8), byte(len(hello))}, hello...)
	s := New(1)
	s.Add(1, record)
	e := s.Evidence()
	if e.Named() || e.Group() != "parse failed" || e.ParseError != "duplicate SNI extension" {
		t.Fatalf("duplicate SNI extension was attributed to a domain: %+v", e)
	}
	nameA, nameB := []byte("first.example.test"), []byte("second.example.test")
	list := append([]byte{0, 0, byte(len(nameA))}, nameA...)
	list = append(list, 0, 0, byte(len(nameB)))
	list = append(list, nameB...)
	sni := append([]byte{byte(len(list) >> 8), byte(len(list))}, list...)
	if got, err := parseSNI(sni); err == nil || got != "" {
		t.Fatalf("duplicate host_name was accepted: name=%q error=%v", got, err)
	}
}

func TestHTTPMultipleHostsAndBodyFraming(t *testing.T) {
	data := []byte("GET /one HTTP/1.1\r\nHost: A.Example.Test\r\n\r\n" +
		"POST /two HTTP/1.1\r\nHost: b.example.test\r\nContent-Length: 4\r\n\r\nbody" +
		"POST /three HTTP/1.1\r\nHost: a.example.test\r\nTransfer-Encoding: chunked\r\n\r\n4\r\ntest\r\n0\r\n\r\n" +
		"GET /four HTTP/1.1\r\nHost: a.example.test\r\n\r\n")
	s := New(5001)
	s.Add(5001+uint32(len(data)/2), data[len(data)/2:])
	s.Add(5001, data[:len(data)/2])
	s.Add(5001, data[:len(data)/2])
	e := s.Evidence()
	if e.Kind != "http" || e.Hosts["a.example.test"] != 3 || e.Hosts["b.example.test"] != 1 || e.Group() != "multiple Hosts" || e.ParseError != "" {
		t.Fatalf("unexpected HTTP evidence: %+v", e)
	}
}
