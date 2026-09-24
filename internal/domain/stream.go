package domain

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"time"
)

const (
	maxPendingBytes = 64 * 1024
	maxPendingParts = 64
	// maxSniffBytes covers the longest SOCKS5 greeting, RFC 1929 exchange and
	// CONNECT request that can precede a tunnel's own protocol.
	maxSniffBytes = 1100
)

// Groups for evidence without a destination name. They keep the reason on
// the domain page instead of folding every gap into "unknown".
const (
	groupUnknown     = "unknown"
	groupNoSNI       = "no SNI"
	groupNoHandshake = "handshake not captured"
	groupParseFailed = "parse failed"
)

type Evidence struct {
	Kind        string            // http, tls, quic, openssl, proxy, dns or other; empty until known.
	Hosts       map[string]uint64 // HTTP/1.x request count per Host.
	SNI         string            // ClientHello server_name as sent, or the OpenSSL process value.
	NoSNI       bool              // A complete ClientHello carried no server_name.
	ECH         bool              // The ClientHello carried an encrypted_client_hello extension.
	ALPN        []string          // Protocols the client offered, not the negotiated one.
	Proxy       string            // Destination requested through an HTTP CONNECT or SOCKS tunnel.
	ProxyVia    string            // CONNECT, SOCKS4 or SOCKS5.
	ProxyClient string            // Original client address from a PROXY protocol header.
	DNS         string            // Name whose DNS answer pointed at the peer address.
	NoHandshake bool              // TLS records arrived, but their ClientHello was not captured.
	ParseError  string
}

// Group names the destination for the domain page. A ClientHello with an ECH
// extension still groups by its on-wire SNI: Chrome and Firefox send GREASE
// ECH on every connection, and then that SNI is the real name. With real ECH
// it is the provider's public name instead; Label marks both cases.
func (e Evidence) Group() string {
	switch e.Kind {
	case "tls", "quic", "openssl":
		if e.SNI != "" {
			return e.SNI
		}
	case "http":
		if len(e.Hosts) == 1 {
			for host := range e.Hosts {
				return host
			}
		}
		if len(e.Hosts) > 1 {
			return "multiple Hosts"
		}
	case "dns":
		return e.DNS
	}
	switch {
	case e.Proxy != "":
		return e.Proxy
	case e.NoHandshake:
		return groupNoHandshake
	case e.ParseError != "":
		return groupParseFailed
	case e.NoSNI:
		return groupNoSNI
	}
	return groupUnknown
}

// Named reports whether the evidence identifies a destination name.
func (e Evidence) Named() bool {
	switch e.Group() {
	case groupUnknown, groupNoSNI, groupNoHandshake, groupParseFailed:
		return false
	}
	return true
}

// Listed reports whether the evidence belongs on the domain page.
func (e Evidence) Listed() bool { return e.Kind != "" && e.Kind != "other" }

// Label is the domain page row: evidence source, group and an ECH marker.
func (e Evidence) Label() string {
	label := strings.ToUpper(e.Kind) + " " + e.Group()
	if e.ECH {
		label += " [ECH]"
	}
	return label
}

// Detail explains the evidence behind a connection's name.
func (e Evidence) Detail() string {
	var parts []string
	if e.ProxyVia != "" {
		parts = append(parts, strings.TrimSpace(e.ProxyVia+" "+e.Proxy))
	}
	if e.ProxyClient != "" {
		parts = append(parts, "PROXY protocol client "+e.ProxyClient)
	}
	if e.ECH {
		parts = append(parts, "ECH offered: on-wire SNI may be a provider's public name")
	}
	if len(e.ALPN) > 0 {
		parts = append(parts, "ALPN offered "+strings.Join(e.ALPN, ","))
	}
	if e.Kind == "dns" {
		parts = append(parts, "name from a DNS answer for the peer, not Host/SNI")
	}
	if e.ParseError != "" {
		parts = append(parts, "parse error: "+e.ParseError)
	}
	return strings.Join(parts, "; ")
}

type Stream struct {
	expected     uint32
	pending      map[uint32][]byte
	pendingBytes int
	parser       parser
	failed       bool
	lastProgress time.Time
	gapSince     time.Time
}

func New(initialSeq uint32) *Stream {
	return &Stream{expected: initialSeq, pending: make(map[uint32][]byte), parser: parser{evidence: Evidence{Hosts: make(map[string]uint64)}}, lastProgress: time.Now()}
}

func (s *Stream) Evidence() Evidence { return s.parser.evidence }

// Fail records why parsing stopped. A finished parser keeps its evidence:
// losing bytes after a complete ClientHello is not a parse failure.
func (s *Stream) Fail(reason string) {
	if s.failed || s.parser.finished() {
		return
	}
	s.failed = true
	s.parser.evidence.ParseError = reason
	clear(s.pending)
	s.pendingBytes = 0
	s.parser.sniff = nil
	s.parser.tls.record, s.parser.tls.handshake = nil, nil
	s.parser.http.buffer = nil
}

func (s *Stream) Tick(now time.Time) {
	if s.failed || s.parser.finished() {
		return
	}
	if s.pendingBytes > 0 && !s.gapSince.IsZero() && now.Sub(s.gapSince) > 10*time.Second {
		s.Fail("TCP reassembly gap timeout")
		return
	}
	if s.parser.incomplete() && now.Sub(s.lastProgress) > 30*time.Second {
		s.Fail("protocol parse timeout")
	}
}

// Add accepts TCP payload using sequence numbers. A retransmission can add
// wire bytes upstream while contributing no second application observation.
func (s *Stream) Add(seq uint32, payload []byte) {
	if s.failed || s.parser.finished() || len(payload) == 0 {
		return
	}
	diff := int32(seq - s.expected)
	if diff > 0 {
		if s.gapSince.IsZero() {
			s.gapSince = time.Now()
		}
		if len(s.pending) >= maxPendingParts || s.pendingBytes+len(payload) > maxPendingBytes {
			s.Fail("TCP reassembly limit")
			return
		}
		if old := s.pending[seq]; len(old) >= len(payload) {
			return
		} else {
			s.pendingBytes -= len(old)
		}
		s.pending[seq] = bytes.Clone(payload)
		s.pendingBytes += len(payload)
		return
	}
	if diff < 0 {
		overlap := int(-diff)
		if overlap >= len(payload) {
			return
		}
		payload = payload[overlap:]
	}
	s.push(payload)
	s.drain()
}

// AddSegment accepts a TCP segment of length payload bytes of which only
// prefix was captured, as with TSO/GRO segments above the copy limit. The
// missing tail is skipped when the parser no longer needs it, such as the
// rest of a known-length HTTP body.
func (s *Stream) AddSegment(seq uint32, prefix []byte, length int) {
	if length <= len(prefix) {
		s.Add(seq, prefix)
		return
	}
	if s.failed || s.parser.finished() || int32(seq+uint32(length)-s.expected) <= 0 {
		return // Nothing more is needed, or this is an old retransmission.
	}
	if seq != s.expected {
		s.Fail("TCP payload capture truncated")
		return
	}
	if len(prefix) > 0 {
		s.push(prefix)
	}
	if s.failed || s.parser.finished() {
		return
	}
	if err := s.parser.skip(length - len(prefix)); err != nil {
		s.Fail(err.Error())
		return
	}
	s.expected += uint32(length - len(prefix))
	s.drain()
}

// drain delivers pending segments that became contiguous.
func (s *Stream) drain() {
	for !s.failed {
		var chosenSeq uint32
		var chosen []byte
		for pendingSeq, segment := range s.pending {
			d := int32(pendingSeq - s.expected)
			if d <= 0 && int(-d) < len(segment) {
				chosenSeq, chosen = pendingSeq, segment
				break
			}
			if d < 0 && int(-d) >= len(segment) {
				delete(s.pending, pendingSeq)
				s.pendingBytes -= len(segment)
			}
		}
		if chosen == nil {
			if s.pendingBytes == 0 {
				s.gapSince = time.Time{}
			}
			return
		}
		delete(s.pending, chosenSeq)
		s.pendingBytes -= len(chosen)
		s.push(chosen[int(-int32(chosenSeq-s.expected)):])
	}
}

func (s *Stream) push(payload []byte) {
	s.expected += uint32(len(payload))
	s.lastProgress = time.Now()
	if s.pendingBytes > 0 {
		s.gapSince = time.Now()
	}
	if err := s.parser.feed(payload); err != nil {
		s.Fail(err.Error())
	} else if s.parser.finished() {
		clear(s.pending)
		s.pendingBytes = 0
	}
}

// finished reports that later client bytes cannot change the evidence, so
// reassembly stops and later capture gaps are not parse failures.
func (p *parser) finished() bool {
	switch p.evidence.Kind {
	case "":
		return false
	case "tls":
		return p.tls.done
	case "http":
		return p.http.state == httpStopped
	case "proxy":
		return p.opaque
	default:
		return true
	}
}

func (p *parser) incomplete() bool {
	switch p.evidence.Kind {
	case "", "proxy":
		return len(p.sniff) > 0
	case "tls":
		return !p.tls.done
	case "http":
		return p.http.state != httpStopped && (p.http.state != httpHeaders || len(p.http.buffer) > 0)
	default:
		return false
	}
}

// skip consumes n payload bytes that were not captured.
func (p *parser) skip(n int) error {
	if p.finished() || p.evidence.Kind == "http" && p.http.skip(n) {
		return nil
	}
	return fmt.Errorf("TCP payload capture truncated")
}

type parser struct {
	evidence Evidence
	sniff    []byte
	opaque   bool // The proxy tunnel carries neither TLS nor HTTP.
	tls      tlsParser
	http     httpParser
}

func (p *parser) feed(data []byte) error {
	for {
		switch p.evidence.Kind {
		case "", "proxy":
			p.sniff = append(p.sniff, data...)
			kind, used, target := sniffStream(p.sniff)
			switch kind {
			case "":
				return nil
			case "other":
				if p.evidence.Kind == "proxy" {
					p.opaque = true
				} else {
					p.evidence.Kind = "other"
				}
				p.sniff = nil
				return nil
			case "socks4", "socks5":
				p.evidence.Kind, p.evidence.Proxy, p.evidence.ProxyVia = "proxy", target, strings.ToUpper(kind)
				data, p.sniff = p.sniff[used:], nil
			case "preamble":
				// A load balancer's PROXY header precedes the client's own bytes.
				p.evidence.ProxyClient = target
				data, p.sniff = p.sniff[used:], nil
			default:
				p.evidence.Kind = kind
				data, p.sniff = p.sniff, nil
			}
		case "tls":
			return p.tls.feed(data, &p.evidence)
		case "http":
			if err := p.http.feed(data, &p.evidence); err != nil || p.http.state != httpTunnel {
				return err
			}
			// Bytes after a CONNECT request header belong to the tunnel.
			data, p.http = p.http.buffer, httpParser{}
			p.evidence.Kind = "proxy"
		default:
			return nil
		}
	}
}

// sniffStream classifies the start of a client byte stream or of a proxy
// tunnel. It returns an empty kind while more bytes are needed. For a SOCKS
// request or PROXY protocol preamble it also returns the bytes it spans and
// the requested destination or the original client address.
func sniffStream(b []byte) (kind string, used int, target string) {
	prefix := func(kind string, parse func([]byte) (int, string, bool)) (string, int, string) {
		used, target, ok := parse(b)
		switch {
		case ok && used > 0:
			return kind, used, target
		case ok && len(b) < maxSniffBytes:
			return "", 0, ""
		}
		return "other", 0, ""
	}
	switch {
	case len(b) >= 2 && b[0] == 22 && b[1] == 3:
		return "tls", 0, ""
	case len(b) > 0 && b[0] == 5:
		return prefix("socks5", socks5Handshake)
	case len(b) > 0 && b[0] == 4:
		return prefix("socks4", socks4Request)
	case bytes.HasPrefix(proxyV2Signature, b[:min(len(b), len(proxyV2Signature))]):
		return prefix("preamble", proxyV2Header)
	case bytes.HasPrefix([]byte("PROXY "), b[:min(len(b), 6)]):
		return prefix("preamble", proxyV1Header)
	case len(b) < 8:
		return "", 0, ""
	case looksLikeHTTP(b):
		return "http", 0, ""
	case len(b) < 16:
		return "", 0, ""
	}
	return "other", 0, ""
}

// socks5Handshake parses a SOCKS5 greeting, an optional RFC 1929
// username/password exchange (skipped, never stored) and a CONNECT request.
// ok is false when the bytes cannot be SOCKS5; used is 0 while more are needed.
func socks5Handshake(b []byte) (used int, target string, ok bool) {
	short := func(end int) bool { return len(b) < end }
	if short(2) {
		return 0, "", true
	}
	if b[0] != 5 || b[1] == 0 {
		return 0, "", false
	}
	offset := 2 + int(b[1])
	if short(offset + 1) {
		return 0, "", true
	}
	if b[offset] == 1 { // The server chose username/password authentication.
		if short(offset + 2) {
			return 0, "", true
		}
		offset += 2 + int(b[offset+1])
		if short(offset + 1) {
			return 0, "", true
		}
		offset += 1 + int(b[offset])
	}
	if short(offset + 4) {
		return 0, "", true
	}
	if b[offset] != 5 || b[offset+1] != 1 || b[offset+2] != 0 {
		return 0, "", false
	}
	addressType := b[offset+3]
	offset += 4
	switch addressType {
	case 1:
		if short(offset + 6) {
			return 0, "", true
		}
		target = netip.AddrFrom4([4]byte(b[offset : offset+4])).String()
		offset += 4
	case 4:
		if short(offset + 18) {
			return 0, "", true
		}
		target = netip.AddrFrom16([16]byte(b[offset : offset+16])).String()
		offset += 16
	case 3:
		if short(offset + 1) {
			return 0, "", true
		}
		length := int(b[offset])
		if short(offset + 1 + length + 2) {
			return 0, "", true
		}
		name := b[offset+1 : offset+1+length]
		if !validHostname(name) {
			return 0, "", false
		}
		target = normalizeName(string(name))
		offset += 1 + length
	default:
		return 0, "", false
	}
	return offset + 2, target, true
}

// socks4Request parses a SOCKS4 or SOCKS4a CONNECT request. The user ID is
// skipped; SOCKS4a carries a domain after it when the address is 0.0.0.x.
func socks4Request(b []byte) (used int, target string, ok bool) {
	if len(b) < 8 {
		return 0, "", len(b) < 2 || b[1] == 1
	}
	if b[1] != 1 {
		return 0, "", false
	}
	addr := netip.AddrFrom4([4]byte(b[4:8]))
	userEnd := bytes.IndexByte(b[8:], 0)
	if userEnd < 0 {
		return 0, "", len(b) < 8+256
	}
	offset := 8 + userEnd + 1
	if b[4] != 0 || b[5] != 0 || b[6] != 0 || b[7] == 0 {
		return offset, addr.String(), true
	}
	nameEnd := bytes.IndexByte(b[offset:], 0)
	if nameEnd < 0 {
		return 0, "", len(b) < offset+256
	}
	name := b[offset : offset+nameEnd]
	if !validHostname(name) {
		return 0, "", false
	}
	return offset + nameEnd + 1, normalizeName(string(name)), true
}

var proxyV2Signature = []byte("\r\n\r\n\x00\r\nQUIT\n")

// proxyV1Header parses a PROXY protocol v1 line, at most 107 bytes.
func proxyV1Header(b []byte) (used int, client string, ok bool) {
	end := bytes.Index(b[:min(len(b), 107)], []byte("\r\n"))
	if end < 0 {
		return 0, "", len(b) < 107
	}
	fields := strings.Fields(string(b[:end]))
	if len(fields) == 6 && (fields[1] == "TCP4" || fields[1] == "TCP6") {
		if addr, err := netip.ParseAddr(fields[2]); err == nil {
			client = net.JoinHostPort(addr.String(), fields[4])
		}
	} else if len(fields) < 2 || fields[1] != "UNKNOWN" {
		return 0, "", false
	}
	return end + 2, client, true
}

// proxyV2Header parses a binary PROXY protocol v2 header and its TCP source
// address. TLVs after the addresses are skipped.
func proxyV2Header(b []byte) (used int, client string, ok bool) {
	if len(b) < 16 {
		return 0, "", true
	}
	if b[12]>>4 != 2 {
		return 0, "", false
	}
	used = 16 + int(binary.BigEndian.Uint16(b[14:16]))
	if len(b) < used {
		return 0, "", true
	}
	switch {
	case b[12]&0x0f == 0: // LOCAL: a health check from the balancer itself.
	case b[13] == 0x11 && used >= 16+12:
		client = netip.AddrPortFrom(netip.AddrFrom4([4]byte(b[16:20])), binary.BigEndian.Uint16(b[24:26])).String()
	case b[13] == 0x21 && used >= 16+36:
		client = netip.AddrPortFrom(netip.AddrFrom16([16]byte(b[16:32])).Unmap(), binary.BigEndian.Uint16(b[48:50])).String()
	}
	return used, client, true
}

// StartsClientMessage reports whether a TCP payload begins with a TLS
// ClientHello record or an HTTP/1.x request line, so parsing can start on a
// connection whose SYN was not captured.
func StartsClientMessage(b []byte) bool {
	if len(b) >= 10 && b[0] == 22 && b[1] == 3 && b[5] == 1 && b[9] == 3 {
		return true
	}
	line, _, found := bytes.Cut(b[:min(len(b), 256)], []byte("\r\n"))
	return found && looksLikeHTTP(line) && (bytes.HasSuffix(line, []byte(" HTTP/1.1")) || bytes.HasSuffix(line, []byte(" HTTP/1.0")))
}

func looksLikeHTTP(data []byte) bool {
	space := bytes.IndexByte(data, ' ')
	if space < 3 || space > 10 {
		return false
	}
	switch string(data[:space]) {
	case "GET", "HEAD", "POST", "PUT", "DELETE", "OPTIONS", "PATCH", "TRACE", "CONNECT":
		return true
	default:
		return false
	}
}

// validHostname accepts printable ASCII names without separators, which also
// keeps observed names safe to print on the terminal.
func validHostname(name []byte) bool {
	if len(name) == 0 || len(name) > 253 {
		return false
	}
	for _, b := range name {
		if b < 33 || b > 126 || b == '/' || b == ':' || b == '\\' {
			return false
		}
	}
	return true
}

func normalizeName(name string) string {
	return strings.ToLower(strings.TrimSuffix(strings.TrimSpace(name), "."))
}
