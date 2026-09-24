package domain

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"time"
)

const (
	// maxServerFlight bounds the server bytes kept while a record is
	// incomplete: the ServerHello and the record that holds the leaf
	// certificate fit well within it.
	maxServerFlight     = 64 * 1024
	maxCertificateNames = 8
)

// serverFlight reads the plaintext start of a TLS server's reply: the
// ServerHello and, when the client sent no SNI and the version is below TLS
// 1.3, the leaf certificate. Segments that arrive ahead of a gap, as after a
// loss upstream of the capture point, wait for the retransmission within the
// same bounds as the client side.
type serverFlight struct {
	expected     uint32
	started      bool
	done         bool
	record       []byte
	handshake    []byte
	pending      map[uint32][]byte
	pendingBytes int
	gapSince     time.Time
}

func (f *serverFlight) stop() {
	f.done, f.record, f.handshake, f.pending, f.pendingBytes = true, nil, nil, nil, 0
}

// AddServer reads one server segment of a connection whose ClientHello was
// parsed; length is the segment's payload length on the wire. The reply
// starts at the first segment that starts with a TLS record, after any
// CONNECT or SOCKS reply of a proxy.
func (s *Stream) AddServer(seq uint32, payload []byte, length int) {
	f, e := &s.server, &s.parser.evidence
	if f.done || len(payload) == 0 || e.Kind != "tls" || !s.parser.tls.done || e.NoHandshake {
		return
	}
	if !f.started {
		if len(payload) < 2 || payload[0] != 22 && payload[0] != 21 || payload[1] != 3 {
			return
		}
		f.started, f.expected = true, seq
	}
	if int32(seq-f.expected) > 0 {
		if length > len(payload) || len(f.pending) >= maxPendingParts || f.pendingBytes+len(payload) > maxServerFlight {
			f.stop()
			return
		}
		if f.pending == nil {
			f.pending, f.gapSince = make(map[uint32][]byte), time.Now()
		}
		if old := f.pending[seq]; len(old) < len(payload) {
			f.pending[seq] = bytes.Clone(payload)
			f.pendingBytes += len(payload) - len(old)
		}
		return
	}
	f.add(seq, payload, length > len(payload), e)
	for delivered := true; delivered && !f.done; {
		delivered = false
		for pendingSeq, segment := range f.pending {
			if int32(pendingSeq-f.expected) <= 0 {
				delete(f.pending, pendingSeq)
				f.pendingBytes -= len(segment)
				f.add(pendingSeq, segment, false, e)
				delivered = true
				break
			}
		}
	}
	if len(f.pending) > 0 {
		f.gapSince = time.Now() // Progress: the next gap starts now.
	}
}

// add feeds a segment that starts at or before the next expected byte.
func (f *serverFlight) add(seq uint32, payload []byte, truncated bool, e *Evidence) {
	if d := int32(seq - f.expected); d < 0 {
		if int(-d) >= len(payload) {
			return // A retransmission.
		}
		payload = payload[-d:]
	}
	f.expected += uint32(len(payload))
	if err := f.feed(payload, e); err != nil || truncated {
		f.stop()
	}
}

func (f *serverFlight) feed(data []byte, e *Evidence) error {
	if len(f.record)+len(data) > maxServerFlight {
		return fmt.Errorf("TLS server flight size limit")
	}
	f.record = append(f.record, data...)
	for len(f.record) >= 5 && !f.done {
		kind, length := f.record[0], int(binary.BigEndian.Uint16(f.record[3:5]))
		if f.record[1] != 3 || length == 0 || length > 18432 {
			return fmt.Errorf("invalid TLS record")
		}
		if len(f.record) < 5+length {
			return nil
		}
		if kind != 22 {
			// An alert ends the handshake; ChangeCipherSpec or an encrypted
			// record ends its plaintext part.
			f.stop()
			return nil
		}
		if len(f.handshake)+length > maxServerFlight {
			return fmt.Errorf("TLS server flight size limit")
		}
		f.handshake = append(f.handshake, f.record[5:5+length]...)
		f.record = f.record[5+length:]
		if err := f.messages(e); err != nil {
			return err
		}
	}
	return nil
}

// messages parses the handshake messages buffered so far.
func (f *serverFlight) messages(e *Evidence) error {
	for len(f.handshake) >= 4 && !f.done {
		kind, body := f.handshake[0], f.handshake[4:]
		length := int(f.handshake[1])<<16 | int(f.handshake[2])<<8 | int(f.handshake[3])
		switch {
		case kind == 11:
			// Certificate: the leaf is the first entry, so the rest of the
			// chain is never waited for.
			if len(body) < 6 {
				return nil
			}
			leaf := int(body[3])<<16 | int(body[4])<<8 | int(body[5])
			if len(body) < 6+leaf {
				return nil
			}
			e.Certificate = certificateNames(body[6 : 6+leaf])
			f.stop()
		case len(body) < length:
			return nil
		case kind == 2:
			version, alpn, err := parseServerHello(body[:length])
			if err != nil {
				return err
			}
			e.TLSVersion, e.ServerALPN = tlsVersionName(version), alpn
			f.handshake = f.handshake[4+length:]
			// TLS 1.3 encrypts the rest, a HelloRetryRequest included, and the
			// certificate is read only to name a connection without SNI.
			if version >= 0x0304 || e.SNI != "" {
				f.stop()
			}
		default:
			f.stop() // No certificate follows, as in a resumed session.
		}
	}
	return nil
}

// parseServerHello returns the version and application protocol the server
// chose. TLS 1.3 names its version in supported_versions and sends ALPN
// encrypted.
func parseServerHello(data []byte) (uint16, string, error) {
	c := cursor{data: data}
	legacy, err := c.uint16()
	if err != nil {
		return 0, "", err
	}
	if _, err := c.take(32); err != nil { // Random.
		return 0, "", err
	}
	sessionLen, err := c.uint8()
	if err != nil {
		return 0, "", err
	}
	if _, err := c.take(sessionLen + 3); err != nil { // Session ID, cipher suite, compression.
		return 0, "", err
	}
	version, alpn := uint16(legacy), ""
	if c.off == len(c.data) {
		return version, "", nil
	}
	extensionsLen, err := c.uint16()
	if err != nil {
		return 0, "", err
	}
	extensions, err := c.take(extensionsLen)
	if err != nil || c.off != len(c.data) {
		return 0, "", fmt.Errorf("invalid TLS extensions length")
	}
	ec := cursor{data: extensions}
	for ec.off < len(ec.data) {
		kind, err := ec.uint16()
		if err != nil {
			return 0, "", err
		}
		length, err := ec.uint16()
		if err != nil {
			return 0, "", err
		}
		body, err := ec.take(length)
		if err != nil {
			return 0, "", err
		}
		switch kind {
		case 43: // supported_versions
			if len(body) != 2 {
				return 0, "", fmt.Errorf("invalid TLS supported_versions")
			}
			version = binary.BigEndian.Uint16(body)
		case 16:
			protocols, err := parseALPN(body)
			if err != nil {
				return 0, "", err
			}
			if len(protocols) == 1 {
				alpn = protocols[0]
			}
		}
	}
	return version, alpn, nil
}

func tlsVersionName(version uint16) string {
	switch {
	case version == 0x0300:
		return "SSL 3.0"
	case version >= 0x0301 && version <= 0x0304:
		return fmt.Sprintf("TLS 1.%d", version-0x0301)
	}
	return fmt.Sprintf("TLS version 0x%04x", version)
}

var (
	oidCommonName     = []byte{0x55, 0x04, 0x03} // 2.5.4.3
	oidSubjectAltName = []byte{0x55, 0x1d, 0x11} // 2.5.29.17
)

// derElement splits the first DER element off b: its tag, its contents and
// the bytes after it.
func derElement(b []byte) (byte, []byte, []byte, bool) {
	if len(b) < 2 {
		return 0, nil, nil, false
	}
	tag, length, b := b[0], int(b[1]), b[2:]
	if length >= 0x80 {
		size := length & 0x7f
		if size == 0 || size > 3 || len(b) < size {
			return 0, nil, nil, false
		}
		length = 0
		for _, c := range b[:size] {
			length = length<<8 | int(c)
		}
		b = b[size:]
	}
	if length > len(b) {
		return 0, nil, nil, false
	}
	return tag, b[:length], b[length:], true
}

// certificateNames reads a certificate's DNS subject alternative names, or
// its subject common name when it has none. Nothing is verified: the names
// only label the connection, and a DER walk costs far less than a full
// X.509 parse.
func certificateNames(certificate []byte) []string {
	_, certificate, _, ok := derElement(certificate)
	if !ok {
		return nil
	}
	_, tbs, _, ok := derElement(certificate)
	if !ok {
		return nil
	}
	if tag, _, rest, ok := derElement(tbs); ok && tag == 0xa0 {
		tbs = rest // Explicit version.
	}
	// Serial number, signature, issuer, validity, subject, public key, then
	// the optional unique IDs and [3] extensions.
	var subject, extensions []byte
	for i := 0; len(tbs) > 0; i++ {
		tag, body, rest, ok := derElement(tbs)
		if !ok {
			return nil
		}
		tbs = rest
		if i == 4 {
			subject = body
		} else if tag == 0xa3 {
			extensions = body
		}
	}
	var names []string
	_, list, _, _ := derElement(extensions)
	for len(list) > 0 {
		_, extension, rest, ok := derElement(list)
		if !ok {
			break
		}
		list = rest
		_, oid, value, ok := derElement(extension)
		if !ok || !bytes.Equal(oid, oidSubjectAltName) {
			continue
		}
		tag, octets, value, ok := derElement(value)
		if ok && tag == 0x01 { // Critical flag.
			tag, octets, _, ok = derElement(value)
		}
		if !ok || tag != 0x04 {
			break
		}
		_, general, _, ok := derElement(octets)
		for ok && len(general) > 0 && len(names) < maxCertificateNames {
			var name []byte
			tag, name, general, ok = derElement(general)
			if ok && tag == 0x82 && validHostname(name) { // dNSName
				names = append(names, normalizeName(string(name)))
			}
		}
	}
	for len(names) == 0 && len(subject) > 0 {
		_, set, rest, ok := derElement(subject)
		if !ok {
			break
		}
		subject = rest
		_, attribute, _, _ := derElement(set)
		if _, oid, value, ok := derElement(attribute); ok && bytes.Equal(oid, oidCommonName) {
			if _, name, _, ok := derElement(value); ok && validHostname(name) {
				names = append(names, normalizeName(string(name)))
			}
		}
	}
	return names
}

// alertNames are the alert descriptions of RFC 8446 and RFC 5246 that a
// failed handshake can carry.
var alertNames = map[byte]string{
	0: "close notify", 10: "unexpected message", 20: "bad record MAC", 22: "record overflow",
	40: "handshake failure", 42: "bad certificate", 43: "unsupported certificate",
	44: "certificate revoked", 45: "certificate expired", 46: "certificate unknown",
	47: "illegal parameter", 48: "unknown certificate authority", 49: "access denied",
	50: "decode error", 51: "decrypt error", 70: "protocol version", 71: "insufficient security",
	80: "internal error", 86: "inappropriate fallback", 90: "user canceled",
	109: "missing extension", 110: "unsupported extension", 112: "unrecognized name",
	113: "bad certificate status response", 115: "unknown PSK identity",
	116: "certificate required", 120: "no application protocol",
}

// Alert records the first plaintext alert either side sends. A peer that
// fails a handshake sends one alert record in its own segment before it
// closes; later alerts are encrypted and never read.
func (s *Stream) Alert(payload []byte, server bool) {
	e := &s.parser.evidence
	if e.Kind != "tls" || e.Alert != "" || len(payload) != 7 || payload[0] != 21 || payload[1] != 3 || payload[3] != 0 || payload[4] != 2 || payload[5] != 1 && payload[5] != 2 {
		return
	}
	name, ok := alertNames[payload[6]]
	if !ok {
		return
	}
	side := "client"
	if server {
		side = "server"
	}
	e.Alert = side + " alert: " + name
}
