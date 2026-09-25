package domain

import (
	"encoding/binary"
	"fmt"
)

const maxClientHello = 64 * 1024

type tlsParser struct {
	record    []byte
	handshake []byte
	done      bool
}

func (p *tlsParser) feed(data []byte, evidence *Evidence) error {
	if p.done {
		return nil
	}
	if len(p.record)+len(data) > maxClientHello+2*18432 {
		return fmt.Errorf("TLS ClientHello size limit")
	}
	p.record = append(p.record, data...)
	for len(p.record) >= 5 {
		if p.record[0] != 22 || p.record[1] != 3 {
			return fmt.Errorf("unexpected TLS record before ClientHello")
		}
		length := int(binary.BigEndian.Uint16(p.record[3:5]))
		if length < 1 || length > 18432 {
			return fmt.Errorf("invalid TLS record length")
		}
		if len(p.record) < 5+length {
			return nil
		}
		p.handshake = append(p.handshake, p.record[5:5+length]...)
		p.record = p.record[5+length:]
		if len(p.handshake) < 4 {
			continue
		}
		if p.handshake[0] != 1 {
			return fmt.Errorf("first TLS handshake is not ClientHello")
		}
		messageLen := int(p.handshake[1])<<16 | int(p.handshake[2])<<8 | int(p.handshake[3])
		if messageLen > maxClientHello {
			return fmt.Errorf("TLS ClientHello size limit")
		}
		if len(p.handshake) < 4+messageLen {
			continue
		}
		hello, err := parseClientHello(p.handshake[4 : 4+messageLen])
		if err != nil {
			return err
		}
		evidence.SNI, evidence.NoSNI, evidence.ECH, evidence.ALPN = hello.sni, hello.sni == "", hello.ech, hello.alpn
		evidence.JA4 = new(hello.ja4.fingerprint('t'))
		p.done = true
		p.record, p.handshake = nil, nil
		return nil
	}
	return nil
}

// NewMissedTLSHandshake marks a TLS connection whose ClientHello was not
// captured, usually because the connection predates socktrail. reason keeps a
// reassembly failure that explains the gap.
func NewMissedTLSHandshake(reason string) *Stream {
	s := &Stream{parser: parser{evidence: Evidence{Kind: "tls", NoHandshake: true, ParseError: reason}}}
	s.parser.tls.done = true
	return s
}

type cursor struct {
	data []byte
	off  int
}

func (c *cursor) take(n int) ([]byte, error) {
	if n < 0 || n > len(c.data)-c.off {
		return nil, fmt.Errorf("truncated TLS handshake message")
	}
	part := c.data[c.off : c.off+n]
	c.off += n
	return part, nil
}

func (c *cursor) uint8() (int, error) {
	b, err := c.take(1)
	if err != nil {
		return 0, err
	}
	return int(b[0]), nil
}

func (c *cursor) uint16() (int, error) {
	b, err := c.take(2)
	if err != nil {
		return 0, err
	}
	return int(binary.BigEndian.Uint16(b)), nil
}

// helloFields is what a ClientHello says about its destination and the
// client software.
type helloFields struct {
	sni  string
	ech  bool
	alpn []string
	ja4  ja4Fields
}

func parseClientHello(data []byte) (helloFields, error) {
	var hello helloFields
	c := cursor{data: data}
	version, err := c.uint16()
	if err != nil {
		return hello, err
	}
	hello.ja4.version = uint16(version)   //nolint:gosec // G115: uint16 read from two bytes.
	if _, err := c.take(32); err != nil { // Random.
		return hello, err
	}
	sessionLen, err := c.uint8()
	if err != nil {
		return hello, err
	}
	if _, err := c.take(sessionLen); err != nil {
		return hello, err
	}
	cipherLen, err := c.uint16()
	if err != nil {
		return hello, err
	}
	if cipherLen == 0 || cipherLen%2 != 0 {
		return hello, fmt.Errorf("invalid TLS cipher suite list")
	}
	ciphers, err := c.take(cipherLen)
	if err != nil {
		return hello, err
	}
	hello.ja4.ciphers = uint16List(ciphers)
	compressionLen, err := c.uint8()
	if err != nil {
		return hello, err
	}
	if _, err := c.take(compressionLen); err != nil {
		return hello, err
	}
	// TLS 1.2 permits ClientHello to omit the extensions field entirely.
	if c.off == len(c.data) {
		return hello, nil
	}
	extensionsLen, err := c.uint16()
	if err != nil {
		return hello, err
	}
	extensions, err := c.take(extensionsLen)
	if err != nil || c.off != len(c.data) {
		return hello, fmt.Errorf("invalid TLS extensions length")
	}
	ec := cursor{data: extensions}
	var hasSNI bool
	for ec.off < len(ec.data) {
		kind, err := ec.uint16()
		if err != nil {
			return hello, err
		}
		length, err := ec.uint16()
		if err != nil {
			return hello, err
		}
		body, err := ec.take(length)
		if err != nil {
			return hello, err
		}
		hello.ja4.extensions = append(hello.ja4.extensions, uint16(kind)) //nolint:gosec // G115: uint16 read from two bytes.
		switch kind {
		case 0:
			if hasSNI {
				return hello, fmt.Errorf("duplicate SNI extension")
			}
			hasSNI = true
			hello.sni, err = parseSNI(body)
			if err != nil {
				return hello, err
			}
		case 13: // signature_algorithms
			if len(body) >= 2 && int(binary.BigEndian.Uint16(body)) == len(body)-2 && len(body)%2 == 0 {
				hello.ja4.signatures = uint16List(body[2:])
			}
		case 16:
			hello.alpn, err = parseALPN(body)
			if err != nil {
				return hello, err
			}
			if len(body) > 3 && int(body[2]) > 0 && 3+int(body[2]) <= len(body) {
				hello.ja4.alpn = body[3 : 3+int(body[2])]
			}
		case 43: // supported_versions
			if len(body) >= 1 && int(body[0]) == len(body)-1 && len(body)%2 == 1 {
				hello.ja4.versions = uint16List(body[1:])
			}
		case 0xfe0d:
			hello.ech = true
		}
	}
	return hello, nil
}

func uint16List(b []byte) []uint16 {
	values := make([]uint16, 0, len(b)/2)
	for i := 0; i+1 < len(b); i += 2 {
		values = append(values, binary.BigEndian.Uint16(b[i:]))
	}
	return values
}

func parseSNI(data []byte) (string, error) {
	c := cursor{data: data}
	listLen, err := c.uint16()
	if err != nil || listLen != len(data)-2 {
		return "", fmt.Errorf("invalid SNI list length")
	}
	if listLen == 0 {
		return "", fmt.Errorf("empty SNI list")
	}
	var hostname string
	var hasHostname bool
	for c.off < len(data) {
		kind, err := c.uint8()
		if err != nil {
			return "", err
		}
		length, err := c.uint16()
		if err != nil {
			return "", err
		}
		name, err := c.take(length)
		if err != nil {
			return "", err
		}
		if kind == 0 {
			if hasHostname {
				return "", fmt.Errorf("duplicate SNI hostname")
			}
			hasHostname = true
			if !validHostname(name) {
				return "", fmt.Errorf("invalid SNI hostname")
			}
			hostname = normalizeName(string(name))
		}
	}
	return hostname, nil
}

func parseALPN(data []byte) ([]string, error) {
	c := cursor{data: data}
	length, err := c.uint16()
	if err != nil || length != len(data)-2 {
		return nil, fmt.Errorf("invalid ALPN list length")
	}
	var protocols []string
	for c.off < len(data) {
		n, err := c.uint8()
		if err != nil || n == 0 {
			return nil, fmt.Errorf("invalid ALPN protocol length")
		}
		protocol, err := c.take(n)
		if err != nil {
			return nil, err
		}
		if printable(protocol) { // GREASE and binary IDs could garble a terminal.
			protocols = append(protocols, string(protocol))
		}
	}
	return protocols, nil
}

func printable(b []byte) bool {
	for _, c := range b {
		if c < 33 || c > 126 {
			return false
		}
	}
	return true
}
