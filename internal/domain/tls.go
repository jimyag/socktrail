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
		sni, ech, alpn, err := parseClientHello(p.handshake[4 : 4+messageLen])
		if err != nil {
			return err
		}
		evidence.SNI, evidence.NoSNI, evidence.ECH, evidence.ALPN = sni, sni == "", ech, alpn
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
		return nil, fmt.Errorf("truncated TLS ClientHello")
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

func parseClientHello(data []byte) (string, bool, []string, error) {
	c := cursor{data: data}
	if _, err := c.take(34); err != nil { // Legacy version and random.
		return "", false, nil, err
	}
	sessionLen, err := c.uint8()
	if err != nil {
		return "", false, nil, err
	}
	if _, err := c.take(sessionLen); err != nil {
		return "", false, nil, err
	}
	cipherLen, err := c.uint16()
	if err != nil {
		return "", false, nil, err
	}
	if cipherLen == 0 || cipherLen%2 != 0 {
		return "", false, nil, fmt.Errorf("invalid TLS cipher suite list")
	}
	if _, err := c.take(cipherLen); err != nil {
		return "", false, nil, err
	}
	compressionLen, err := c.uint8()
	if err != nil {
		return "", false, nil, err
	}
	if _, err := c.take(compressionLen); err != nil {
		return "", false, nil, err
	}
	// TLS 1.2 permits ClientHello to omit the extensions field entirely.
	if c.off == len(c.data) {
		return "", false, nil, nil
	}
	extensionsLen, err := c.uint16()
	if err != nil {
		return "", false, nil, err
	}
	extensions, err := c.take(extensionsLen)
	if err != nil || c.off != len(c.data) {
		return "", false, nil, fmt.Errorf("invalid TLS extensions length")
	}
	ec := cursor{data: extensions}
	var sni string
	var hasSNI bool
	var ech bool
	var alpn []string
	for ec.off < len(ec.data) {
		kind, err := ec.uint16()
		if err != nil {
			return "", false, nil, err
		}
		length, err := ec.uint16()
		if err != nil {
			return "", false, nil, err
		}
		body, err := ec.take(length)
		if err != nil {
			return "", false, nil, err
		}
		switch kind {
		case 0:
			if hasSNI {
				return "", false, nil, fmt.Errorf("duplicate SNI extension")
			}
			hasSNI = true
			sni, err = parseSNI(body)
			if err != nil {
				return "", false, nil, err
			}
		case 16:
			alpn, err = parseALPN(body)
			if err != nil {
				return "", false, nil, err
			}
		case 0xfe0d:
			ech = true
		}
	}
	return sni, ech, alpn, nil
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
		protocols = append(protocols, string(protocol))
	}
	return protocols, nil
}
