package domain

import (
	"cmp"
	"encoding/binary"
	"fmt"
	"strings"

	"golang.org/x/net/http2/hpack"
)

// h2Preface opens every cleartext HTTP/2 (h2c) connection.
var h2Preface = []byte("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")

const (
	maxH2Block      = 64 << 10
	h2FrameHeaders  = 1
	h2FrameContinue = 9
)

// h2Parser reads the client side of cleartext HTTP/2, as internal gRPC often
// speaks it: each request's :authority, from HEADERS frames decoded with
// HPACK. Other frames, DATA above all, are skipped by length unbuffered.
type h2Parser struct {
	header    []byte // The next frame's 9-byte header, as it arrives.
	kind      byte
	flags     byte
	stream    uint32
	remaining int    // Payload bytes of the current frame still to come.
	frame     []byte // The payload of a HEADERS or CONTINUATION frame.
	block     []byte // One header block, across CONTINUATION frames.
	last      uint32 // Highest stream counted as a request; trailers reuse it.
	decoder   *hpack.Decoder
	stopped   bool
}

func (p *h2Parser) feed(data []byte, e *Evidence) error {
	for len(data) > 0 && !p.stopped {
		if len(p.header) < 9 {
			n := min(len(data), 9-len(p.header))
			p.header, data = append(p.header, data[:n]...), data[n:]
			if len(p.header) < 9 {
				return nil
			}
			p.remaining = int(p.header[0])<<16 | int(p.header[1])<<8 | int(p.header[2])
			p.kind, p.flags = p.header[3], p.header[4]
			p.stream = binary.BigEndian.Uint32(p.header[5:9]) & 0x7fffffff
			if p.headerFrame() && p.remaining > maxH2Block {
				p.stopped = true
				return fmt.Errorf("HTTP/2 header block limit")
			}
		}
		n := min(len(data), p.remaining)
		if p.headerFrame() {
			p.frame = append(p.frame, data[:n]...)
		}
		p.remaining -= n
		data = data[n:]
		if p.remaining > 0 {
			return nil
		}
		if p.headerFrame() {
			if err := p.headers(e); err != nil {
				p.stopped = true
				return err
			}
		}
		p.header, p.frame = p.header[:0], p.frame[:0]
	}
	return nil
}

func (p *h2Parser) headerFrame() bool {
	return p.kind == h2FrameHeaders || p.kind == h2FrameContinue
}

// headers adds a HEADERS or CONTINUATION payload to the header block and
// decodes the block once it ends. Every client block is decoded, trailers
// too, because HPACK's dynamic table depends on all of them.
func (p *h2Parser) headers(e *Evidence) error {
	fragment := p.frame
	if p.kind == h2FrameHeaders {
		if p.flags&0x8 != 0 { // PADDED
			if len(fragment) == 0 || int(fragment[0]) >= len(fragment) {
				return fmt.Errorf("HTTP/2 padding")
			}
			fragment = fragment[1 : len(fragment)-int(fragment[0])]
		}
		if p.flags&0x20 != 0 { // PRIORITY
			if len(fragment) < 5 {
				return fmt.Errorf("HTTP/2 priority")
			}
			fragment = fragment[5:]
		}
		p.block = p.block[:0]
	}
	if len(p.block)+len(fragment) > maxH2Block {
		return fmt.Errorf("HTTP/2 header block limit")
	}
	p.block = append(p.block, fragment...)
	if p.flags&0x4 == 0 { // END_HEADERS: more in CONTINUATION frames.
		return nil
	}
	if p.decoder == nil {
		p.decoder = hpack.NewDecoder(4096, nil)
		p.decoder.SetAllowedMaxDynamicTableSize(64 << 10)
	}
	fields, err := p.decoder.DecodeFull(p.block)
	if err != nil {
		return fmt.Errorf("HTTP/2 HPACK: %w", err)
	}
	var authority string
	for _, field := range fields {
		switch field.Name {
		case ":authority", "host":
			authority = cmp.Or(authority, field.Value)
		case "content-type":
			e.GRPC = e.GRPC || strings.HasPrefix(field.Value, "application/grpc")
		}
	}
	if p.stream <= p.last {
		return nil // Trailers of a counted request.
	}
	p.last = p.stream
	if host := normalizeHTTPHost(authority); host != "" {
		if e.Hosts[host] == 0 && len(e.Hosts) >= maxHTTPHosts {
			return fmt.Errorf("HTTP distinct Host limit")
		}
		e.Hosts[host]++
	}
	return nil
}

// skip consumes uncaptured bytes inside a frame that is not being read.
func (p *h2Parser) skip(n int) bool {
	if len(p.header) < 9 || p.headerFrame() || n > p.remaining {
		return false
	}
	p.remaining -= n
	if p.remaining == 0 {
		p.header = p.header[:0]
	}
	return true
}
