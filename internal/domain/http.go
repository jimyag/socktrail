package domain

import (
	"bytes"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
)

const (
	maxHTTPHeader = 16 * 1024
	maxChunkLine  = 256
	maxHTTPHosts  = 256
)

type httpState uint8

const (
	httpHeaders httpState = iota
	httpFixedBody
	httpChunkSize
	httpChunkData
	httpChunkEnd
	httpChunkTrailer
	httpTunnel // A CONNECT request header ended; later bytes are tunnel payload.
	httpH2C    // An h2c upgrade succeeded; the buffer starts with the HTTP/2 preface.
	httpStopped
)

type httpParser struct {
	state     httpState
	buffer    []byte
	remaining uint64
	h2c       bool // The last request asked to upgrade to cleartext HTTP/2.
}

func (p *httpParser) feed(data []byte, evidence *Evidence) error {
	if p.state == httpStopped {
		return nil
	}
	p.buffer = append(p.buffer, data...)
	for {
		switch p.state {
		case httpHeaders:
			if p.h2c {
				// The client sends the HTTP/2 preface only after the server's
				// 101 Switching Protocols; after a refusal it goes on in HTTP/1.1.
				if bytes.HasPrefix(p.buffer, h2Preface) {
					p.state = httpH2C
					return nil
				}
				if bytes.HasPrefix(h2Preface, p.buffer) {
					return nil
				}
				p.h2c = false
			}
			end := bytes.Index(p.buffer, []byte("\r\n\r\n"))
			if end < 0 {
				if len(p.buffer) > maxHTTPHeader {
					return fmt.Errorf("HTTP header size limit")
				}
				return nil
			}
			if end+4 > maxHTTPHeader {
				return fmt.Errorf("HTTP header size limit")
			}
			method, target, bodyLength, chunked, upgrade, host, err := parseHTTPHeader(p.buffer[:end])
			if err != nil {
				return err
			}
			p.buffer = p.buffer[end+4:]
			if method == "CONNECT" {
				// The authority names the proxied destination, not a request Host.
				evidence.Proxy, evidence.ProxyVia = normalizeHTTPHost(target), "CONNECT"
				p.state = httpTunnel
				return nil
			}
			if host != "" {
				if evidence.Hosts[host] == 0 && len(evidence.Hosts) >= maxHTTPHosts {
					return fmt.Errorf("HTTP distinct Host limit")
				}
				if evidence.Hosts == nil {
					evidence.Hosts = make(map[string]uint64)
				}
				evidence.Hosts[host]++
			}
			if strings.EqualFold(upgrade, "h2c") {
				p.h2c = true
			} else if upgrade != "" {
				p.state, p.buffer = httpStopped, nil // WebSocket and others: not HTTP any more.
				return nil
			}
			if chunked {
				p.state = httpChunkSize
			} else if bodyLength > 0 {
				p.state, p.remaining = httpFixedBody, bodyLength
			}
		case httpFixedBody, httpChunkData:
			consume := min(uint64(len(p.buffer)), p.remaining)
			p.buffer = p.buffer[consume:]
			p.remaining -= consume
			if p.remaining > 0 {
				return nil
			}
			if p.state == httpFixedBody {
				p.state = httpHeaders
			} else {
				p.state = httpChunkEnd
			}
		case httpChunkSize:
			end := bytes.Index(p.buffer, []byte("\r\n"))
			if end < 0 {
				if len(p.buffer) > maxChunkLine {
					return fmt.Errorf("HTTP chunk size line limit")
				}
				return nil
			}
			if end > maxChunkLine {
				return fmt.Errorf("HTTP chunk size line limit")
			}
			sizeText, _, _ := bytes.Cut(p.buffer[:end], []byte(";"))
			size, err := strconv.ParseUint(strings.TrimSpace(string(sizeText)), 16, 63)
			if err != nil {
				return fmt.Errorf("invalid HTTP chunk size: %w", err)
			}
			p.buffer = p.buffer[end+2:]
			if size == 0 {
				p.state = httpChunkTrailer
			} else {
				p.state, p.remaining = httpChunkData, size
			}
		case httpChunkEnd:
			if len(p.buffer) < 2 {
				return nil
			}
			if p.buffer[0] != '\r' || p.buffer[1] != '\n' {
				return fmt.Errorf("invalid HTTP chunk terminator")
			}
			p.buffer = p.buffer[2:]
			p.state = httpChunkSize
		case httpChunkTrailer:
			if len(p.buffer) >= 2 && p.buffer[0] == '\r' && p.buffer[1] == '\n' {
				p.buffer = p.buffer[2:]
				p.state = httpHeaders
				continue
			}
			end := bytes.Index(p.buffer, []byte("\r\n\r\n"))
			if end < 0 {
				if len(p.buffer) > maxHTTPHeader {
					return fmt.Errorf("HTTP chunk trailer size limit")
				}
				return nil
			}
			p.buffer = p.buffer[end+4:]
			p.state = httpHeaders
		case httpStopped:
			p.buffer = nil
			return nil
		}
		if len(p.buffer) == 0 {
			return nil
		}
	}
}

// skip consumes n body bytes that were not captured. Only a body whose
// remaining length is already known can be skipped.
func (p *httpParser) skip(n int) bool {
	//nolint:gosec // G115: n is a nonnegative count of consumed bytes.
	if len(p.buffer) != 0 || p.state != httpFixedBody && p.state != httpChunkData || uint64(n) > p.remaining {
		return false
	}
	//nolint:gosec // G115: n is a nonnegative count of consumed bytes.
	p.remaining -= uint64(n)
	if p.remaining == 0 && p.state == httpFixedBody {
		p.state = httpHeaders
	} else if p.remaining == 0 {
		p.state = httpChunkEnd
	}
	return true
}

func parseHTTPHeader(header []byte) (method, target string, bodyLength uint64, chunked bool, upgrade, host string, err error) {
	lines := bytes.Split(header, []byte("\r\n"))
	parts := bytes.Fields(lines[0])
	if len(parts) != 3 || !looksLikeHTTP(lines[0]) || (string(parts[2]) != "HTTP/1.1" && string(parts[2]) != "HTTP/1.0") {
		err = fmt.Errorf("invalid HTTP/1.1 request line")
		return
	}
	method, target = string(parts[0]), string(parts[1])
	var sawHost, sawLength, sawEncoding bool
	for _, line := range lines[1:] {
		name, value, ok := bytes.Cut(line, []byte(":"))
		if !ok {
			err = fmt.Errorf("invalid HTTP header field")
			return
		}
		value = bytes.TrimSpace(value)
		switch strings.ToLower(string(name)) {
		case "host":
			if sawHost {
				err = fmt.Errorf("duplicate HTTP Host")
				return
			}
			sawHost = true
			host = normalizeHTTPHost(string(value))
		case "content-length":
			if sawLength {
				err = fmt.Errorf("duplicate HTTP Content-Length")
				return
			}
			sawLength = true
			bodyLength, err = strconv.ParseUint(string(value), 10, 63)
			if err != nil {
				return
			}
		case "transfer-encoding":
			sawEncoding = true
			chunked = strings.EqualFold(strings.TrimSpace(string(value)), "chunked")
			if !chunked {
				err = fmt.Errorf("unsupported HTTP Transfer-Encoding")
				return
			}
		case "upgrade":
			upgrade = string(value)
		}
	}
	if sawLength && sawEncoding {
		err = fmt.Errorf("conflicting HTTP body framing")
	}
	return
}

// normalizeHTTPHost returns the host of a Host header or CONNECT authority.
// Names that are not IP literals must pass validHostname, so control bytes
// never reach the terminal.
func normalizeHTTPHost(value string) string {
	value = strings.TrimSpace(value)
	if value == "" || strings.ContainsAny(value, "/\\@ \t\r\n") {
		return ""
	}
	host := value
	if strings.HasPrefix(value, "[") {
		if h, _, err := net.SplitHostPort(value); err == nil {
			host = h
		} else {
			host = strings.Trim(value, "[]")
		}
	} else if h, port, ok := strings.Cut(value, ":"); ok {
		if _, err := strconv.ParseUint(port, 10, 16); err == nil {
			host = h
		}
	}
	if addr, err := netip.ParseAddr(host); err == nil {
		return addr.String()
	}
	if !validHostname([]byte(host)) {
		return ""
	}
	return normalizeName(host)
}
