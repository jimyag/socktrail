package domain

import (
	"encoding/binary"
	"net/netip"
	"slices"
	"time"
)

const (
	dnsHintAge         = 10 * time.Minute
	maxDNSAddresses    = 16384
	maxNamesPerAddress = 4
)

// DNSAnswers returns the question name and the A/AAAA addresses of a DNS
// response. Every address, including one behind a CNAME chain, is paired with
// the name the client asked for.
func DNSAnswers(msg []byte) (string, []netip.Addr) {
	if len(msg) < 12 || msg[2]&0x80 == 0 || msg[3]&0x0f != 0 || binary.BigEndian.Uint16(msg[4:6]) != 1 {
		return "", nil // Not a successful response to a single question.
	}
	answers := int(binary.BigEndian.Uint16(msg[6:8]))
	name, offset, ok := questionName(msg, 12)
	if !ok || offset+4 > len(msg) {
		return "", nil
	}
	if questionType := binary.BigEndian.Uint16(msg[offset:]); questionType != 1 && questionType != 28 {
		return "", nil
	}
	offset += 4
	var addrs []netip.Addr
	for range answers {
		if offset, ok = skipName(msg, offset); !ok || offset+10 > len(msg) {
			break
		}
		recordType, class := binary.BigEndian.Uint16(msg[offset:]), binary.BigEndian.Uint16(msg[offset+2:])
		length := int(binary.BigEndian.Uint16(msg[offset+8:]))
		offset += 10
		if offset+length > len(msg) {
			break
		}
		switch {
		case class == 1 && recordType == 1 && length == 4:
			addrs = append(addrs, netip.AddrFrom4([4]byte(msg[offset:offset+4])))
		case class == 1 && recordType == 28 && length == 16:
			addrs = append(addrs, netip.AddrFrom16([16]byte(msg[offset:offset+16])).Unmap())
		}
		offset += length
	}
	return name, addrs
}

// DNSQuestion returns the name and type of a DNS message's first question.
func DNSQuestion(msg []byte) (string, uint16, bool) {
	if len(msg) < 12 || binary.BigEndian.Uint16(msg[4:6]) == 0 {
		return "", 0, false
	}
	name, offset, ok := questionName(msg, 12)
	if !ok || offset+2 > len(msg) {
		return "", 0, false
	}
	return name, binary.BigEndian.Uint16(msg[offset:]), true
}

// questionName reads an uncompressed question name, as resolvers send it.
func questionName(msg []byte, offset int) (string, int, bool) {
	var name []byte
	for {
		if offset >= len(msg) {
			return "", 0, false
		}
		length := int(msg[offset])
		offset++
		if length == 0 {
			break
		}
		if length > 63 || offset+length > len(msg) {
			return "", 0, false
		}
		if len(name) > 0 {
			name = append(name, '.')
		}
		name = append(name, msg[offset:offset+length]...)
		offset += length
	}
	if !validHostname(name) {
		return "", 0, false
	}
	return normalizeName(string(name)), offset, true
}

func skipName(msg []byte, offset int) (int, bool) {
	for offset < len(msg) {
		length := int(msg[offset])
		switch {
		case length == 0:
			return offset + 1, true
		case length&0xc0 == 0xc0:
			return offset + 2, offset+2 <= len(msg)
		case length > 63:
			return 0, false
		}
		offset += 1 + length
	}
	return 0, false
}

type dnsAnswer struct {
	name        string
	first, last time.Time
}

// DNSCache remembers which names recently resolved to each address. It is a
// hint source only: one address can serve many names, so a DNS name never
// replaces Host or SNI evidence.
type DNSCache struct {
	answers map[netip.Addr][]dnsAnswer // Ordered by first observation.
}

// Observe records the answers of a DNS response seen at now.
func (c *DNSCache) Observe(msg []byte, now time.Time) {
	name, addrs := DNSAnswers(msg)
	c.ObserveAnswers(name, addrs, now)
}

// ObserveAnswers records an already parsed response, so callers can also use
// its addresses for a connection's recent-query history.
func (c *DNSCache) ObserveAnswers(name string, addrs []netip.Addr, now time.Time) {
	for _, addr := range addrs {
		if c.answers == nil {
			c.answers = make(map[netip.Addr][]dnsAnswer)
		}
		known, exists := c.answers[addr]
		if !exists && len(c.answers) >= maxDNSAddresses {
			return
		}
		if i := slices.IndexFunc(known, func(a dnsAnswer) bool { return a.name == name }); i >= 0 {
			known[i].last = now
			continue
		}
		known = append(known, dnsAnswer{name: name, first: now, last: now})
		if len(known) > maxNamesPerAddress {
			known = known[1:]
		}
		c.answers[addr] = known
	}
}

// Lookup returns the name resolved to addr most recently before a connection
// that started at, allowing one second for capture goroutines of different
// interfaces to deliver the answer after the connection's first packet. With
// allowLater, a connection that predates every retained answer takes the
// earliest later one, as a re-resolution of the name it was opened for.
func (c *DNSCache) Lookup(addr netip.Addr, at time.Time, allowLater bool) string {
	var name string
	for _, answer := range c.answers[addr.Unmap()] {
		if answer.first.After(at.Add(time.Second)) {
			if name == "" && allowLater {
				return answer.name
			}
			break
		}
		name = answer.name
	}
	return name
}

// Names lists every retained name for addr, oldest first.
func (c *DNSCache) Names(addr netip.Addr) []string {
	var names []string
	for _, answer := range c.answers[addr.Unmap()] {
		names = append(names, answer.name)
	}
	return names
}

// Expire drops names not seen in a DNS answer for the hint window.
func (c *DNSCache) Expire(now time.Time) {
	for addr, known := range c.answers {
		known = slices.DeleteFunc(known, func(a dnsAnswer) bool { return now.Sub(a.last) > dnsHintAge })
		if len(known) == 0 {
			delete(c.answers, addr)
		} else {
			c.answers[addr] = known
		}
	}
}

// NewDNSHint records that the peer address was a recent DNS answer for name.
func NewDNSHint(name string) *Stream {
	return &Stream{parser: parser{evidence: Evidence{Kind: "dns", DNS: name}}}
}
