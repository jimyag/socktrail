package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"strings"
	"time"

	"github.com/jimyag/socktrail/internal/capture"
	"github.com/jimyag/socktrail/internal/domain"
)

// dnsState summarizes a DNS, mDNS or LLMNR flow: its latest question and how
// it was answered.
type dnsState struct {
	Queries, Responses, Failures uint64
	Name                         string
	Type                         uint16
	RCode                        uint8
	Answered                     bool // The latest question has a response.
	LastRTT, MinRTT              time.Duration
	pending                      [4]dnsPending // The latest queries awaiting a response.
}

type dnsPending struct {
	id uint16
	at time.Time
}

// observe reads one message. Its question is parsed only for a query, or
// while the flow has none, so a busy resolver's responses allocate nothing.
func (s *dnsState) observe(p capture.Packet) {
	msg := p.Payload
	if p.Protocol == 6 { // DNS over TCP: a whole message after its length prefix.
		if len(msg) < 2 || int(binary.BigEndian.Uint16(msg)) != len(msg)-2 {
			return
		}
		msg = msg[2:]
	}
	if len(msg) < 12 {
		return
	}
	response, id := msg[2]&0x80 != 0, binary.BigEndian.Uint16(msg)
	if response {
		s.Responses++
		if s.RCode, s.Answered = msg[3]&0x0f, true; s.RCode != 0 {
			s.Failures++
		}
		for i, query := range s.pending {
			if !query.at.IsZero() && query.id == id {
				if rtt := p.CapturedAt.Sub(query.at); rtt >= 0 {
					s.LastRTT = rtt
					if s.MinRTT == 0 || rtt < s.MinRTT {
						s.MinRTT = rtt
					}
				}
				s.pending[i] = dnsPending{}
			}
		}
	} else {
		s.pending[s.Queries%uint64(len(s.pending))] = dnsPending{id: id, at: p.CapturedAt}
		s.Queries++
		s.Answered = false
	}
	if !response || s.Name == "" {
		if name, qtype, ok := domain.DNSQuestion(msg); ok {
			s.Name, s.Type = name, qtype
		}
	}
}

var (
	dnsTypes  = map[uint16]string{1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR", 15: "MX", 16: "TXT", 28: "AAAA", 33: "SRV", 35: "NAPTR", 43: "DS", 46: "RRSIG", 48: "DNSKEY", 64: "SVCB", 65: "HTTPS", 255: "ANY", 257: "CAA"}
	dnsRCodes = []string{"NOERROR", "FORMERR", "SERVFAIL", "NXDOMAIN", "NOTIMP", "REFUSED"}
)

func (s dnsState) String() string {
	if s.Name == "" {
		return ""
	}
	kind, ok := dnsTypes[s.Type]
	if !ok {
		kind = fmt.Sprintf("TYPE%d", s.Type)
	}
	text := kind + " " + s.Name
	if s.Answered && int(s.RCode) < len(dnsRCodes) {
		text += " " + dnsRCodes[s.RCode]
	} else if s.Answered {
		text += fmt.Sprintf(" RCODE%d", s.RCode)
	}
	if s.Queries > 1 {
		text += fmt.Sprintf(" queries=%d", s.Queries)
	}
	if s.Failures > 0 {
		text += fmt.Sprintf(" failed=%d", s.Failures)
	}
	if s.LastRTT > 0 {
		text += " rtt=" + s.LastRTT.Round(100*time.Microsecond).String()
		if s.MinRTT < s.LastRTT {
			text += " min=" + s.MinRTT.Round(100*time.Microsecond).String()
		}
	}
	return text
}

// sshBanner keeps the identification string each SSH endpoint sends first,
// such as SSH-2.0-OpenSSH_9.6. A client's names the tool behind a login.
func (f *flow) sshBanner(p capture.Packet) {
	side := 1
	if p.Source == f.Initiator {
		side = 0
	}
	if f.SSH != nil && f.SSH[side] != "" || !f.Initiator.IsValid() || !bytes.HasPrefix(p.Payload, []byte("SSH-")) {
		return
	}
	if f.SSH == nil {
		f.SSH = new([2]string)
	}
	line, _, _ := bytes.Cut(p.Payload[:min(len(p.Payload), 255)], []byte("\n")) // RFC 4253 caps it at 255 bytes.
	f.SSH[side] = strings.Map(func(r rune) rune {
		if r < ' ' || r > '~' {
			return -1 // Only printable ASCII reaches the terminal.
		}
		return r
	}, string(line))
}

func sshDescription(banners [2]string) string {
	if banners == ([2]string{}) {
		return ""
	}
	short := func(banner string) string {
		if banner == "" {
			return "-"
		}
		return strings.TrimPrefix(banner, "SSH-2.0-")
	}
	return fmt.Sprintf("client=%s server=%s", short(banners[0]), short(banners[1]))
}

// appDetail describes what a flow's application said about itself beyond
// its destination name: DNS questions and answers, SSH banners, or the alert
// that ended a TLS handshake.
func appDetail(f *flow) string {
	switch f.AppProtocol {
	case "DNS", "mDNS", "LLMNR":
		if f.DNS != nil {
			return f.DNS.String()
		}
	case "SSH":
		if f.SSH != nil {
			return sshDescription(*f.SSH)
		}
	case "TLS":
		if f.WireDomain != nil {
			return f.WireDomain.Evidence().Alert // A failed handshake shows in the list.
		}
	}
	return ""
}
