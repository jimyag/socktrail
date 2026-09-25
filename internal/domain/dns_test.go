package domain

import (
	"encoding/binary"
	"net/netip"
	"slices"
	"strings"
	"testing"
	"time"
)

func dnsName(name string) []byte {
	var b []byte
	for label := range strings.SplitSeq(name, ".") {
		b = append(append(b, byte(len(label))), label...)
	}
	return append(b, 0)
}

// dnsResponse answers name with a CNAME to cdn.example.net and an A record.
func dnsResponse(name string, addr netip.Addr) []byte {
	msg := []byte{0x12, 0x34, 0x81, 0x80, 0, 1, 0, 2, 0, 0, 0, 0}
	msg = append(msg, dnsName(name)...)
	msg = append(msg, 0, 1, 0, 1) // A, IN.
	target := dnsName("cdn.example.net")
	msg = append(msg, 0xc0, 12, 0, 5, 0, 1, 0, 0, 0, 60)
	msg = binary.BigEndian.AppendUint16(msg, uint16(len(target)))
	msg = append(msg, target...)
	msg = append(msg, target...)
	msg = append(msg, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4)
	return append(msg, addr.AsSlice()...)
}

func TestDNSAnswersFollowCNAMEToQuestionName(t *testing.T) {
	addr := netip.MustParseAddr("198.51.100.7")
	name, addrs := DNSAnswers(dnsResponse("WWW.Example.Test", addr))
	if name != "www.example.test" || !slices.Equal(addrs, []netip.Addr{addr}) {
		t.Fatalf("name=%q addrs=%v", name, addrs)
	}
	if _, records := DNSAnswerRecords(dnsResponse("www.example.test", addr)); len(records) != 1 || records[0].Address != addr || records[0].TTL != time.Minute {
		t.Fatalf("answer records with TTL: %v", records)
	}
	query := dnsResponse("www.example.test", addr)
	query[2] &^= 0x80
	nxdomain := dnsResponse("www.example.test", addr)
	nxdomain[3] |= 3
	for _, msg := range [][]byte{query, nxdomain, dnsResponse("www.example.test", addr)[:40]} {
		if name, addrs := DNSAnswers(msg); len(addrs) != 0 {
			t.Fatalf("non-answer produced a hint: %q %v", name, addrs)
		}
	}
}

func TestDNSCacheMatchesAnswerBeforeConnection(t *testing.T) {
	addr := netip.MustParseAddr("198.51.100.7")
	t0 := time.Now()
	var c DNSCache
	c.Observe(dnsResponse("first.example.test", addr), t0)
	c.Observe(dnsResponse("second.example.test", addr), t0.Add(5*time.Second))
	for _, tc := range []struct {
		at         time.Time
		allowLater bool
		want       string
	}{
		{t0.Add(2 * time.Second), false, "first.example.test"},
		{t0.Add(10 * time.Second), false, "second.example.test"},
		{t0.Add(-500 * time.Millisecond), false, "first.example.test"}, // Answer delivered just after the SYN.
		{t0.Add(-time.Minute), false, ""},                              // A new connection cannot use a later answer.
		{t0.Add(-time.Minute), true, "first.example.test"},             // A pre-existing one takes its re-resolution.
	} {
		if got := c.Lookup(addr, tc.at, tc.allowLater); got != tc.want {
			t.Fatalf("Lookup(at %v, later=%t) = %q, want %q", tc.at.Sub(t0), tc.allowLater, got, tc.want)
		}
	}
	if names := c.Names(addr); !slices.Equal(names, []string{"first.example.test", "second.example.test"}) {
		t.Fatalf("names for shared address: %v", names)
	}
	c.Expire(t0.Add(5*time.Second + dnsHintAge + time.Second))
	if names := c.Names(addr); len(names) != 0 {
		t.Fatalf("expired answers kept: %v", names)
	}
}
