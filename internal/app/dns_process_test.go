package app

import (
	"net/netip"
	"testing"
	"time"

	"github.com/jimyag/socktrail/internal/domain"
)

func TestProcessDNSAssociationAndExpiry(t *testing.T) {
	now := time.Now()
	target := netip.MustParseAddrPort("198.51.100.7:443")
	resolver := netip.MustParseAddrPort("127.0.0.53:53")
	queryClient := netip.MustParseAddrPort("127.0.0.1:40000")
	query := &flow{
		Key: keyFor(queryClient, resolver, 17), Client: participant{PID: 10, StartNS: 1},
		DNS: &dnsState{Queries: 1, recent: []dnsQueryRecord{{
			name: "a.example.test", kind: 1, at: now, answered: true, sequence: 1,
			addresses: []domain.DNSAnswer{{Address: target.Addr(), TTL: time.Minute}},
		}}},
	}
	clientA := netip.MustParseAddrPort("192.0.2.10:40001")
	clientB := netip.MustParseAddrPort("192.0.2.10:40002")
	wire := domain.New(1)
	wire.Add(1, testClientHello("public.example.test", true))
	a := &flow{Key: keyFor(clientA, target, 6), Client: participant{PID: 10, StartNS: 1}, Initiator: clientA, Target: target, Direction: "outbound", First: now.Add(time.Second), WireDomain: wire, WireClient: clientA}
	b := &flow{Key: keyFor(clientB, target, 6), Client: participant{PID: 11, StartNS: 1}, Initiator: clientB, Target: target, Direction: "outbound", First: now.Add(time.Second)}
	host := &collector{flows: map[flowKey]*flow{query.Key: query, a.Key: a, b.Key: b}}
	correlateProcessDNS(host, nil, nil, nil, now.Add(2*time.Second))
	if e := a.Domain.Evidence(); e.Kind != "dns_process" || e.DNS != "a.example.test" || !e.ECH || e.SNI != "public.example.test" {
		t.Fatalf("process DNS and ECH: %+v", e)
	}
	if b.Domain != nil {
		t.Fatalf("borrowed another process's DNS answer: %+v", b.Domain.Evidence())
	}
	correlateProcessDNS(host, nil, nil, nil, now.Add(61*time.Second))
	if a.Domain != wire {
		t.Fatalf("expired process DNS hint was retained: %+v", a.Domain.Evidence())
	}
}

func BenchmarkProcessDNSNoQueries(b *testing.B) {
	target := netip.MustParseAddrPort("198.51.100.7:443")
	host := &collector{flows: make(map[flowKey]*flow, 10000)}
	for i := range 10000 {
		client := netip.AddrPortFrom(netip.AddrFrom4([4]byte{10, 0, byte(i >> 8), byte(i)}), 40000)
		f := &flow{Key: keyFor(client, target, 6), Client: participant{PID: 10, StartNS: 1}, Target: target, Direction: "outbound"}
		host.flows[f.Key] = f
	}
	now := time.Now()
	b.ReportAllocs()
	for b.Loop() {
		correlateProcessDNS(host, nil, nil, nil, now)
	}
}
