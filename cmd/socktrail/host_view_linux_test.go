package main

import (
	"net/netip"
	"testing"
	"time"

	"github.com/jimyag/socktrail/internal/domain"
)

func TestHostViewKeepsOneCaptureCopyAndDomainEvidence(t *testing.T) {
	now := time.Now()
	client := netip.MustParseAddrPort("192.0.2.10:51000")
	server := netip.MustParseAddrPort("198.51.100.20:80")
	key := keyFor(client, server, 6)
	id := processID{PID: 123, StartNS: 456}
	defer func(names []string) { captureInterfaces = names }(captureInterfaces)
	captureInterfaces = []string{"br0", "eno1"}
	first := &flow{
		Key: key, SYNSeen: true, SYNSeq: 100, First: now, Last: now.Add(time.Second),
		Initiator: client, Target: server, RX: 80, TX: 120, Packets: 4, Interfaces: interfaceSet{first: 1 << 0},
		Client: participant{PID: id.PID, StartNS: id.StartNS, Name: "curl"},
		IO:     map[processID]ioBytes{id: {RX: 35, TX: 45}},
	}
	second := &flow{
		Key: key, SYNSeen: true, SYNSeq: 100, First: now, Last: now.Add(time.Second),
		Initiator: client, Target: server, RX: 80, TX: 120, Packets: 4, Interfaces: interfaceSet{first: 1 << 1},
		Domain: domain.New(1),
		IO:     map[processID]ioBytes{id: {RX: 35, TX: 45}},
	}
	second.Domain.Add(1, []byte("GET / HTTP/1.1\r\nHost: api.example.test\r\n\r\n"))
	collectors := map[string]*collector{
		"br0":  {flows: map[flowKey]*flow{key: first}, pidIO: map[processID]processIO{id: {Name: "curl", ioBytes: ioBytes{RX: 35, TX: 45}}}},
		"eno1": {flows: map[flowKey]*flow{key: second}},
	}
	host, _, _ := hostCollector([]string{"br0", "eno1"}, collectors)
	flows := host.allFlows()
	if len(flows) != 1 || host.bytes != 200 || flows[0].IO[id] != (ioBytes{RX: 35, TX: 45}) {
		t.Fatalf("host view doubled interface bytes or socket I/O: flows=%+v bytes=%d", flows, host.bytes)
	}
	u := &terminalUI{rates: make(map[*flow]rate)}
	pidRows := u.rows(host, viewPID)
	if len(pidRows) != 1 || pidRows[0].rx != 35 || pidRows[0].tx != 45 || len(pidRows[0].flows) != 1 {
		t.Fatalf("PID view is not global: %+v", pidRows)
	}
	if got := interfaceList(flows[0].Interfaces, 0); got != "br0,eno1" || interfaceList(pidRows[0].ifaces, 2) != got {
		t.Fatalf("the merged flow names the interfaces %q, its row %q", got, interfaceList(pidRows[0].ifaces, 2))
	}
	domainRows := u.rows(host, viewDomain)
	if len(domainRows) != 1 || domainRows[0].label != "HTTP api.example.test" || domainRows[0].reqs != 1 || domainRows[0].rx+domainRows[0].tx != 200 {
		t.Fatalf("Host was lost or duplicated across interfaces: %+v", domainRows)
	}
}

func TestHostViewSeparatesReusedTCPGenerations(t *testing.T) {
	now := time.Now()
	a := netip.MustParseAddrPort("192.0.2.10:51000")
	b := netip.MustParseAddrPort("198.51.100.20:443")
	key := keyFor(a, b, 6)
	one := &flow{Key: key, SYNSeen: true, SYNSeq: 10, First: now, Last: now.Add(time.Second), TX: 40}
	two := &flow{Key: key, SYNSeen: true, SYNSeq: 20, First: now.Add(2 * time.Second), Last: now.Add(3 * time.Second), TX: 50}
	host, _, _ := hostCollector([]string{"br0", "eno1"}, map[string]*collector{
		"br0":  {retired: []*flow{one}},
		"eno1": {retired: []*flow{two}},
	})
	if len(host.allFlows()) != 2 || host.bytes != 90 {
		t.Fatalf("separate TCP generations were merged: flows=%d bytes=%d", len(host.allFlows()), host.bytes)
	}
}

func TestHostViewMergesMidstreamCopyOfKnownHandshake(t *testing.T) {
	now := time.Now()
	a := netip.MustParseAddrPort("192.0.2.10:51000")
	b := netip.MustParseAddrPort("198.51.100.20:443")
	key := keyFor(a, b, 6)
	known := &flow{Key: key, SYNSeen: true, SYNSeq: 10, First: now, Last: now.Add(time.Second), TX: 40}
	midstream := &flow{Key: key, First: now.Add(100 * time.Millisecond), Last: now.Add(time.Second), TX: 40}
	host, _, _ := hostCollector([]string{"br0", "eno1"}, map[string]*collector{
		"br0":  {retired: []*flow{known}},
		"eno1": {retired: []*flow{midstream}},
	})
	if len(host.allFlows()) != 1 || host.bytes != 40 {
		t.Fatalf("midstream capture copy was not merged: flows=%d bytes=%d", len(host.allFlows()), host.bytes)
	}
}

func TestHostViewPreservesLoopbackDirectionWithOneKnownPID(t *testing.T) {
	f := &flow{Direction: "local", Client: participant{PID: 123}, TX: 40}
	merged, _ := mergeObservedFlow([]observedFlow{{flow: f, interfaceName: "lo"}})
	if merged.Direction != "local" {
		t.Fatalf("loopback flow direction = %q", merged.Direction)
	}
}

func TestHostViewRetainsOneCopyAfterFlowExpiry(t *testing.T) {
	a := netip.MustParseAddrPort("192.0.2.10:51000")
	b := netip.MustParseAddrPort("198.51.100.20:80")
	key := keyFor(a, b, 6)
	f1 := &flow{Key: key, RX: 30, TX: 70, Domain: domain.New(1)}
	f1.Domain.Add(1, []byte("GET / HTTP/1.1\r\nHost: expiry.example.test\r\n\r\n"))
	f2 := &flow{Key: key, RX: 30, TX: 70}
	collectors := map[string]*collector{
		"br0":  {flows: map[flowKey]*flow{key: f1}},
		"eno1": {flows: map[flowKey]*flow{key: f2}},
	}
	var state hostViewState
	host, _, members := hostCollector([]string{"br0", "eno1"}, collectors)
	state.update(host, members)
	if host.expiredRX+host.expiredTX != 0 {
		t.Fatal("live bytes were recorded as expired")
	}
	clear(collectors["br0"].flows)
	clear(collectors["eno1"].flows)
	host, _, members = hostCollector([]string{"br0", "eno1"}, collectors)
	state.update(host, members)
	if host.expiredRX != 30 || host.expiredTX != 70 || host.expiredDomainRX != 30 || host.expiredDomainTX != 70 || host.expiredFlows != 1 {
		t.Fatalf("expired host observation was lost or doubled: %+v", host)
	}
}

func TestHostViewKeepsIdentityWhenPreferredInterfaceChanges(t *testing.T) {
	a := netip.MustParseAddrPort("192.0.2.10:51000")
	b := netip.MustParseAddrPort("198.51.100.20:443")
	key := keyFor(a, b, 6)
	first := &flow{Key: key, SYNSeen: true, SYNSeq: 100, TX: 40}
	second := &flow{Key: key, SYNSeen: true, SYNSeq: 100, TX: 80}
	collectors := map[string]*collector{
		"br0":  {flows: map[flowKey]*flow{key: first}},
		"eno1": {flows: make(map[flowKey]*flow)},
	}
	var state hostViewState
	host, _, members := hostCollector([]string{"br0", "eno1"}, collectors)
	state.update(host, members)
	shown := host.allFlows()[0]
	collectors["eno1"].flows[key] = second
	host, _, members = hostCollector([]string{"br0", "eno1"}, collectors)
	state.update(host, members)
	if host.expiredTX != 0 || host.bytes != 80 || host.allFlows()[0] != shown {
		t.Fatalf("switching the preferred capture point expired an active flow: expired=%d current=%d", host.expiredTX, host.bytes)
	}
	clear(collectors["br0"].flows)
	clear(collectors["eno1"].flows)
	host, _, members = hostCollector([]string{"br0", "eno1"}, collectors)
	state.update(host, members)
	if host.expiredTX != 80 || host.expiredFlows != 1 {
		t.Fatalf("flow was not retired once with the latest single-point value: bytes=%d flows=%d", host.expiredTX, host.expiredFlows)
	}
}
