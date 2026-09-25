package app

import (
	"net/netip"
	"testing"

	"github.com/jimyag/socktrail/internal/domain"
)

func TestStructuredFilter(t *testing.T) {
	c := newTestCollector()
	f := &flow{
		Key:       flowKey{A: netip.MustParseAddrPort("10.0.0.2:53111"), B: netip.MustParseAddrPort("203.0.113.8:443"), Protocol: 6},
		Initiator: netip.MustParseAddrPort("10.0.0.2:53111"), Target: netip.MustParseAddrPort("203.0.113.8:443"),
		Direction: "outbound", AppProtocol: "https", TCPState: "established", Client: participant{PID: 123, Name: "curl"},
	}
	f.Domain = domain.New(0)
	f.Domain.Add(0, []byte("GET / HTTP/1.1\r\nHost: example.org\r\n\r\n"))
	previousInterfaces := captureInterfaces
	captureInterfaces = []string{"eth0"}
	t.Cleanup(func() { captureInterfaces = previousInterfaces })
	f.Interfaces.add(0)
	processes := newProcessTable(t.TempDir())
	processes.procs[processID{PID: 123}] = &processMeta{Name: "curl", UID: 1000, UIDChecked: true}
	processes.userNames[1000] = "alice"
	for _, tc := range []struct {
		query string
		want  bool
	}{
		{"port:443 sport:53111 dport:443", true},
		{"port:80", false},
		{"ip:10.0.0.0/8 ip:203.0.113.8", true},
		{"ip:192.0.2.0/24", false},
		{"proto:tcp app:https state:established dir:outbound", true},
		{"proc:curl pid:123", true},
		{"iface:eth* host:example.org", true},
		{"svc:unknown", true},
		{"user:alice user:1000 user:al*", true},
		{"user:root", false},
		{"ja4:t13*", false},
		{"asn:64500 cc:US", false},
		{"proc:wget", false},
		{"!port:80 !dir:inbound", true},
		{"!port:443", false},
		{"fail:false", true},
		{"fail:true", false},
		{"curl port:443", true},
		{"curl port:80", false},
	} {
		t.Run(tc.query, func(t *testing.T) {
			conditions, err := parseFilter(tc.query)
			if err != nil {
				t.Fatal(err)
			}
			if got := matchesFilter(conditions, f, c, processes, nil, ""); got != tc.want {
				t.Fatalf("got %v, want %v", got, tc.want)
			}
		})
	}
	body := append(append([]byte{3, 3}, make([]byte, 32)...), 0, 0, 2, 0x13, 1, 1, 0) // TLS 1.2, one cipher, no extensions.
	quic, err := domain.NewQUICClientHello(append([]byte{1, 0, 0, byte(len(body))}, body...))
	if err != nil {
		t.Fatal(err)
	}
	f.Domain = quic
	for query, want := range map[string]bool{"ja4:q12i010000_*": true, "ja4:t12*": false, "!ja4:q*": false} {
		conditions, err := parseFilter(query)
		if err != nil {
			t.Fatal(err)
		}
		if got := matchesFilter(conditions, f, c, processes, nil, ""); got != want {
			t.Errorf("%s: got %v, want %v", query, got, want)
		}
	}
	for _, query := range []string{"foo:bar", "ip:bad", "port:abc", "proc:[", "!", "fail:maybe"} {
		if _, err := parseFilter(query); err == nil {
			t.Errorf("%q accepted", query)
		}
	}
}

func TestStructuredFilterRowsAndSnapshot(t *testing.T) {
	c := newTestCollector()
	server := netip.MustParseAddrPort("203.0.113.8:443")
	for _, tc := range []struct {
		client string
		name   string
	}{
		{"10.0.0.2:53111", "curl"},
		{"10.0.0.3:53112", "wget"},
	} {
		client := netip.MustParseAddrPort(tc.client)
		key := flowKey{A: client, B: server, Protocol: 6}
		c.flows[key] = &flow{Key: key, Initiator: client, Target: server, Client: participant{PID: 123, Name: tc.name}}
	}
	u := &terminalUI{filter: "port:443 proc:curl"}
	rows := u.rows(c, viewTarget)
	if len(rows) != 1 || len(rows[0].flows) != 1 || rows[0].flows[0].Client.Name != "curl" {
		t.Fatalf("filtered rows: %+v", rows)
	}
	conditions, err := parseFilter(u.filter)
	if err != nil {
		t.Fatal(err)
	}
	report := reportJSON(c, "test", 10, u.processes, nil, nil, nil, conditions)
	if len(report.Flows) != 1 || report.Flows[0].Client.Name != "curl" {
		t.Fatalf("filtered JSON flows: %+v", report.Flows)
	}
	u.filter = "port:bogus"
	_ = u.rows(c, viewTarget)
	if u.filterError == "" || u.filter != "port:bogus" {
		t.Fatalf("invalid filter must remain editable: %q, %q", u.filter, u.filterError)
	}
}
