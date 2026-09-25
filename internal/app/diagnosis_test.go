package app

import (
	"net/netip"
	"strings"
	"syscall"
	"testing"

	"github.com/jimyag/socktrail/internal/probe"
)

func TestDiagnosisUsesStrongestEvidence(t *testing.T) {
	f := &flow{Key: keyFor(netip.MustParseAddrPort("127.0.0.1:40000"), netip.MustParseAddrPort("127.0.0.1:8080"), 6)}
	if got := diagnosis(f); got != "" {
		t.Fatalf("normal connection diagnosis = %q", got)
	}
	f.Health.ConnectResult = int32(syscall.ECONNREFUSED)
	if got := diagnosis(f); !strings.Contains(got, "Connection refused") {
		t.Fatalf("refused diagnosis = %q", got)
	}
	f.Drops = &dropStats{reasons: map[string]uint64{"NO_SOCKET": 3}}
	if got := diagnosis(f); !strings.Contains(got, "No matching local socket for 3 packets") {
		t.Fatalf("no socket diagnosis = %q", got)
	}
	f.Drops.reasons["NETFILTER_DROP"] = 2
	if got := diagnosis(f); !strings.Contains(got, "Netfilter dropped 2 packets") {
		t.Fatalf("firewall diagnosis = %q", got)
	}
	delete(f.Drops.reasons, "NETFILTER_DROP")
	delete(f.Drops.reasons, "NO_SOCKET")
	f.Health.ConnectResult = 0
	f.Health.observeKernel(0, probe.TCPInfo{Metrics: probe.TCPMetrics{SampledNS: 1_000_000_000, Jiffies: 1000, Busy: 100}})
	f.Health.observeKernel(0, probe.TCPInfo{Metrics: probe.TCPMetrics{SampledNS: 2_000_000_000, Jiffies: 2000, Busy: 1000, RwndLimited: 600}})
	if got := diagnosis(f); !strings.Contains(got, "Peer receive window") {
		t.Fatalf("peer window diagnosis = %q", got)
	}
	if row := jsonFlowFor(f, 1, nil, nil); row.Diagnosis != diagnosis(f) {
		t.Fatalf("JSON diagnosis = %q", row.Diagnosis)
	}
}
