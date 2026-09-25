package app

import (
	"net/netip"
	"testing"

	"github.com/jimyag/socktrail/internal/dropprobe"
)

func TestDropAttributionKeepsUnrelatedTrafficGlobal(t *testing.T) {
	c := newTestCollector()
	c.roles = make(map[flowKey]roles)
	sample := dropprobe.Sample{Source: netip.MustParseAddrPort("127.0.0.1:40000"), Target: netip.MustParseAddrPort("127.0.0.1:8080"), Protocol: 6, Reason: "NETFILTER_DROP", Count: 2}
	key := keyFor(sample.Source, sample.Target, 6)
	c.recordDrop(sample, true)
	if c.flows[key] != nil {
		t.Fatal("unowned drop created a flow")
	}
	c.roles[key] = roles{}
	c.recordDrop(sample, true)
	if got := c.flows[key].Drops.reasons[sample.Reason]; got != 2 {
		t.Fatalf("owned flow drop count = %d", got)
	}
	c.recordDrop(sample, false)
	if got := c.flows[key].Drops.reasons[sample.Reason]; got != 4 {
		t.Fatalf("existing flow drop count = %d", got)
	}
}
