package app

import (
	"net/netip"
	"testing"
	"time"
)

// The reused group map must not keep a connection alive after it is gone, and
// a tuple that disappears must not leave a stale group behind.
func TestObservationGroupsReleaseFinishedFlows(t *testing.T) {
	a := netip.MustParseAddrPort("192.0.2.10:51000")
	b := netip.MustParseAddrPort("198.51.100.20:443")
	key := keyFor(a, b, 6)
	first := &flow{Key: key, First: time.Now(), Last: time.Now()}
	collectors := map[string]*collector{"eno1": {flows: map[flowKey]*flow{key: first}, netns: 1, maxFlows: 20000}}
	names := []string{"eno1"}
	var state hostViewState
	host, _, members := state.collect(names, collectors)
	state.update(host, members)
	if len(state.observationGroups) == 0 {
		t.Fatal("no group was recorded")
	}
	// The connection disappears: its tuple must take no group with it.
	clear(collectors["eno1"].flows)
	host, _, members = state.collect(names, collectors)
	state.update(host, members)
	if len(state.observationGroups) != 0 {
		t.Fatalf("stale groups retained: %d", len(state.observationGroups))
	}
	// A second connection with a different tuple must not inherit the old one.
	c := netip.MustParseAddrPort("192.0.2.30:51001")
	key2 := keyFor(c, b, 6)
	collectors["eno1"].flows[key2] = &flow{Key: key2, First: time.Now(), Last: time.Now()}
	host, _, members = state.collect(names, collectors)
	state.update(host, members)
	if len(state.observationGroups) != 1 {
		t.Fatalf("groups = %d, want 1", len(state.observationGroups))
	}
	for k, group := range state.observationGroups {
		if k.key != key2 || len(group) != 1 || group[0].flow.Key != key2 {
			t.Fatalf("group carried a stale flow: key=%v group=%+v", k.key, group)
		}
	}
}

// Reuse must keep each group's capacity so the steady state stops allocating.
func TestObservationGroupsReuseCapacity(t *testing.T) {
	collectors, names := buildScratchFixture(200)
	var state hostViewState
	host, _, members := state.collect(names, collectors)
	state.update(host, members)
	before := len(state.observationGroups)
	host, _, members = state.collect(names, collectors)
	state.update(host, members)
	if len(state.observationGroups) != before {
		t.Fatalf("group count changed from %d to %d", before, len(state.observationGroups))
	}
}

func buildScratchFixture(n int) (map[string]*collector, []string) {
	c := &collector{flows: make(map[flowKey]*flow, n), roles: make(map[flowKey]roles), roleSeen: make(map[flowKey]time.Time), pidIO: make(map[processID]processIO), netns: 1, maxFlows: 20000}
	now := time.Now()
	for i := range n {
		a := netip.AddrPortFrom(netip.AddrFrom4([4]byte{10, 0, byte(i >> 8), byte(i)}), uint16(1024+i))
		b := netip.AddrPortFrom(netip.AddrFrom4([4]byte{1, 1, byte(i >> 8), byte(i)}), uint16(443))
		key := keyFor(a, b, 6)
		c.flows[key] = &flow{Key: key, First: now, Last: now}
	}
	return map[string]*collector{"eno1": c}, []string{"eno1"}
}
