package app

import (
	"net/netip"
	"syscall"
	"testing"
	"time"

	"github.com/jimyag/socktrail/internal/probe"
)

func TestConnectResultCreatesFailedFlowAndHistory(t *testing.T) {
	local := netip.MustParseAddrPort("127.0.0.1:40000")
	remote := netip.MustParseAddrPort("127.0.0.1:443")
	e := probe.Event{
		Protocol: 6, Role: "out", Operation: "connect_result", Local: local, Remote: remote,
		PID: 123, StartNS: 1, Process: "curl", Result: int32(syscall.ECONNREFUSED), ConnectLatency: 300,
	}
	c := newTestCollector()
	c.loopback = true
	c.roles, c.roleSeen = make(map[flowKey]roles), make(map[flowKey]time.Time)
	c.event(e)
	f := c.flows[keyFor(local, remote, 6)]
	if f == nil || f.End != flowFailed || f.Client.PID != 123 || f.Health.ConnectLatency != 300 || f.Packets != 0 || flowState(f) != "syn, refused" {
		t.Fatalf("failed probe-only connection: %+v", f)
	}
	row := jsonFlowFor(f, 1, newProcessTable(t.TempDir()), nil)
	if row.ConnectResult != "refused" || row.ConnectLatencyUS != 300 || row.End != "failed" {
		t.Fatalf("failed connection JSON: %+v", row)
	}
	f.TCPState = "reset" // The packet path can see RST before the probe result.
	if got := flowState(f); got != "syn, refused" {
		t.Fatalf("failed connection state = %q", got)
	}
	host, _, members := hostCollector([]string{"lo"}, map[string]*collector{"lo": c})
	var state hostViewState
	state.updateAt(host, members, time.Now())
	if len(state.history) != 1 || len(state.lastChanges) != 1 {
		t.Fatalf("failure history=%d changes=%d", len(state.history), len(state.lastChanges))
	}
	host, _, members = hostCollector([]string{"lo"}, map[string]*collector{"lo": c})
	state.updateAt(host, members, time.Now().Add(time.Second))
	if len(state.history) != 1 {
		t.Fatalf("duplicate failure history: %d", len(state.history))
	}
	other := newTestCollector()
	other.interfaceIndex = 1
	other.roles, other.roleSeen = make(map[flowKey]roles), make(map[flowKey]time.Time)
	other.event(e)
	if len(other.flows) != 0 {
		t.Fatal("non-base collector created probe-only flow")
	}
}

func TestFailureGroupsCountUniqueConnections(t *testing.T) {
	now := time.Now()
	target := netip.MustParseAddrPort("127.0.0.1:443")
	state := &hostViewState{displayed: make(map[uint64]*flow)}
	for _, item := range []struct {
		id     uint64
		offset time.Duration
	}{{1, time.Second}, {2, 2 * time.Second}, {3, 3 * time.Second}} {
		f := &flow{Client: participant{PID: 123, StartNS: 1, Name: "curl"}, Target: target, Last: now.Add(item.offset)}
		f.Health.ConnectResult = int32(syscall.ECONNREFUSED)
		state.displayed[item.id] = f
	}
	state.history, state.historyIDs = []*flow{state.displayed[1]}, []uint64{1}
	groups := state.failureGroups(nil, nil)
	if len(groups) != 1 || len(groups[0].IDs) != 3 || groups[0].Reason != "refused" || groups[0].First != state.displayed[1].Last || groups[0].Last != state.displayed[3].Last {
		t.Fatalf("failure groups: %+v", groups)
	}
}
