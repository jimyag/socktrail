package app

import (
	"cmp"
	"net/netip"
	"slices"
	"time"
)

type failureGroup struct {
	Reason      string
	Process     participant
	Target      netip.AddrPort
	First, Last time.Time
	IDs         []uint64
	Flows       []*flow
}

func (s *hostViewState) failureGroups(scope *processScope, host *collector) []failureGroup {
	type key struct {
		reason  string
		process processID
		target  netip.AddrPort
	}
	groups := make(map[key]*failureGroup)
	seen := make(map[uint64]bool)
	add := func(id uint64, f *flow) {
		if seen[id] || f.Health.ConnectResult == 0 || scope != nil && !scope.flow(f, host) {
			return
		}
		seen[id] = true
		reason := connectResultName(f.Health.ConnectResult)
		k := key{reason, f.Client.id(), f.Target}
		group := groups[k]
		if group == nil {
			group = &failureGroup{Reason: reason, Process: f.Client, Target: f.Target, First: f.Last}
			groups[k] = group
		}
		group.IDs = append(group.IDs, id)
		group.Flows = append(group.Flows, f)
		if f.Last.Before(group.First) {
			group.First = f.Last
		}
		if f.Last.After(group.Last) {
			group.Last = f.Last
		}
	}
	for id, f := range s.displayed {
		add(id, f)
	}
	for i, f := range s.history {
		add(s.historyIDs[i], f)
	}
	result := make([]failureGroup, 0, len(groups))
	for _, group := range groups {
		slices.Sort(group.IDs)
		result = append(result, *group)
	}
	slices.SortFunc(result, func(a, b failureGroup) int {
		return cmp.Or(b.Last.Compare(a.Last), cmp.Compare(a.Reason, b.Reason), cmp.Compare(a.Process.PID, b.Process.PID), a.Target.Compare(b.Target))
	})
	return result
}
