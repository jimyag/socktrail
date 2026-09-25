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

type failureItem struct {
	id   uint64
	flow *flow
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
		// Keep IDs paired with their flows for consumers that select a subset.
		items := make([]failureItem, len(group.IDs))
		for i, id := range group.IDs {
			items[i].id, items[i].flow = id, group.Flows[i]
		}
		slices.SortFunc(items, func(a, b failureItem) int { return cmp.Compare(a.id, b.id) })
		for i, item := range items {
			group.IDs[i], group.Flows[i] = item.id, item.flow
		}
		result = append(result, *group)
	}
	slices.SortFunc(result, func(a, b failureGroup) int {
		return cmp.Or(b.Last.Compare(a.Last), cmp.Compare(a.Reason, b.Reason), cmp.Compare(a.Process.PID, b.Process.PID), a.Target.Compare(b.Target))
	})
	return result
}
