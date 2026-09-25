package app

import (
	"hash/maphash"
	"time"
)

var flowNameSeed = maphash.MakeSeed()

type flowChange struct {
	ID      uint64
	Flow    *flow
	Changes []string
	At      time.Time
}

type flowChangeKey struct {
	group, name    string
	tcp, icmp      string
	hosts, actors  uint64
	client, server processID
	end            flowEnd
	connectResult  int32
	connectLatency uint32
	drops          uint64
}

type pendingFlowName struct {
	group, name string
	hosts       uint64
	since       time.Time
}

func changeKey(f *flow) flowChangeKey {
	k := flowChangeKey{
		tcp: f.TCPState, icmp: f.ICMPError, client: f.Client.id(), server: f.Server.id(), end: f.End,
		connectResult: f.Health.ConnectResult, connectLatency: f.Health.ConnectLatency,
	}
	if f.Domain != nil {
		e := f.Domain.Evidence()
		k.group, k.name = e.Group(), e.Label()
		for host := range e.Hosts {
			k.hosts ^= maphash.String(flowNameSeed, host)
		}
	}
	for id := range f.IO {
		//nolint:gosec // G115: socket I/O map keys are positive kernel PIDs.
		k.actors ^= uint64(id.PID)*0x9e3779b97f4a7c15 ^ id.StartNS*0xbf58476d1ce4e5b9
	}
	if f.Drops != nil {
		for _, count := range f.Drops.reasons {
			k.drops += count
		}
	}
	return k
}

func (s *hostViewState) detectChanges(current, previous map[uint64]*flow, now time.Time) []flowChange {
	if s.changeKeys == nil {
		s.changeKeys = make(map[uint64]flowChangeKey)
		s.firstObserved = make(map[uint64]time.Time)
		s.pendingNames = make(map[uint64]pendingFlowName)
	}
	var changes []flowChange
	for id, f := range current {
		key := changeKey(f)
		old, emitted := s.changeKeys[id]
		if !emitted {
			seen, tracked := s.firstObserved[id]
			if !tracked {
				seen = now
				s.firstObserved[id] = now
			}
			if now.Sub(seen) < lateEventWindow && f.End == flowOngoing {
				continue
			}
			delete(s.firstObserved, id)
			s.changeKeys[id] = key
			fields := []string{"new"}
			if f.End != flowOngoing {
				fields = append(fields, "end")
			}
			changes = append(changes, flowChange{ID: id, Flow: f, Changes: fields, At: now})
			continue
		}
		var fields []string
		if key.tcp != old.tcp || key.icmp != old.icmp || key.connectResult != old.connectResult || key.connectLatency != old.connectLatency {
			fields = append(fields, "state")
			old.tcp, old.icmp = key.tcp, key.icmp
			old.connectResult, old.connectLatency = key.connectResult, key.connectLatency
		}
		if key.client != old.client || key.server != old.server || key.actors != old.actors {
			fields = append(fields, "process")
			old.client, old.server, old.actors = key.client, key.server, key.actors
		}
		if key.end != old.end {
			fields = append(fields, "end")
			old.end = key.end
		}
		if key.drops != old.drops {
			fields = append(fields, "drops")
			old.drops = key.drops
		}
		if key.group != old.group || key.name != old.name || key.hosts != old.hosts {
			pending := s.pendingNames[id]
			if pending.group != key.group || pending.name != key.name || pending.hosts != key.hosts {
				s.pendingNames[id] = pendingFlowName{key.group, key.name, key.hosts, now}
			} else if now.Sub(pending.since) >= lateEventWindow {
				fields = append(fields, "name")
				old.group, old.name, old.hosts = key.group, key.name, key.hosts
				delete(s.pendingNames, id)
			}
		} else {
			delete(s.pendingNames, id)
		}
		s.changeKeys[id] = old
		if len(fields) > 0 {
			changes = append(changes, flowChange{ID: id, Flow: f, Changes: fields, At: now})
		}
	}
	for id, f := range previous {
		if current[id] != nil {
			continue
		}
		old, emitted := s.changeKeys[id]
		if !emitted {
			changes = append(changes, flowChange{ID: id, Flow: f, Changes: []string{"new", "end"}, At: now})
		} else if old.end == flowOngoing {
			changes = append(changes, flowChange{ID: id, Flow: f, Changes: []string{"end"}, At: now})
		}
		delete(s.changeKeys, id)
		delete(s.firstObserved, id)
		delete(s.pendingNames, id)
	}
	return changes
}
