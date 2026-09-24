package main

import (
	"net/netip"
	"slices"
	"time"

	"github.com/jimyag/socktrail/internal/probe"
)

type observedFlow struct {
	flow          *flow
	interfaceName string
}

type hostFlowTotal struct {
	ioBytes
	domain bool
}

type hostViewState struct {
	nextID        uint64
	flowIDs       map[*flow]uint64
	active        map[uint64]hostFlowTotal
	displayed     map[uint64]*flow
	expired       ioBytes
	expiredDomain ioBytes
	expiredFlows  uint64
}

// update retains single-point totals when the corresponding interface flow
// detail expires. Member pointers keep the identity stable if another
// interface later becomes the preferred observation for the same flow.
func (s *hostViewState) update(host *collector, members map[*flow][]*flow) map[*flow]*flow {
	if s.flowIDs == nil {
		s.flowIDs = make(map[*flow]uint64)
	}
	newIDs := make(map[*flow]uint64)
	newActive := make(map[uint64]hostFlowTotal)
	newDisplayed := make(map[uint64]*flow)
	replacements := make(map[*flow]*flow)
	absorbed := make(map[uint64]bool)
	for index, merged := range host.retired {
		observations := members[merged]
		var id uint64
		for _, observation := range observations {
			if previous := s.flowIDs[observation]; previous != 0 {
				absorbed[previous] = true
				if id == 0 {
					id = previous
				}
			}
		}
		_, alreadyUsed := newActive[id]
		if id == 0 || alreadyUsed {
			s.nextID++
			id = s.nextID
		}
		for _, observation := range observations {
			newIDs[observation] = id
		}
		listed := merged.Domain != nil && merged.Domain.Evidence().Listed()
		newActive[id] = hostFlowTotal{ioBytes: ioBytes{RX: merged.RX, TX: merged.TX}, domain: listed}
		shown := s.displayed[id]
		if shown == nil {
			shown = merged
		} else {
			*shown = *merged
		}
		newDisplayed[id] = shown
		replacements[merged] = shown
		host.retired[index] = shown
	}
	for id, old := range s.active {
		if _, active := newActive[id]; active || absorbed[id] {
			continue
		}
		s.expired.RX += old.RX
		s.expired.TX += old.TX
		s.expiredFlows++
		if old.domain {
			s.expiredDomain.RX += old.RX
			s.expiredDomain.TX += old.TX
		}
	}
	s.flowIDs, s.active, s.displayed = newIDs, newActive, newDisplayed
	host.expiredRX, host.expiredTX = s.expired.RX, s.expired.TX
	host.expiredDomainRX, host.expiredDomainTX = s.expiredDomain.RX, s.expiredDomain.TX
	host.expiredFlows = s.expiredFlows
	return replacements
}

// hostCollector builds a logical connection view from interface observations.
// IP bytes come from one capture point per connection; interface counters are
// never added together. PID socket I/O is copied once from the global probe.
func hostCollector(names []string, collectors map[string]*collector) (*collector, map[*flow]*flow, map[*flow][]*flow) {
	host := &collector{flows: make(map[flowKey]*flow)}
	sources := make(map[*flow]*flow)
	members := make(map[*flow][]*flow)
	if len(names) == 0 {
		return host, sources, members
	}
	base := collectors[names[0]]
	if base == nil {
		return host, sources, members
	}
	host.dns = base.dns
	host.pidIO = base.pidIO
	host.pidSeen = base.pidSeen
	host.expiredPIDIO = base.expiredPIDIO
	host.ioUnindexed = base.ioUnindexed
	host.ioUnmatched = base.ioUnmatched
	byKey := make(map[flowKey][]observedFlow)
	for _, name := range names {
		c := collectors[name]
		if c == nil {
			continue
		}
		host.kernelDropped += c.kernelDropped
		host.kernelReceived += c.kernelReceived
		host.truncated += c.truncated
		host.droppedFlow += c.droppedFlow
		host.droppedRole += c.droppedRole
		for source, a := range c.attempts {
			if host.attempts == nil {
				host.attempts = make(map[netip.Addr]*attemptSummary)
			}
			if host.attempts[source] == nil {
				host.attempts[source] = &attemptSummary{Ports: make(map[uint16]struct{})}
			}
			host.attempts[source].add(a)
		}
		for _, f := range c.allFlows() {
			key := f.Key
			if f.NAT != nil {
				key = f.NAT.orig // A gateway's LAN and WAN tuples are one connection.
			}
			byKey[key] = append(byKey[key], observedFlow{flow: f, interfaceName: name})
		}
	}
	for _, candidates := range byKey {
		groups := groupObservations(candidates)
		for _, group := range groups {
			merged, source := mergeObservedFlow(group)
			host.retired = append(host.retired, merged)
			sources[merged] = source
			for _, observation := range group {
				members[merged] = append(members[merged], observation.flow)
			}
			host.rxBytes += merged.RX
			host.txBytes += merged.TX
			host.bytes += merged.RX + merged.TX
			host.packets += merged.Packets
		}
	}
	return host, sources, members
}

func groupObservations(candidates []observedFlow) [][]observedFlow {
	slices.SortFunc(candidates, func(a, b observedFlow) int {
		return a.flow.First.Compare(b.flow.First)
	})
	var groups [][]observedFlow
	bySYN := make(map[uint32][]int)
	var midstream []int
	for _, candidate := range candidates {
		matched := -1
		if candidate.flow.SYNSeen {
			for _, i := range bySYN[candidate.flow.SYNSeq] {
				if sameObservedConnection(candidate, groups[i]) {
					matched = i
					break
				}
			}
			if matched < 0 {
				for _, i := range midstream {
					if sameObservedConnection(candidate, groups[i]) {
						matched = i
						bySYN[candidate.flow.SYNSeq] = append(bySYN[candidate.flow.SYNSeq], i)
						break
					}
				}
			}
		} else {
			for i, group := range groups {
				if sameObservedConnection(candidate, group) {
					matched = i
					break
				}
			}
		}
		if matched < 0 {
			index := len(groups)
			groups = append(groups, []observedFlow{candidate})
			if candidate.flow.SYNSeen {
				bySYN[candidate.flow.SYNSeq] = append(bySYN[candidate.flow.SYNSeq], index)
			} else {
				midstream = append(midstream, index)
			}
		} else {
			groups[matched] = append(groups[matched], candidate)
		}
	}
	return groups
}

func sameObservedConnection(candidate observedFlow, group []observedFlow) bool {
	for _, other := range group {
		if other.interfaceName == candidate.interfaceName {
			return false // A reused tuple on one interface is another generation.
		}
		if candidate.flow.SYNSeen && other.flow.SYNSeen && candidate.flow.SYNSeq != other.flow.SYNSeq {
			return false
		}
		if !candidate.flow.First.IsZero() && !other.flow.Last.IsZero() && candidate.flow.First.After(other.flow.Last.Add(2*time.Second)) {
			return false
		}
		if !other.flow.First.IsZero() && !candidate.flow.Last.IsZero() && other.flow.First.After(candidate.flow.Last.Add(2*time.Second)) {
			return false
		}
	}
	return true
}

// domainEvidenceScore ranks interface observations of one connection in the
// same order as chooseDomain: a name parsed from the client's bytes beats a
// process SNI, which beats a DNS hint, which beats evidence without a name.
// Without this order the merged view showed whichever copy arrived first.
func domainEvidenceScore(f *flow) uint64 {
	if f.Domain == nil {
		return 0
	}
	evidence := f.Domain.Evidence()
	switch {
	case !evidence.Listed():
		return 0
	case !evidence.Named():
		return 1
	case evidence.Kind == "dns":
		return 2
	case evidence.Kind == "openssl":
		return 3
	}
	var requests uint64
	for _, count := range evidence.Hosts {
		requests += count
	}
	return 4 + requests
}

// crossed reports a flow seen entering the host on one interface and
// leaving on another: the host routed it, as a NAT gateway does.
func crossed(a, b string) bool {
	in := func(d string) bool { return d == "inbound" || d == "first-packet-in" }
	out := func(d string) bool { return d == "outbound" || d == "first-packet-out" }
	return in(a) && out(b) || out(a) && in(b)
}

func mergeObservedFlow(group []observedFlow) (*flow, *flow) {
	packetSource := group[0].flow
	evidenceSource := packetSource
	for _, candidate := range group[1:] {
		f := candidate.flow
		if f.RX+f.TX > packetSource.RX+packetSource.TX {
			packetSource = f
		}
		if domainEvidenceScore(f) > domainEvidenceScore(evidenceSource) {
			evidenceSource = f
		}
	}
	merged := *packetSource
	// Rebuilt below from every observation, packetSource's too; the view is
	// rebuilt each second, so maps come only with an entry.
	merged.IO, merged.TLSActors = nil, nil
	merged.Domain = evidenceSource.Domain
	// The observation that supplied the name also parsed the application protocol.
	if merged.AppProtocol == "" || evidenceSource.AppProtocol != "" && domainEvidenceScore(evidenceSource) > 0 {
		merged.AppProtocol, merged.AppSource = evidenceSource.AppProtocol, evidenceSource.AppSource
	}
	for _, candidate := range group {
		if merged.AppProtocol == "" && candidate.flow.AppProtocol != "" {
			merged.AppProtocol, merged.AppSource = candidate.flow.AppProtocol, candidate.flow.AppSource
		}
	}
	merged.First, merged.Last = time.Time{}, time.Time{}
	var direction string
	for _, candidate := range group {
		f := candidate.flow
		for id, actor := range f.TLSActors {
			if merged.TLSActors == nil {
				merged.TLSActors = make(map[processID]participant)
			}
			merged.TLSActors[id] = actor
		}
		merged.DomainConflict = merged.DomainConflict || f.DomainConflict
		merged.Preexisting = merged.Preexisting || f.Preexisting
		merged.Interfaces |= f.Interfaces
		if merged.Health.SynRTT == 0 && f.Health.SynRTT > 0 {
			merged.Health.SynRTT = f.Health.SynRTT
		}
		merged.Health.Retransmits = max(merged.Health.Retransmits, f.Health.Retransmits)
		for side, info := range f.Health.Kernel {
			if info != (probe.TCPInfo{}) {
				merged.Health.observeKernel(side, info)
			}
		}
		if !f.First.IsZero() && (merged.First.IsZero() || f.First.Before(merged.First)) {
			merged.First = f.First
		}
		if f.Last.After(merged.Last) {
			merged.Last = f.Last
		}
		if !merged.Initiator.IsValid() && f.Initiator.IsValid() {
			merged.Initiator, merged.Target = f.Initiator, f.Target
		}
		if f.Client.PID > 0 {
			merged.Client = mergeParticipant(merged.Client, f.Client)
		}
		if f.Server.PID > 0 {
			merged.Server = mergeParticipant(merged.Server, f.Server)
		}
		for id, io := range f.IO {
			if merged.IO == nil {
				merged.IO = make(map[processID]ioBytes)
			}
			old := merged.IO[id]
			merged.IO[id] = ioBytes{RX: max(old.RX, io.RX), TX: max(old.TX, io.TX)}
		}
		if f.Direction != "" && f.Direction != "unknown" {
			switch {
			case direction == "" || direction == f.Direction:
				direction = f.Direction
			case crossed(direction, f.Direction):
				direction = "forwarded"
			case direction != "forwarded":
				direction = "unknown"
			}
		}
	}
	if evidenceSource.Initiator.IsValid() {
		merged.Initiator, merged.Target = evidenceSource.Initiator, evidenceSource.Target
	}
	switch {
	case direction == "local":
		merged.Direction = "local"
	case merged.Client.PID > 0 && merged.Server.PID > 0:
		merged.Direction = "local"
	case merged.Client.PID > 0:
		merged.Direction = "outbound"
	case merged.Server.PID > 0:
		merged.Direction = "inbound"
	case direction != "":
		merged.Direction = direction
	default:
		merged.Direction = "unknown"
	}
	return &merged, packetSource
}
