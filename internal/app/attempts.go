package app

import (
	"cmp"
	"fmt"
	"maps"
	"net/netip"
	"slices"
	"time"
)

// Inbound connection attempts that got no connection: refused by this host
// with a TCP reset or ICMP unreachable, or never answered. Summed per source
// they show a scan at a glance, and they outlive the flows, which are the
// first to go when a scan fills the table.

const (
	maxAttemptPorts = 1024
	attemptIdle     = 10 * time.Minute
)

type attemptSummary struct {
	Refused, Unanswered uint64
	Ports               map[uint16]struct{} // Up to maxAttemptPorts.
	Last                time.Time
}

func (a *attemptSummary) String() string {
	ports := fmt.Sprint(len(a.Ports), " ports")
	switch {
	case len(a.Ports) >= maxAttemptPorts:
		ports = fmt.Sprint(len(a.Ports), "+ ports")
	case len(a.Ports) == 1:
		ports = "1 port"
	}
	return fmt.Sprintf("tried %s: refused %d, unanswered %d", ports, a.Refused, a.Unanswered)
}

func (a *attemptSummary) add(other *attemptSummary) {
	a.Refused += other.Refused
	a.Unanswered += other.Unanswered
	for port := range other.Ports {
		if len(a.Ports) >= maxAttemptPorts {
			break
		}
		a.Ports[port] = struct{}{}
	}
	if other.Last.After(a.Last) {
		a.Last = other.Last
	}
}

// noteAttempt records that an inbound attempt on f got no connection.
func (c *collector) noteAttempt(f *flow, refused bool, now time.Time) {
	if f.Direction != "inbound" && f.Direction != "first-packet-in" {
		return
	}
	source := f.Initiator.Addr()
	a := c.attempts[source]
	if a == nil {
		if len(c.attempts) >= c.maxFlows {
			return
		}
		if c.attempts == nil {
			c.attempts = make(map[netip.Addr]*attemptSummary)
		}
		a = &attemptSummary{Ports: make(map[uint16]struct{})}
		c.attempts[source] = a
	}
	if refused {
		a.Refused++
	} else {
		a.Unanswered++
	}
	if len(a.Ports) < maxAttemptPorts {
		a.Ports[f.Target.Port()] = struct{}{}
	}
	a.Last = now
}

// disposable reports whether a flow has nothing more to show: a closed TCP
// connection, a TCP attempt the target never answered, or a lone one-way
// UDP datagram, as scans and floods leave behind.
func disposable(f *flow) bool {
	switch f.Key.Protocol {
	case 6:
		return f.Closed || f.TCPState == "syn" && !f.SynAck
	case 17:
		return f.Packets <= 2 && (f.RX == 0 || f.TX == 0)
	}
	return false
}

// evict frees a tenth of a full flow table, oldest first, among disposable
// flows. One sweep makes room for many new flows, so a flood costs one sort
// per few thousand of them.
func (c *collector) evict(now time.Time) {
	var candidates []*flow
	for _, f := range c.flows {
		if disposable(f) {
			candidates = append(candidates, f)
		}
	}
	slices.SortFunc(candidates, func(a, b *flow) int { return a.Last.Compare(b.Last) })
	for _, f := range candidates[:min(len(candidates), c.maxFlows/10+1)] {
		c.expireFlow(f, now)
		delete(c.flows, f.Key)
	}
}

// expireFlow keeps a removed flow's bytes in the expired totals.
func (c *collector) expireFlow(f *flow, now time.Time) {
	c.expiredFlows++
	c.expiredRX += f.RX
	c.expiredTX += f.TX
	if f.Domain != nil && f.Domain.Evidence().Listed() {
		c.expiredDomainRX += f.RX
		c.expiredDomainTX += f.TX
	}
	if f.Key.Protocol == 6 && f.TCPState == "syn" && !f.SynAck {
		c.noteAttempt(f, false, now)
	}
}

// attemptSources lists the sources with attempts, most ports first.
func attemptSources(attempts map[netip.Addr]*attemptSummary) []netip.Addr {
	return slices.SortedFunc(maps.Keys(attempts), func(a, b netip.Addr) int {
		return cmp.Or(cmp.Compare(len(attempts[b].Ports), len(attempts[a].Ports)), a.Compare(b))
	})
}
