package app

import (
	"net/netip"
	"time"

	"github.com/jimyag/socktrail/internal/domain"
)

type processDNSHint struct {
	name    string
	at      time.Time
	expires time.Time
}

// correlateProcessDNS uses only the current merged connections and bounded
// history. The index is rebuilt each tick, so it cannot outlive its evidence.
func correlateProcessDNS(host *collector, history []*flow, collectors map[string]*collector, names []string, now time.Time) {
	var hints map[processID]map[netip.Addr]processDNSHint
	index := func(f *flow) {
		if f.DNS == nil || f.Client.PID <= 0 {
			return
		}
		id := f.Client.id()
		for _, query := range f.DNS.recentQueries() {
			if !query.answered {
				continue
			}
			for _, answer := range query.addresses {
				lifetime := min(answer.TTL, 5*time.Minute)
				if lifetime <= 0 || now.After(query.at.Add(lifetime)) {
					continue
				}
				if hints[id] == nil {
					if hints == nil {
						hints = make(map[processID]map[netip.Addr]processDNSHint)
					}
					hints[id] = make(map[netip.Addr]processDNSHint)
				}
				addr := answer.Address.Unmap()
				if old := hints[id][addr]; query.at.After(old.at) {
					hints[id][addr] = processDNSHint{query.name, query.at, query.at.Add(lifetime)}
				}
			}
		}
	}
	for _, f := range host.flows {
		index(f)
	}
	for _, f := range host.retired {
		index(f)
	}
	for _, f := range history {
		index(f)
	}
	applyFlow := func(f *flow) {
		if f.DNS != nil || f.Client.PID <= 0 || !f.Target.IsValid() || f.Direction != "outbound" && f.Direction != "local" {
			return
		}
		wire := clientBytes(f)
		if named(wire) && !wire.Evidence().ECH || named(f.ProcessDomain) {
			return
		}
		hint := hints[f.Client.id()][f.Target.Addr().Unmap()]
		if hint.name == "" || hint.at.After(f.First.Add(time.Second)) || now.After(hint.expires) {
			if f.DNSDomain != nil && f.DNSDomain.Evidence().Kind == "dns_process" {
				f.DNSDomain = nil
				chooseDomain(f)
			}
			return
		}
		outer, ech := "", false
		if wire != nil {
			e := wire.Evidence()
			if e.ECH {
				outer, ech = e.SNI, true
			}
		}
		if f.DNSDomain != nil {
			e := f.DNSDomain.Evidence()
			if e.Kind == "dns_process" && e.DNS == hint.name && e.SNI == outer {
				return
			}
		}
		f.DNSDomain = domain.NewDNSProcessHint(hint.name, outer, ech)
		chooseDomain(f)
	}
	apply := func(c *collector) {
		for _, f := range c.flows {
			applyFlow(f)
		}
		for _, f := range c.retired {
			applyFlow(f)
		}
	}
	apply(host)
	for _, name := range names {
		apply(collectors[name])
	}
}
