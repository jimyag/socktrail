package app

import (
	"fmt"
	"strings"
	"time"

	"github.com/jimyag/socktrail/internal/dropprobe"
)

type dropStats struct{ reasons map[string]uint64 }

// recordDrop attaches a kernel discard to an observed flow. The first
// collector in a namespace also keeps drops that occurred before AF_PACKET.
func (c *collector) recordDrop(sample dropprobe.Sample, create bool) {
	if !sample.Source.IsValid() || !sample.Target.IsValid() || !c.acceptPort(sample.Source, sample.Target) {
		return
	}
	key := keyFor(sample.Source, sample.Target, sample.Protocol)
	f := c.flows[key]
	if f == nil && create {
		owners, knownSocket := c.roles[key]
		if !knownSocket {
			return
		}
		if len(c.flows)+len(c.retired) >= c.maxFlows {
			return
		}
		now := time.Now()
		f = &flow{Key: key, Initiator: sample.Source, Target: sample.Target, Direction: "unknown", First: now, Last: now, Client: owners.Client, Server: owners.Server}
		if sample.Protocol == 6 {
			f.TCPState = "midstream"
		}
		c.flows[key] = f
	}
	if f == nil {
		return
	}
	if f.Drops == nil {
		f.Drops = &dropStats{reasons: make(map[string]uint64)}
	}
	f.Drops.reasons[sample.Reason] += sample.Count
	f.Last = time.Now()
}

func dropDetail(f *flow) string {
	if f.Drops == nil {
		return ""
	}
	var parts []string
	for _, item := range dropsJSON(f.Drops.reasons) {
		parts = append(parts, fmt.Sprintf("%s×%d", item.Reason, item.Count))
	}
	return strings.Join(parts, "  ")
}
