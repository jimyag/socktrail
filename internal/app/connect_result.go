package app

import (
	"fmt"
	"syscall"
	"time"

	"github.com/jimyag/socktrail/internal/probe"
)

func connectResultName(result int32) string {
	switch result {
	case 0:
		return "connected"
	case -1:
		return "aborted"
	case int32(syscall.ECONNREFUSED):
		return "refused"
	case int32(syscall.ETIMEDOUT):
		return "timeout"
	case int32(syscall.EHOSTUNREACH):
		return "host unreachable"
	case int32(syscall.ENETUNREACH):
		return "network unreachable"
	default:
		return fmt.Sprintf("errno %d", result)
	}
}

func (c *collector) connectResult(e probe.Event) {
	if !c.acceptPort(e.Local, e.Remote) || !e.Local.IsValid() || !e.Remote.IsValid() {
		return
	}
	key := keyFor(e.Local, e.Remote, 6)
	f := c.flows[key]
	now := time.Now()
	if f != nil && !f.takesEvents(now) {
		if c.interfaceIndex != 0 {
			return
		}
		c.retired = append(c.retired, f)
		delete(c.flows, key)
		f = nil
	}
	if f == nil {
		if c.interfaceIndex != 0 {
			return // Only the base collector keeps probe-only connections.
		}
		if len(c.flows)+len(c.retired) >= c.maxFlows {
			c.evict(now)
		}
		if len(c.flows)+len(c.retired) >= c.maxFlows {
			return
		}
		f = &flow{Key: key, Initiator: e.Local, Target: e.Remote, First: now, Last: now, TCPState: "syn", Direction: "outbound"}
		if c.loopback {
			f.Direction = "local"
		}
		c.flows[key] = f
	}
	f.Health.ConnectResult, f.Health.ConnectLatency = e.Result, e.ConnectLatency
	if e.Result != 0 {
		f.End, f.Closed, f.Last = flowFailed, true, now
	}
}
