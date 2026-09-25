package app

import (
	"context"
	"fmt"
	"maps"
	"net/netip"
	"sync/atomic"
	"time"

	"github.com/jimyag/socktrail/internal/conntrack"
)

const (
	maxNATEntries = 65536
	natEntryIdle  = 5 * time.Minute // Flows expire after as long idle.
	natQueue      = 1024
)

// natEntry is a NAT'd connection, known by both of its tuples.
type natEntry struct {
	conntrack.Entry
	orig, reply flowKey
	seen        time.Time
}

type natRequest struct {
	protocol uint8
	src, dst netip.AddrPort
}

// natTable links the tuples a NAT rewrote. Each new TCP or UDP flow costs
// one conntrack lookup, made off the packet path; subscribing to conntrack
// events instead would make the kernel report every connection on the host.
// Only the main loop touches entries.
type natTable struct {
	entries   map[flowKey]*natEntry // By both tuples.
	requests  chan natRequest
	results   chan conntrack.Entry
	lookups   atomic.Uint64
	found     atomic.Uint64 // Entries with NAT.
	skipped   atomic.Uint64 // Lookups dropped on a full queue.
	failed    atomic.Uint64
	lastError atomic.Pointer[string]
}

func startNAT(ctx context.Context) (*natTable, string) {
	if err := conntrack.Available(); err != nil {
		return nil, "NAT mapping off: " + err.Error()
	}
	conn, err := conntrack.Open()
	if err != nil {
		return nil, "NAT mapping unavailable: " + err.Error()
	}
	t := &natTable{entries: make(map[flowKey]*natEntry), requests: make(chan natRequest, natQueue), results: make(chan conntrack.Entry, natQueue)}
	go t.resolve(ctx, conn)
	return t, "NAT mapping active: one conntrack lookup per new TCP/UDP flow"
}

func (t *natTable) resolve(ctx context.Context, conn *conntrack.Conn) {
	defer conn.Close()
	for {
		var r natRequest
		select {
		case <-ctx.Done():
			return
		case r = <-t.requests:
		}
		t.lookups.Add(1)
		entry, ok, err := conn.Lookup(r.protocol, r.src, r.dst)
		if err == nil && !ok {
			// A packet seen after the NAT carries the reply direction's tuple.
			entry, ok, err = conn.Lookup(r.protocol, r.dst, r.src)
		}
		if err != nil {
			t.failed.Add(1)
			message := err.Error()
			t.lastError.Store(&message)
			continue
		}
		if !ok || !entry.NAT() {
			continue
		}
		t.found.Add(1)
		select {
		case t.results <- entry:
		case <-ctx.Done():
			return
		}
	}
}

// lookup asks for the conntrack entry of a new flow. A full queue skips it:
// the flow stays unlinked rather than slowing capture.
func (t *natTable) lookup(protocol uint8, src, dst netip.AddrPort) {
	select {
	case t.requests <- natRequest{protocol: protocol, src: src, dst: dst}:
	default:
		t.skipped.Add(1)
	}
}

func (t *natTable) add(e conntrack.Entry, now time.Time) *natEntry {
	orig := keyFor(e.Orig[0], e.Orig[1], e.Protocol)
	if old := t.entries[orig]; old != nil && old.Entry == e {
		old.seen = now
		return old
	}
	entry := &natEntry{Entry: e, orig: orig, reply: keyFor(e.Reply[0], e.Reply[1], e.Protocol), seen: now}
	if len(t.entries) < 2*maxNATEntries {
		t.entries[entry.orig], t.entries[entry.reply] = entry, entry
	}
	return entry
}

func (t *natTable) expire(now time.Time) {
	maps.DeleteFunc(t.entries, func(_ flowKey, e *natEntry) bool { return now.Sub(e.seen) > natEntryIdle })
}

func (t *natTable) stats() string {
	line := fmt.Sprintf("NAT lookups %d  NAT'd %d  queue full %d  failed %d", t.lookups.Load(), t.found.Load(), t.skipped.Load(), t.failed.Load())
	if last := t.lastError.Load(); last != nil {
		line += "  last error: " + *last
	}
	return line
}

func (t *natTable) json(status string) jsonNAT {
	n := jsonNAT{Status: status, Lookups: t.lookups.Load(), Translated: t.found.Load(), QueueFull: t.skipped.Load(), Failed: t.failed.Load()}
	if last := t.lastError.Load(); last != nil {
		n.LastError = *last
	}
	return n
}

// natFlow links a new flow to its NAT entry, or asks conntrack for one.
func (c *collector) natFlow(f *flow, protocol uint8, src, dst netip.AddrPort) {
	if c.nat == nil || protocol != 6 && protocol != 17 || dst.Addr().IsMulticast() {
		return
	}
	if entry := c.nat.entries[f.Key]; entry != nil {
		c.linkNAT(entry)
	} else {
		c.nat.lookup(protocol, src, dst)
	}
}

// linkNAT records a NAT entry on this collector's flows for either tuple. A
// process's socket holds the tuple on its own side of the NAT, so roles and
// I/O recorded under the other tuple move to the captured flow.
func (c *collector) linkNAT(entry *natEntry) {
	for _, keys := range [2][2]flowKey{{entry.orig, entry.reply}, {entry.reply, entry.orig}} {
		f, socket := c.flows[keys[0]], keys[1]
		if f == nil || f.NAT == entry {
			continue
		}
		f.NAT = entry
		if c.flows[socket] != nil {
			continue // Both tuples are captured here, each with its own processes.
		}
		if r, ok := c.roles[socket]; ok {
			client, server := r.Client, r.Server
			if f.Key.Protocol == 17 {
				client, server = r.owner(entry.Other(f.Initiator), socket), r.owner(entry.Other(f.Target), socket)
			}
			if f.Client.PID == 0 {
				f.Client = client
			}
			if f.Server.PID == 0 {
				f.Server = server
			}
		}
		c.attachPendingIO(socket, f)
	}
}

// natSocket translates a socket's tuple into the one this collector
// captured, when a NAT sits between them.
func (c *collector) natSocket(local, remote netip.AddrPort, protocol uint8) (netip.AddrPort, netip.AddrPort) {
	if c.nat == nil || len(c.nat.entries) == 0 {
		return local, remote
	}
	key := keyFor(local, remote, protocol)
	entry := c.nat.entries[key]
	if entry == nil || c.flows[key] != nil {
		return local, remote
	}
	if other, otherRemote := entry.Other(local), entry.Other(remote); c.flows[keyFor(other, otherRemote, protocol)] != nil {
		return other, otherRemote
	}
	return local, remote
}
