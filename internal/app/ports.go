package app

import (
	"cmp"
	"fmt"
	"maps"
	"net/netip"
	"slices"
	"strconv"
	"strings"
)

type portInfo struct {
	protocol, bind, process, service string
	port                             uint16
	accepted, refused, unanswered    uint64
	queue, backlog                   uint32
	backlogKnown                     bool
	sources                          []string
	noListener                       bool
	owner                            participant
}

func (p *portInfo) filterFlow() *flow {
	protocol := uint8(0)
	switch p.protocol {
	case "TCP":
		protocol = 6
	case "UDP":
		protocol = 17
	}
	addr, err := netip.ParseAddr(p.bind)
	if err != nil {
		addr = netip.IPv4Unspecified()
	}
	endpoint := netip.AddrPortFrom(addr, p.port)
	return &flow{Key: flowKey{B: endpoint, Protocol: protocol}, Target: endpoint, Server: p.owner, Direction: "inbound"}
}

func listenerRows(c *collector, inv *socketInventory, processes *processTable, scope *processScope, rates map[*flow]rate) []*uiRow {
	if inv == nil {
		return nil
	}
	attempts := make(map[uint16]attemptPort)
	for _, summary := range c.attempts {
		for port, counts := range summary.Ports {
			current := attempts[port]
			current.Refused += counts.Refused
			current.Unanswered += counts.Unanswered
			attempts[port] = current
		}
	}
	rows := make([]*uiRow, 0, len(inv.listeners)+len(attempts))
	listeningPorts := make(map[uint16]bool)
	type portKey struct {
		protocol uint8
		port     uint16
	}
	flowsByPort := make(map[portKey][]*flow)
	for _, f := range c.allFlows() {
		if f.Closed || f.End != flowOngoing || f.Direction != "inbound" && f.Direction != "local" && f.Direction != "first-packet-in" {
			continue
		}
		key := portKey{f.Key.Protocol, f.Target.Port()}
		flowsByPort[key] = append(flowsByPort[key], f)
	}
	for tuple, socket := range inv.listeners {
		owner, _ := inv.owner(socket.inode)
		if scope != nil && (owner.PID <= 0 || !scope.process(owner.id(), owner.Name)) {
			continue
		}
		service := "-"
		if owner.PID > 0 && processes != nil {
			_, service = processes.group(owner.id(), owner.Name, byService)
		}
		proto := "TCP"
		if tuple.protocol == 17 {
			proto = "UDP"
		}
		bind := tuple.local.Addr().String()
		info := &portInfo{
			protocol: proto, bind: bind, port: tuple.local.Port(), process: formatPIDBrief(owner), service: service, owner: owner,
			accepted: inv.accepted[tuple.local.Port()], queue: socket.queue, backlog: socket.backlog, backlogKnown: socket.backlogKnown,
		}
		if owner.PID <= 0 {
			info.process = "-"
		}
		if counts, ok := attempts[info.port]; ok {
			info.refused, info.unanswered = counts.Refused, counts.Unanswered
		}
		row := &uiRow{key: fmt.Sprintf("port:%d:%s:%s", tuple.protocol, bind, tuple.local), label: proto + " " + tuple.local.String(), listener: info}
		sources := make(map[netip.Addr]uint64)
		for _, f := range flowsByPort[portKey{tuple.protocol, info.port}] {
			if !tuple.local.Addr().IsUnspecified() && f.Target.Addr() != tuple.local.Addr() {
				continue
			}
			row.add(f, rates[f], true)
			sources[f.Initiator.Addr()]++
		}
		addresses := slices.SortedFunc(maps.Keys(sources), func(a, b netip.Addr) int {
			return cmp.Or(cmp.Compare(sources[b], sources[a]), a.Compare(b))
		})
		for _, addr := range addresses[:min(3, len(addresses))] {
			info.sources = append(info.sources, addr.String()+"×"+strconv.FormatUint(sources[addr], 10))
		}
		rows = append(rows, row)
		listeningPorts[info.port] = true
	}
	if scope == nil {
		for port, counts := range attempts {
			if listeningPorts[port] {
				continue
			}
			info := &portInfo{protocol: "-", bind: "-", port: port, process: "-", service: "-", refused: counts.Refused, unanswered: counts.Unanswered, noListener: true}
			rows = append(rows, &uiRow{key: fmt.Sprintf("attempt:%d", port), label: "attempt " + strconv.Itoa(int(port)), listener: info})
		}
	}
	slices.SortFunc(rows, func(a, b *uiRow) int {
		if a.listener.noListener != b.listener.noListener {
			if a.listener.noListener {
				return 1
			}
			return -1
		}
		return cmp.Or(cmp.Compare(a.listener.port, b.listener.port), strings.Compare(a.listener.bind, b.listener.bind))
	})
	return rows
}

func portLayout(rows []*uiRow, viewport int) tableLayout {
	columns := []tableColumn{
		{title: "PROTO", width: 7},
		{title: "BIND", width: 16},
		{title: "PORT", width: 6, right: true},
		{title: "PROCESS", width: 18},
		{title: "SERVICE", width: 20},
		{title: "ACTIVE", width: 7, right: true},
		{title: "ACCEPTED", width: 9, right: true},
		{title: "QUEUE", width: 9, right: true},
		{title: "REFUSED", width: 8, right: true},
		{title: "UNANSWERED", width: 12, right: true},
		{title: "TOP SOURCES", width: 32},
	}
	for _, row := range rows {
		p := row.listener
		columns[1].width = max(columns[1].width, displayWidth(p.bind)+1)
		columns[3].width = max(columns[3].width, displayWidth(p.process)+1)
		columns[4].width = max(columns[4].width, displayWidth(p.service)+1)
	}
	return newTableLayout(columns, viewport, len(columns)-1)
}

func portLine(layout tableLayout, row *uiRow, cursor string) string {
	p := row.listener
	queue, accepted := "-", "-"
	if !p.noListener {
		accepted = strconv.FormatUint(p.accepted, 10)
		if p.protocol == "TCP" {
			queue = strconv.FormatUint(uint64(p.queue), 10) + "/?"
			if p.backlogKnown {
				queue = fmt.Sprintf("%d/%d", p.queue, p.backlog)
				if p.backlog > 0 && uint64(p.queue)*100 >= uint64(p.backlog)*80 {
					queue = styleAlert.paint(queue)
				}
			}
		}
	}
	bind := p.bind
	if bind == "0.0.0.0" || bind == "::" {
		bind = styleYellow.paint(bind)
	}
	values := []string{
		p.protocol, bind, strconv.Itoa(int(p.port)), p.process, p.service,
		strconv.Itoa(len(row.flows)), accepted, queue, strconv.FormatUint(p.refused, 10), strconv.FormatUint(p.unanswered, 10),
		fitItems(p.sources, ", ", layout.columns[len(layout.columns)-1].width),
	}
	return layout.line(cursor, values...)
}

func sortPortRows(rows []*uiRow, spec sortSpec) {
	slices.SortFunc(rows, func(a, b *uiRow) int {
		p, q := a.listener, b.listener
		var order int
		switch spec.key {
		case "PROTO":
			order = strings.Compare(p.protocol, q.protocol)
		case "BIND":
			order = strings.Compare(p.bind, q.bind)
		case "PORT":
			order = cmp.Compare(p.port, q.port)
		case "PROCESS":
			order = strings.Compare(p.process, q.process)
		case "SERVICE":
			order = strings.Compare(p.service, q.service)
		case "ACTIVE":
			order = cmp.Compare(len(a.flows), len(b.flows))
		case "ACCEPTED":
			order = cmp.Compare(p.accepted, q.accepted)
		case "QUEUE":
			order = cmp.Compare(p.queue, q.queue)
		case "REFUSED":
			order = cmp.Compare(p.refused, q.refused)
		case "UNANSWERED":
			order = cmp.Compare(p.unanswered, q.unanswered)
		case "TOP SOURCES":
			order = strings.Compare(strings.Join(p.sources, ","), strings.Join(q.sources, ","))
		default:
			if p.noListener != q.noListener {
				if p.noListener {
					return 1
				}
				return -1
			}
			order = cmp.Compare(p.port, q.port)
		}
		if spec.key != "" {
			order = spec.direction(order)
		}
		return cmp.Or(order, strings.Compare(a.label, b.label))
	})
}
