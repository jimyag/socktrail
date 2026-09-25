package app

import (
	"maps"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/jimyag/socktrail/internal/geoip"
)

type tableColumn struct {
	title string
	width int
	right bool
}

type tableLayout struct {
	columns []tableColumn
	width   int
	styled  bool // Color the cells by their columns; see styleCell.
}

func newTableLayout(columns []tableColumn, viewport int, flexible ...int) tableLayout {
	layout := tableLayout{columns: columns}
	for _, column := range columns {
		layout.width += max(column.width, displayWidth(column.title)+1)
	}
	for i := range layout.columns {
		layout.columns[i].width = max(layout.columns[i].width, displayWidth(layout.columns[i].title)+1)
	}
	layout.width += len(columns) // cursor and spaces between columns
	if extra := viewport - layout.width; extra > 0 && len(flexible) > 0 {
		for i, index := range flexible {
			share := extra / len(flexible)
			if i < extra%len(flexible) {
				share++
			}
			layout.columns[index].width += share
		}
		layout.width = viewport
	}
	return layout
}

func (layout tableLayout) line(cursor string, values ...string) string {
	var result strings.Builder
	result.Grow(layout.width)
	result.WriteString(cursor)
	for i, column := range layout.columns {
		if i > 0 {
			result.WriteByte(' ')
		}
		value := values[i]
		padding := max(0, column.width-displayWidth(value))
		if layout.styled {
			value = styleCell(column.title, value)
		}
		if column.right {
			result.WriteString(strings.Repeat(" ", padding))
		}
		result.WriteString(value)
		if !column.right {
			result.WriteString(strings.Repeat(" ", padding))
		}
	}
	return result.String()
}

func (layout tableLayout) header() string {
	return layout.sortedHeader(sortSpec{})
}

func (layout tableLayout) sortedHeader(spec sortSpec) string {
	values := make([]string, len(layout.columns))
	for i, column := range layout.columns {
		values[i] = column.title
		if column.title == spec.key {
			if spec.desc {
				values[i] += styleCyan.paint("↓")
			} else {
				values[i] += styleCyan.paint("↑")
			}
		}
	}
	return layout.line(" ", values...)
}

func (layout tableLayout) columnAt(screenX, scrollX int) (string, bool) {
	if screenX < 1 {
		return "", false
	}
	virtualX := screenX + scrollX
	start := 1
	for _, column := range layout.columns {
		if virtualX >= start && virtualX < start+column.width {
			return column.title, true
		}
		start += column.width + 1
	}
	return "", false
}

func groupHint(row *uiRow, mode viewMode) string {
	if mode == viewDomain && len(row.flows) > 0 {
		var first string
		for _, f := range row.flows {
			source, target := displayedEndpoints(f)
			pair := source + " → " + target
			if first == "" || pair < first {
				first = pair
			}
		}
		return first
	}
	return observedDomainHint(row)
}

func groupHintValues(row *uiRow, mode viewMode) []string {
	if mode == viewDomain && len(row.flows) > 0 {
		pairs := make(map[string]struct{}, len(row.flows))
		for _, f := range row.flows {
			source, target := displayedEndpoints(f)
			pairs[source+" → "+target] = struct{}{}
		}
		return slices.Sorted(maps.Keys(pairs))
	}
	return observedDomainHints(row)
}

func fitItems(items []string, separator string, width int) string {
	if len(items) == 0 {
		return "-"
	}
	best := "+" + strconv.Itoa(len(items))
	var value strings.Builder
	used := 0
	for i, item := range items {
		if i > 0 {
			value.WriteString(separator)
			used += displayWidth(separator)
		}
		value.WriteString(item)
		used += displayWidth(item)
		remaining := len(items) - i - 1
		suffix := ""
		if remaining > 0 {
			suffix = " +" + strconv.Itoa(remaining)
		}
		if used+displayWidth(suffix) > width {
			break
		}
		best = value.String() + suffix
	}
	return best
}

func flowTimes(flows []*flow) (string, string) {
	var first, last time.Time
	for _, f := range flows {
		if !f.First.IsZero() && (first.IsZero() || f.First.Before(first)) {
			first = f.First
		}
		if f.Last.After(last) {
			last = f.Last
		}
	}
	return displayTime(first), displayTime(last)
}

func displayTime(value time.Time) string {
	if value.IsZero() {
		return "-"
	}
	return value.Format("15:04:05")
}

func groupLayout(rows []*uiRow, mode viewMode, viewport int) tableLayout {
	groupWidth, ifaceWidth := 0, 0
	fullHintWidth, fullIfaceWidth := 42, 0
	tcpWidth, udpWidth, icmpWidth, reqWidth, unknownWidth, flowsWidth := 5, 5, 8, 5, 5, 6
	for _, row := range rows {
		groupWidth = max(groupWidth, displayWidth(row.label))
		ifaceWidth = max(ifaceWidth, displayWidth(interfaceList(row.ifaces, 2)))
		fullIfaceWidth = max(fullIfaceWidth, displayWidth(interfaceList(row.ifaces, 0)))
		separator := ", "
		if mode == viewDomain {
			separator = "; "
		}
		fullHintWidth = max(fullHintWidth, displayWidth(strings.Join(groupHintValues(row, mode), separator)))
		tcpWidth = max(tcpWidth, len(strconv.FormatUint(row.tcp, 10)))
		udpWidth = max(udpWidth, len(strconv.FormatUint(row.udp, 10)))
		icmpWidth = max(icmpWidth, len(strconv.FormatUint(row.icmp, 10)))
		reqWidth = max(reqWidth, len(strconv.FormatUint(row.reqs, 10)))
		unknownWidth = max(unknownWidth, len(strconv.FormatUint(row.unknownPID, 10)))
		flowsWidth = max(flowsWidth, len(strconv.Itoa(len(row.flows))))
	}
	columns := []tableColumn{
		{title: "GROUP", width: groupWidth},
		{title: "IFACE", width: ifaceWidth},
		{title: "RX/s", width: 8, right: true},
		{title: "TX/s", width: 8, right: true},
		{title: "RX B", width: 10, right: true},
		{title: "TX B", width: 10, right: true},
		{title: "TCP", width: tcpWidth, right: true},
		{title: "UDP", width: udpWidth, right: true},
		{title: "ICMP PKT", width: icmpWidth, right: true},
		{title: "REQ", width: reqWidth, right: true},
		{title: "PID?", width: unknownWidth, right: true},
		{title: "FLOWS", width: flowsWidth, right: true},
		{title: "FIRST", width: 8},
		{title: "LAST", width: 8},
		{title: "HOST/SNI OR PEER", width: 42},
	}
	base := newTableLayout(columns, 0)
	extra := max(0, viewport-base.width)
	ifaceNeed := max(0, fullIfaceWidth-base.columns[1].width)
	hintNeed := max(0, fullHintWidth-base.columns[len(base.columns)-1].width)
	if ifaceNeed+hintNeed > 0 {
		columns[1].width += min(ifaceNeed, extra*ifaceNeed/(ifaceNeed+hintNeed))
	}
	return newTableLayout(columns, viewport, len(columns)-1)
}

func groupLine(layout tableLayout, row *uiRow, mode viewMode, cursor string) string {
	first, last := flowTimes(row.flows)
	separator := ", "
	if mode == viewDomain {
		separator = "; "
	}
	ifaces := fitItems(interfacesOf(row.ifaces), ",", layout.columns[1].width)
	hint := fitItems(groupHintValues(row, mode), separator, layout.columns[len(layout.columns)-1].width)
	return layout.line(cursor,
		row.label, ifaces, human(row.rxRate), human(row.txRate), human(row.rx), human(row.tx),
		strconv.FormatUint(row.tcp, 10), strconv.FormatUint(row.udp, 10), strconv.FormatUint(row.icmp, 10),
		strconv.FormatUint(row.reqs, 10), strconv.FormatUint(row.unknownPID, 10), strconv.Itoa(len(row.flows)),
		first, last, hint,
	)
}

// connectionColumns are the connection table's columns, the same on every
// page.
var connectionColumns = []tableColumn{
	{title: "I/O PID"},
	{title: "IFACE"},
	{title: "DIR"},
	{title: "SOURCE"},
	{title: "TARGET"},
	{title: "PROTO"},
	{title: "APP"},
	{title: "STATE"},
	{title: "DOMAIN / ICMP"},
	{title: "IP RX", right: true},
	{title: "IP TX", right: true},
	{title: "RTT", right: true},
	{title: "RETX", right: true},
	{title: "PID RX", right: true},
	{title: "PID TX", right: true},
	{title: "ORIGIN PID"},
	{title: "TARGET PID"},
	{title: "FIRST"},
	{title: "LAST"},
}

// connectionLayout sizes each column to its title or its widest value over
// all the row's connections, so scrolling keeps the columns in place and
// short addresses leave room for the columns after them. GeoIP columns have
// fixed widths so sizing does not look up every retained connection.
func connectionLayout(row *uiRow, mode viewMode, c *collector, showGeo bool) tableLayout {
	columns := slices.Clone(connectionColumns)
	var values []string // Reused: a group can hold thousands of connections.
	for _, f := range row.flows {
		values = connectionValues(values[:0], f, row, mode, c)
		for i, value := range values {
			columns[i].width = max(columns[i].width, displayWidth(value))
		}
	}
	if showGeo {
		columns = slices.Insert(columns, 4, tableColumn{title: "SRC GEO", width: 25})
		columns = slices.Insert(columns, 6, tableColumn{title: "DST GEO", width: 25})
	}
	return newTableLayout(columns, 0)
}

// connectionValues appends a connection's cells in connectionColumns' order.
func connectionValues(values []string, f *flow, row *uiRow, mode viewMode, c *collector) []string {
	processes, io := rowIO(f, row, mode, c)
	pidRX, pidTX := "-", "-"
	if processes != "-" {
		pidRX, pidTX = human(io.RX), human(io.TX)
	}
	source, target := displayedEndpoints(f)
	retx, _ := retransmits(f)
	rtt, _ := flowRTT(f)
	return append(values,
		processes, interfaceList(f.Interfaces, 0), f.Direction, source, target, flowProtocol(f), f.AppProtocol, flowState(f), flowName(f),
		human(f.RX), human(f.TX), formatSYNRTT(rtt), strconv.FormatUint(retx, 10), pidRX, pidTX,
		formatPIDBrief(f.Client), formatPIDBrief(f.Server), displayTime(f.First), displayTime(f.Last))
}

// rowIO names the selected row's processes that read or wrote f's sockets,
// in a stable order, and sums their bytes: the selected process on the PID
// page, the group's processes on the service page, and every process on the
// pages that do not group by process. Unlike the ends' PIDs, it shows the
// child a parent handed an accepted connection to.
func rowIO(f *flow, row *uiRow, mode viewMode, c *collector) (string, ioBytes) {
	var names []string
	var total ioBytes
	for id, io := range f.IO {
		if _, member := row.members[id]; mode == viewPID && id != row.pidID || mode == viewService && !member {
			continue
		}
		names = append(names, formatPIDBrief(participant{PID: id.PID, StartNS: id.StartNS, Name: c.pidIO[id].Name}))
		total.RX, total.TX = total.RX+io.RX, total.TX+io.TX
	}
	if len(names) == 0 {
		return "-", total
	}
	slices.Sort(names)
	return strings.Join(names, ","), total
}

func connectionLine(layout tableLayout, f *flow, row *uiRow, mode viewMode, c *collector, geo *geoip.DB, showGeo bool, cursor string) string {
	values := connectionValues(nil, f, row, mode, c)
	if showGeo {
		source, target := endpointAddresses(f)
		values = slices.Insert(values, 4, geoCell(geo.Lookup(source)))
		values = slices.Insert(values, 6, geoCell(geo.Lookup(target)))
	}
	return layout.line(cursor, values...)
}

func geoCell(place *geoip.Location) string {
	if place == nil {
		return "-"
	}
	var parts []string
	if code := place.CountryCode; len(code) == 2 && code[0] >= 'A' && code[0] <= 'Z' && code[1] >= 'A' && code[1] <= 'Z' {
		parts = append(parts, string([]rune{rune(0x1F1E6) + rune(code[0]-'A'), rune(0x1F1E6) + rune(code[1]-'A')}))
	}
	if place.ASN != 0 {
		parts = append(parts, "AS"+strconv.FormatUint(uint64(place.ASN), 10))
	}
	if place.Organization != "" {
		org, _, _ := strings.Cut(place.Organization, ",")
		if displayWidth(org) > 12 {
			org = fit(org, 11) + "…"
		}
		parts = append(parts, org)
	}
	if len(parts) == 0 {
		return "-"
	}
	return fit(strings.Join(parts, " "), 25)
}

// processLayout lays out a process list; depths indents a process tree.
// Like the connection table, its columns fit their contents.
func processLayout(processes []participant, depths map[processID]int) tableLayout {
	columns := []tableColumn{
		{title: "PID"},
		{title: "PROCESS"},
		{title: "PPID", width: 7}, // pid_max is at most 2^22: seven digits.
		{title: "SOCKET RX B", right: true},
		{title: "SOCKET TX B", right: true},
	}
	for _, p := range processes {
		columns[0].width = max(columns[0].width, len(strconv.Itoa(p.PID)))
		columns[1].width = max(columns[1].width, displayWidth(treeName(p, depths[p.id()])))
	}
	return newTableLayout(columns, 0)
}

func treeName(p participant, depth int) string {
	if depth == 0 {
		return p.Name
	}
	return strings.Repeat("  ", depth-1) + "└ " + p.Name
}

func processLine(layout tableLayout, p participant, parent processID, depth int, io processIO, observed bool, cursor string) string {
	rx, tx, ppid := "-", "-", "-"
	if observed {
		rx, tx = human(io.RX), human(io.TX)
	}
	if parent.PID > 0 {
		ppid = strconv.Itoa(parent.PID)
	}
	return layout.line(cursor, strconv.Itoa(p.PID), treeName(p, depth), ppid, rx, tx)
}
