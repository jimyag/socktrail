package main

import (
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

type tableColumn struct {
	title string
	width int
	right bool
}

type tableLayout struct {
	columns []tableColumn
	width   int
}

func newTableLayout(columns []tableColumn, viewport int, flexible ...int) tableLayout {
	layout := tableLayout{columns: columns}
	for _, column := range columns {
		layout.width += max(column.width, utf8.RuneCountInString(column.title)+1)
	}
	for i := range layout.columns {
		layout.columns[i].width = max(layout.columns[i].width, utf8.RuneCountInString(layout.columns[i].title)+1)
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
		padding := max(0, column.width-utf8.RuneCountInString(value))
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
				values[i] += "↓"
			} else {
				values[i] += "↑"
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

func scrollLine(line string, offset, width int) string {
	if width <= 0 {
		return ""
	}
	runes := []rune(line)
	if offset >= len(runes) {
		return ""
	}
	return string(runes[max(0, offset):min(len(runes), max(0, offset)+width)])
}

func scrollTableLine(line string, offset, width int) string {
	if width <= 0 || line == "" {
		return ""
	}
	runes := []rune(line)
	return string(runes[0]) + scrollLine(string(runes[1:]), offset, width-1)
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
	groupWidth, hintWidth := 32, 42
	tcpWidth, udpWidth, icmpWidth, reqWidth, unknownWidth, flowsWidth := 5, 5, 8, 5, 5, 6
	for _, row := range rows {
		groupWidth = max(groupWidth, utf8.RuneCountInString(row.label))
		hintWidth = max(hintWidth, utf8.RuneCountInString(groupHint(row, mode)))
		tcpWidth = max(tcpWidth, len(strconv.FormatUint(row.tcp, 10)))
		udpWidth = max(udpWidth, len(strconv.FormatUint(row.udp, 10)))
		icmpWidth = max(icmpWidth, len(strconv.FormatUint(row.icmp, 10)))
		reqWidth = max(reqWidth, len(strconv.FormatUint(row.reqs, 10)))
		unknownWidth = max(unknownWidth, len(strconv.FormatUint(row.unknownPID, 10)))
		flowsWidth = max(flowsWidth, len(strconv.Itoa(len(row.flows))))
	}
	columns := []tableColumn{
		{title: "GROUP", width: groupWidth},
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
		{title: "HOST/SNI OR PEER", width: hintWidth},
	}
	return newTableLayout(columns, viewport, 0, len(columns)-1)
}

func groupLine(layout tableLayout, row *uiRow, mode viewMode, cursor string) string {
	first, last := flowTimes(row.flows)
	return layout.line(cursor,
		row.label, human(row.rxRate), human(row.txRate), human(row.rx), human(row.tx),
		strconv.FormatUint(row.tcp, 10), strconv.FormatUint(row.udp, 10), strconv.FormatUint(row.icmp, 10),
		strconv.FormatUint(row.reqs, 10), strconv.FormatUint(row.unknownPID, 10), strconv.Itoa(len(row.flows)),
		first, last, groupHint(row, mode),
	)
}

func connectionLayout(flows []*flow, mode viewMode, viewport int) tableLayout {
	sourceWidth, targetWidth, nameWidth := 42, 42, 40
	directionWidth, protocolWidth, appWidth, stateWidth := 10, 7, 12, 12
	ownerWidth, targetPIDWidth := 20, 20
	for _, f := range flows {
		source, target := displayedEndpoints(f)
		directionWidth = max(directionWidth, utf8.RuneCountInString(f.Direction))
		sourceWidth = max(sourceWidth, utf8.RuneCountInString(source))
		targetWidth = max(targetWidth, utf8.RuneCountInString(target))
		protocolWidth = max(protocolWidth, utf8.RuneCountInString(flowProtocol(f)))
		appWidth = max(appWidth, utf8.RuneCountInString(f.AppProtocol))
		stateWidth = max(stateWidth, utf8.RuneCountInString(flowState(f)))
		nameWidth = max(nameWidth, utf8.RuneCountInString(flowName(f)))
		ownerWidth = max(ownerWidth, utf8.RuneCountInString(formatPIDBrief(f.Client)))
		targetPIDWidth = max(targetPIDWidth, utf8.RuneCountInString(formatPIDBrief(f.Server)))
	}
	columns := []tableColumn{
		{title: "DIR", width: directionWidth},
		{title: "SOURCE", width: sourceWidth},
		{title: "TARGET", width: targetWidth},
		{title: "PROTO", width: protocolWidth},
		{title: "APP", width: appWidth},
		{title: "STATE", width: stateWidth},
		{title: "DOMAIN / ICMP", width: nameWidth},
		{title: "IP RX", width: 10, right: true},
		{title: "IP TX", width: 10, right: true},
		{title: "SYN RTT", width: 10, right: true},
		{title: "RETX", width: 6, right: true},
	}
	if mode == viewPID {
		columns = append(columns,
			tableColumn{title: "PID RX", width: 10, right: true},
			tableColumn{title: "PID TX", width: 10, right: true},
		)
	}
	columns = append(columns,
		tableColumn{title: "ORIGIN PID", width: ownerWidth},
		tableColumn{title: "TARGET PID", width: targetPIDWidth},
	)
	columns = append(columns,
		tableColumn{title: "FIRST", width: 8},
		tableColumn{title: "LAST", width: 8},
	)
	return newTableLayout(columns, viewport, 1, 2, 6)
}

func connectionLine(layout tableLayout, f *flow, row *uiRow, mode viewMode, cursor string) string {
	source, target := displayedEndpoints(f)
	retx, _ := retransmits(f)
	values := []string{
		f.Direction, source, target, flowProtocol(f), f.AppProtocol, flowState(f), flowName(f),
		human(f.RX), human(f.TX), formatSYNRTT(f.Health.SynRTT), strconv.FormatUint(retx, 10),
	}
	if mode == viewPID {
		rx, tx := "-", "-"
		if io, ok := f.IO[row.pidID]; ok && row.pidID.PID > 0 {
			rx, tx = human(io.RX), human(io.TX)
		}
		values = append(values, rx, tx)
	}
	values = append(values, formatPIDBrief(f.Client), formatPIDBrief(f.Server))
	values = append(values, displayTime(f.First), displayTime(f.Last))
	return layout.line(cursor, values...)
}

func processLayout(processes []participant, viewport int) tableLayout {
	pidWidth, nameWidth := 10, 20
	for _, p := range processes {
		pidWidth = max(pidWidth, len(strconv.Itoa(p.PID)))
		nameWidth = max(nameWidth, utf8.RuneCountInString(p.Name))
	}
	columns := []tableColumn{
		{title: "PID", width: pidWidth},
		{title: "PROCESS", width: nameWidth},
		{title: "SOCKET RX B", width: 12, right: true},
		{title: "SOCKET TX B", width: 12, right: true},
	}
	return newTableLayout(columns, viewport, 1)
}

func processLine(layout tableLayout, p participant, io processIO, observed bool, cursor string) string {
	rx, tx := "-", "-"
	if observed {
		rx, tx = human(io.RX), human(io.TX)
	}
	return layout.line(cursor, strconv.Itoa(p.PID), p.Name, rx, tx)
}
