package app

import (
	"net/netip"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/charmbracelet/x/ansi"
)

func TestEveryTableHeaderIsClickableAfterHorizontalScroll(t *testing.T) {
	u := &terminalUI{screenWidth: 80, screenHeight: 40, bottomStart: 20, dividerY: 19}
	c := &collector{}
	for _, tc := range []struct {
		name   string
		layout tableLayout
		tab    int
		main   bool
	}{
		{"groups", groupLayout(nil, viewPID, 80), 0, true},
		{"connections", connectionLayout(&uiRow{}, viewPID, &collector{}), 0, false},
		{"processes", processLayout(nil, nil), 1, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			virtualX := 1
			for _, column := range tc.layout.columns {
				scrollX := min(max(0, virtualX-8), max(0, tc.layout.width-u.screenWidth))
				x := virtualX - scrollX
				if x < 1 || x >= u.screenWidth {
					t.Fatalf("header %q cannot be reached at x=%d", column.title, x)
				}
				u.tab = tc.tab
				y := u.bottomStart + 1
				if tc.main {
					y = 3
					u.mainLayout, u.mainX = tc.layout, scrollX
				} else {
					u.detailLayout, u.detailX = tc.layout, scrollX
				}
				u.handleMouse(mouseInput{action: mousePress, x: x, y: y}, c)
				var spec *sortSpec
				switch {
				case tc.main:
					spec = &u.mainSort
				case tc.tab == 0:
					spec = &u.flowSort
				default:
					spec = &u.processSort
				}
				if spec.key != column.title {
					t.Fatalf("clicked %q, selected %q", column.title, spec.key)
				}
				firstDirection := spec.desc
				u.handleMouse(mouseInput{action: mousePress, x: x, y: y}, c)
				if spec.desc == firstDirection {
					t.Fatalf("second click on %q did not reverse sort", column.title)
				}
				virtualX += column.width + 1
			}
		})
	}
	if !strings.Contains(ansi.Strip(groupLayout(nil, viewPID, 80).sortedHeader(sortSpec{key: "ICMP PKT", desc: true})), "ICMP PKT↓") {
		t.Fatal("active sort direction is not visible in header")
	}
}

func TestColumnSortUsesActualValuesAndKeepsSelectedFlow(t *testing.T) {
	a := netip.MustParseAddrPort("127.0.0.1:40001")
	b := netip.MustParseAddrPort("127.0.0.1:40002")
	target := netip.MustParseAddrPort("127.0.0.1:443")
	first := &flow{Key: keyFor(a, target, 6), Initiator: a, Target: target, RX: 10, TX: 90, First: time.Unix(10, 0), Client: participant{PID: 101, StartNS: 1000}}
	second := &flow{Key: keyFor(b, target, 6), Initiator: b, Target: target, RX: 20, TX: 0, First: time.Unix(20, 0), Client: first.Client}
	row := &uiRow{label: "101@1000 client", pidID: first.Client.id(), flows: []*flow{first, second}}
	sortFlows(row.flows, row, sortSpec{}, viewPID, &collector{})
	if row.flows[0] != first {
		t.Fatal("default connection order changed")
	}
	u := &terminalUI{mode: viewPID, tab: 0, processGroup: row.label, selectedFlowRef: first, screenWidth: 100, bottomHeight: 20}
	u.flowSort = sortSpec{key: "IP RX", desc: true}
	u.renderBottom(new([]string), []*uiRow{row}, &collector{})
	if u.flowOrder[0] != second || u.selectedFlow != 1 || u.selectedFlowRef != first {
		t.Fatalf("IP RX sort lost selected flow: order=%v selected=%d", u.flowOrder, u.selectedFlow)
	}
	sortFlows(row.flows, row, sortSpec{key: "SOURCE"}, viewPID, &collector{})
	if row.flows[0] != first {
		t.Fatal("SOURCE sort did not use displayed source addresses")
	}
	sortFlows(row.flows, row, sortSpec{key: "FIRST", desc: true}, viewPID, &collector{})
	if row.flows[0] != second {
		t.Fatal("FIRST sort did not use observation time")
	}
}

func TestGroupAndProcessColumnsSortIndependently(t *testing.T) {
	a := &uiRow{label: "101@1000 a", pidID: processID{PID: 101, StartNS: 1000}, rx: 10, tx: 90, rxRate: 2, tcp: 3}
	b := &uiRow{label: "202@2000 b", pidID: processID{PID: 202, StartNS: 2000}, rx: 20, tx: 0, rxRate: 9, tcp: 1}
	rows := []*uiRow{a, b}
	sortGroups(rows, viewPID, sortSpec{}, false)
	if rows[0] != a {
		t.Fatal("default total-byte sort changed")
	}
	sortGroups(rows, viewPID, sortSpec{key: "RX B", desc: true}, false)
	if rows[0] != b {
		t.Fatal("RX B column sorted by combined bytes")
	}
	sortGroups(rows, viewPID, sortSpec{key: "TCP", desc: true}, false)
	if rows[0] != a {
		t.Fatal("TCP column did not sort by flow count")
	}
	processes := []participant{{PID: 101, StartNS: 1000, Name: "z"}, {PID: 202, StartNS: 2000, Name: "a"}}
	c := &collector{pidIO: map[processID]processIO{processes[0].id(): {ioBytes: ioBytes{RX: 2}}, processes[1].id(): {ioBytes: ioBytes{RX: 9}}}}
	parents := func(id processID) int { return map[int]int{101: 7, 202: 9}[id.PID] }
	sortProcesses(processes, c, sortSpec{key: "PROCESS"}, parents)
	if processes[0].PID != 202 {
		t.Fatal("process name sort failed")
	}
	sortProcesses(processes, c, sortSpec{key: "SOCKET RX B", desc: true}, parents)
	if processes[0].PID != 202 || !slices.Contains(processes, participant{PID: 101, StartNS: 1000, Name: "z"}) {
		t.Fatal("process socket-byte sort failed")
	}
	sortProcesses(processes, c, sortSpec{key: "PPID"}, parents)
	if processes[0].PID != 101 {
		t.Fatal("parent PID sort failed")
	}
}
