package main

import (
	"cmp"
	"fmt"
	"maps"
	"net/netip"
	"os"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/jimyag/socktrail/internal/domain"
	"github.com/jimyag/socktrail/internal/sockstream"
	"github.com/jimyag/socktrail/internal/tlsprobe"

	"golang.org/x/term"
)

type viewMode uint8

const (
	viewPID viewMode = iota
	viewSource
	viewTarget
	viewProtocol
	viewDomain
	viewInterfaces
	viewService
)

var viewNames = [...]string{"PID", "SOURCE IP", "TARGET IP", "PROTOCOL", "DOMAINS", "INTERFACES", "SERVICES"}
var tabNames = [...]string{"conns", "process"}

type rate struct{ rx, tx uint64 }
type counters struct{ rx, tx uint64 }
type hitSpan struct{ start, end int }

type uiRow struct {
	key                  string
	label                string
	iface                string
	pidID                processID
	members              map[processID]string // A service page row's processes with socket I/O, by name.
	flows                []*flow
	rx, tx               uint64
	rxRate, txRate       uint64
	tcp, udp, icmp, reqs uint64
	unknownPID           uint64
}

func pidGroupLabel(p participant) string {
	if p.Name == "" {
		return fmt.Sprint(p.PID)
	}
	return fmt.Sprintf("%d %s", p.PID, p.Name)
}

func pidGroupKey(id processID) string {
	return fmt.Sprintf("%d@%d", id.PID, id.StartNS)
}

func (r *uiRow) identity() string {
	if r.key != "" {
		return r.key
	}
	return r.label
}

func formatPIDBrief(p participant) string {
	if p.PID < 0 {
		return "ambiguous"
	}
	if p.PID == 0 {
		return "unknown"
	}
	if p.Name == "" {
		return strconv.Itoa(p.PID)
	}
	return strconv.Itoa(p.PID) + "(" + p.Name + ")" // Not fmt: the connection table formats every row.
}

func (r *uiRow) add(f *flow, speed rate, ownBytes bool) {
	r.flows = append(r.flows, f)
	if ownBytes {
		r.rx += f.RX
		r.tx += f.TX
		r.rxRate += speed.rx
		r.txRate += speed.tx
	}
	switch f.Key.Protocol {
	case 6:
		r.tcp++
	case 17:
		r.udp++
	case 1, 58:
		r.icmp += f.Packets
	}
	if f.Domain != nil {
		for _, count := range f.Domain.Evidence().Hosts {
			r.reqs += count
		}
	}
	if f.Client.PID == 0 && f.Server.PID == 0 {
		r.unknownPID++
	}
}

type terminalUI struct {
	state             *term.State
	keys              chan uiInput
	mode              viewMode
	previousMode      viewMode
	returnMode        viewMode
	tab               int
	selected          int
	selectedFlow      int
	selectedProcess   int
	selectedGroup     string
	selectedFlowRef   *flow
	selectedProcessID processID
	mainLabels        []string
	flowOrder         []*flow
	processOrder      []participant
	mainSort          sortSpec
	flowSort          sortSpec
	processSort       sortSpec
	mainLayout        tableLayout
	detailLayout      tableLayout
	scroll            int
	focusBottom       bool
	filtering         bool
	filter            string
	sortRate          bool
	help              bool
	status            bool
	captureToggle     bool
	captureStatus     string
	capturePath       string
	tlsProbeStatus    string
	tlsProbeStats     *tlsprobe.Statistics
	streamStatus      string
	streamStats       *sockstream.Statistics
	natStatus         string
	nat               *natTable
	processes         *processTable
	scopeFilter       processFilter   // From --process, --pid and --cgroup: fixed for the session.
	grouping          processGrouping // How the service page groups processes; g cycles it.
	scope             *processScope   // scopeFilter's answers for the current render.
	lastSample        time.Time
	previous          map[*flow]counters
	rates             map[*flow]rate
	pidPrevious       map[processID]ioBytes
	pidRates          map[processID]rate
	globalRate        rate
	started           time.Time
	interfaces        []string
	collectors        map[string]*collector
	interfaceName     string
	hostScope         bool
	interfacePrevious map[string]counters
	interfaceRates    map[string]rate
	netNS             uint64
	screenWidth       int
	screenHeight      int
	mainX             int
	detailX           int
	mainCanvas        int
	detailCanvas      int
	tableRows         int
	dividerY          int
	bottomStart       int
	bottomHeight      int
	flowStart         int
	flowCount         int
	processListStart  int
	processListCount  int
	processTotal      int
	processEnvY       int
	processEnvScroll  int
	processEnvCount   int
	processEnvTotal   int
	processGroup      string
	processInfoID     processID
	processInfo       processDetails
	processInfoAt     time.Time
	topLine           string
	drawnLines        []string
	renderedWidth     int
	renderedHeight    int
	tabHits           [2]hitSpan
	dragging          bool
	closed            bool
}

func openUI(interfaceNames []string, netNS uint64, collectors map[string]*collector) (*terminalUI, error) {
	if !term.IsTerminal(int(os.Stdin.Fd())) || !term.IsTerminal(int(os.Stdout.Fd())) {
		return nil, fmt.Errorf("interactive mode requires a terminal; use --duration for a text snapshot")
	}
	state, err := term.MakeRaw(int(os.Stdin.Fd()))
	if err != nil {
		return nil, fmt.Errorf("put terminal in raw mode: %w", err)
	}
	if _, err := fmt.Fprint(os.Stdout, "\x1b[?1049h\x1b[?25l\x1b[?1000h\x1b[?1002h\x1b[?1006h\x1b[2J\x1b[H"); err != nil {
		fmt.Fprint(os.Stdout, "\x1b[?1006l\x1b[?1002l\x1b[?1000l\x1b[?25h\x1b[?1049l")
		term.Restore(int(os.Stdin.Fd()), state)
		return nil, err
	}
	u := &terminalUI{
		state: state, keys: make(chan uiInput, 64), previous: make(map[*flow]counters),
		rates: make(map[*flow]rate), pidPrevious: make(map[processID]ioBytes), pidRates: make(map[processID]rate),
		started: time.Now(), interfaces: slices.Clone(interfaceNames), interfaceName: interfaceNames[0], hostScope: true, netNS: netNS,
		collectors: collectors, interfacePrevious: make(map[string]counters), interfaceRates: make(map[string]rate),
	}
	u.mode, u.returnMode = viewPID, viewPID
	go readKeys(u.keys)
	return u, nil
}

func (u *terminalUI) close() {
	if u == nil || u.closed {
		return
	}
	u.closed = true
	fmt.Fprint(os.Stdout, "\x1b[?1006l\x1b[?1002l\x1b[?1000l\x1b[?25h\x1b[?1049l")
	term.Restore(int(os.Stdin.Fd()), u.state)
}

func (u *terminalUI) handleKey(key string) bool {
	if key == "quit" { // Ctrl-C, or the terminal went away.
		return true
	}
	if u.filtering {
		switch key {
		case "enter":
			u.filtering = false
		case "esc":
			u.filtering, u.filter = false, ""
		case "backspace":
			if len(u.filter) > 0 {
				u.filter = u.filter[:len(u.filter)-1]
			}
		default:
			if len(key) == 1 && len(u.filter) < 64 {
				u.filter += key
			}
		}
		u.selected, u.scroll = 0, 0
		u.selectedGroup, u.selectedFlowRef, u.selectedProcessID = "", nil, processID{}
		return false
	}
	if key == "q" { // Quits from help and status too; a filter takes q as text.
		return true
	}
	if u.help || u.status {
		u.help, u.status = false, false
		return false
	}
	switch key {
	case "0":
		if u.mode == viewInterfaces {
			u.hostScope = true
			u.mode = u.returnMode
		} else {
			u.returnMode, u.mode = u.mode, viewInterfaces
		}
		u.selected, u.scroll, u.selectedFlow, u.focusBottom = 0, 0, 0, false
		u.selectedGroup, u.selectedFlowRef, u.selectedProcessID = "", nil, processID{}
	case "i":
		if len(u.interfaces) > 1 {
			u.hostScope = false
			u.interfaceName = u.interfaces[(slices.Index(u.interfaces, u.interfaceName)+1)%len(u.interfaces)]
			u.globalRate = u.interfaceRates[u.interfaceName]
			u.selected, u.scroll, u.selectedFlow, u.focusBottom = 0, 0, 0, false
			u.selectedGroup, u.selectedFlowRef, u.selectedProcessID = "", nil, processID{}
			if u.mode == viewInterfaces {
				u.selectedGroup = "iface:" + u.interfaceName
			}
		}
	case "a":
		u.hostScope = true
		if u.mode == viewInterfaces {
			u.mode = u.returnMode
		}
		u.selected, u.scroll, u.selectedFlow, u.focusBottom = 0, 0, 0, false
		u.selectedGroup, u.selectedFlowRef, u.selectedProcessID = "", nil, processID{}
	case "1", "2", "3", "4", "5":
		if u.mode == viewInterfaces {
			u.hostScope = true
		}
		u.mode = viewMode(key[0] - '1')
		if key == "5" {
			u.mode = viewService
		}
		u.selected, u.scroll, u.selectedFlow, u.focusBottom = 0, 0, 0, false
		u.selectedGroup, u.selectedFlowRef, u.selectedProcessID = "", nil, processID{}
	case "g":
		if u.mode == viewService {
			u.grouping = (u.grouping + 1) % processGrouping(len(groupingNames))
			u.selected, u.scroll, u.selectedFlow, u.focusBottom = 0, 0, 0, false
			u.selectedGroup, u.selectedFlowRef, u.selectedProcessID = "", nil, processID{}
		}
	case "d":
		if u.mode == viewInterfaces {
			u.hostScope = true
			u.mode = u.returnMode
		}
		if u.mode == viewDomain {
			u.mode = u.previousMode
		} else {
			u.previousMode, u.mode = u.mode, viewDomain
		}
		u.selected, u.scroll, u.selectedFlow, u.focusBottom = 0, 0, 0, false
		u.selectedGroup, u.selectedFlowRef, u.selectedProcessID = "", nil, processID{}
	case "esc":
		if u.focusBottom {
			u.focusBottom = false
		} else if u.mode == viewInterfaces {
			u.hostScope = true
			u.mode = u.returnMode
		} else if u.mode == viewDomain {
			u.mode = u.previousMode
		} else if u.filter != "" {
			u.filter = ""
		} else if !u.hostScope {
			u.hostScope = true
		}
	case "up", "k":
		if u.focusBottom && u.tab == 0 {
			u.selectedFlow = max(0, u.selectedFlow-1)
			u.rememberFlow()
		} else if u.focusBottom && u.tab == 1 {
			u.selectedProcess = max(0, u.selectedProcess-1)
			u.rememberProcess()
		} else {
			u.selectMain(u.selected - 1)
		}
	case "down", "j":
		if u.focusBottom && u.tab == 0 {
			u.selectedFlow++
			u.rememberFlow()
		} else if u.focusBottom && u.tab == 1 {
			u.selectedProcess++
			u.rememberProcess()
		} else {
			u.selectMain(u.selected + 1)
		}
	case "pageup", "pagedown":
		direction := -1
		if key == "pagedown" {
			direction = 1
		}
		switch {
		case u.focusBottom && u.tab == 1:
			u.processEnvScroll = min(max(0, u.processEnvScroll+direction*max(1, u.processEnvCount)), max(0, u.processEnvTotal-u.processEnvCount))
		case u.focusBottom:
			pageSize := max(1, u.bottomHeight-4)
			u.selectedFlow = min(max(0, u.selectedFlow+direction*pageSize), max(0, len(u.flowOrder)-1))
			u.flowStart = min(u.selectedFlow, max(0, len(u.flowOrder)-pageSize))
			u.rememberFlow()
		default:
			pageSize := max(1, u.dividerY-4)
			u.selectMain(u.selected + direction*pageSize)
			u.scroll = min(u.selected, max(0, len(u.mainLabels)-pageSize))
		}
	case "enter":
		if u.mode == viewInterfaces && !u.focusBottom {
			u.activateSelectedInterface()
			u.hostScope = false
			u.mode = u.returnMode
			u.selected, u.scroll, u.selectedFlow = 0, 0, 0
			u.selectedGroup, u.selectedFlowRef, u.selectedProcessID = "", nil, processID{}
		} else {
			u.focusBottom = !u.focusBottom
		}
	case "tab":
		u.tab = (u.tab + 1) % len(tabNames)
		u.focusBottom = true
	case "left", "h":
		u.scrollColumns(-max(4, u.screenWidth/4), u.focusBottom)
	case "right", "l":
		u.scrollColumns(max(4, u.screenWidth/4), u.focusBottom)
	case "/":
		u.filtering = true
	case "s":
		u.sortRate = !u.sortRate
		u.mainSort = sortSpec{}
	case "?":
		u.help = true
	case "!":
		u.status = true
	case "c":
		u.captureToggle = true
	}
	return false
}

func (u *terminalUI) activateSelectedInterface() {
	if u.mode != viewInterfaces {
		return
	}
	if name, ok := strings.CutPrefix(u.selectedGroup, "iface:"); ok && slices.Contains(u.interfaces, name) {
		u.interfaceName = name
		u.globalRate = u.interfaceRates[name]
	}
}

func (u *terminalUI) selectMain(index int) {
	if len(u.mainLabels) == 0 {
		u.selected = max(0, index)
		return
	}
	u.selected = min(max(0, index), len(u.mainLabels)-1)
	u.selectedGroup = u.mainLabels[u.selected]
	u.selectedFlow, u.selectedFlowRef = 0, nil
	u.selectedProcess, u.selectedProcessID = 0, processID{}
}

func (u *terminalUI) rememberFlow() {
	if len(u.flowOrder) > 0 {
		u.selectedFlow = min(u.selectedFlow, len(u.flowOrder)-1)
		u.selectedFlowRef = u.flowOrder[u.selectedFlow]
	}
}

func (u *terminalUI) rememberProcess() {
	if len(u.processOrder) > 0 {
		u.selectedProcess = min(u.selectedProcess, len(u.processOrder)-1)
		u.selectedProcessID = u.processOrder[u.selectedProcess].id()
	}
}

func (u *terminalUI) handleInput(input uiInput, c *collector) bool {
	if input.mouse.action != mouseNone {
		u.handleMouse(input.mouse, c)
		return false
	}
	return u.handleKey(input.key)
}

func (u *terminalUI) scrollColumns(delta int, detail bool) {
	if detail {
		u.detailX = min(max(u.detailX+delta, 0), max(0, u.detailCanvas-u.screenWidth))
		return
	}
	u.mainX = min(max(u.mainX+delta, 0), max(0, u.mainCanvas-u.screenWidth))
}

func (u *terminalUI) handleMouse(m mouseInput, c *collector) {
	if m.action == mouseRelease {
		if u.dragging {
			u.tableRows = min(max(m.y-4, 2), max(2, u.screenHeight-11))
		}
		u.dragging = false
		return
	}
	if m.action == mouseDrag {
		if u.dragging && m.button == 0 {
			u.tableRows = min(max(m.y-4, 2), max(2, u.screenHeight-11))
		}
		return
	}
	if m.action == mousePress && m.button == 0 && m.y == u.dividerY {
		u.dragging = true
		return
	}
	if c == nil || m.x < 0 || m.y < 0 || m.x >= u.screenWidth || m.y >= u.screenHeight {
		return
	}
	if m.action == mouseWheelLeft || m.action == mouseWheelRight || m.shift && (m.action == mouseWheelUp || m.action == mouseWheelDown) {
		delta := -max(4, u.screenWidth/4)
		if m.action == mouseWheelRight || m.action == mouseWheelDown {
			delta = -delta
		}
		u.scrollColumns(delta, m.y > u.dividerY)
		return
	}
	rows := u.rows(c, u.mode)
	if len(rows) > 0 {
		u.selected = min(u.selected, len(rows)-1)
	}
	if m.action == mouseWheelUp || m.action == mouseWheelDown {
		delta := -3
		if m.action == mouseWheelDown {
			delta = 3
		}
		if m.y > u.dividerY && u.tab == 1 && m.y >= u.processEnvY && u.processEnvCount > 0 {
			u.focusBottom = true
			u.processEnvScroll = min(max(0, u.processEnvTotal-u.processEnvCount), max(0, u.processEnvScroll+delta))
		} else if m.y > u.dividerY && u.tab == 1 && u.processListCount > 0 {
			u.focusBottom = true
			u.selectedProcess = min(max(u.selectedProcess+delta, 0), u.processTotal-1)
			u.rememberProcess()
		} else if m.y > u.dividerY && u.tab == 0 && len(rows) > 0 && len(rows[u.selected].flows) > 0 {
			u.focusBottom = true
			u.selectedFlow = min(max(u.selectedFlow+delta, 0), len(rows[u.selected].flows)-1)
			u.rememberFlow()
		} else if len(rows) > 0 {
			u.focusBottom = false
			u.selectMain(u.selected + delta)
		}
		return
	}
	if m.action != mousePress || m.button != 0 {
		return
	}
	u.help, u.status, u.filtering = false, false, false
	if m.y == 0 {
		for _, item := range [...]struct{ label, key string }{
			{"a OVERVIEW", "a"}, {"0 IFACES", "0"}, {"1 PID", "1"}, {"2 SRC", "2"}, {"3 DST", "3"}, {"4 PROTO", "4"}, {"5 SVC", "5"}, {"d DOMAINS", "d"}, {"i NEXT", "i"},
		} {
			start := strings.Index(u.topLine, item.label)
			if start >= 0 && m.x >= start && m.x < start+len(item.label) {
				u.handleKey(item.key)
				return
			}
		}
	}
	if m.y >= 4 && m.y < u.dividerY {
		index := u.scroll + m.y - 4
		if index < len(rows) {
			u.selectMain(index)
			u.focusBottom = false
		}
		return
	}
	if m.y == 3 {
		if key, ok := u.mainLayout.columnAt(m.x, u.mainX); ok {
			u.mainSort.selectColumn(key)
		}
		return
	}
	if m.y == u.bottomStart+1 {
		if key, ok := u.detailLayout.columnAt(m.x, u.detailX); ok {
			if u.tab == 0 {
				u.flowSort.selectColumn(key)
			} else {
				u.processSort.selectColumn(key)
			}
		}
		return
	}
	if m.y == u.bottomStart {
		for i, hit := range u.tabHits {
			if hit.end > hit.start && m.x >= hit.start && m.x < hit.end {
				u.tab = i
				u.focusBottom = true
				return
			}
		}
	}
	if u.tab == 0 && m.y >= u.bottomStart+2 && m.y < u.bottomStart+2+u.flowCount {
		u.selectedFlow = u.flowStart + m.y - u.bottomStart - 2
		u.rememberFlow()
		u.focusBottom = true
	} else if u.tab == 1 && m.y >= u.bottomStart+2 && m.y < u.bottomStart+2+u.processListCount {
		u.selectedProcess = u.processListStart + m.y - u.bottomStart - 2
		u.rememberProcess()
		u.focusBottom = true
	}
}

func (u *terminalUI) sampleAll(collectors map[string]*collector, now time.Time) {
	if u.lastSample.IsZero() {
		u.lastSample = now
	}
	seconds := now.Sub(u.lastSample).Seconds()
	if seconds <= 0 {
		return
	}
	if u.interfacePrevious == nil {
		u.interfacePrevious = make(map[string]counters)
		u.interfaceRates = make(map[string]rate)
	}
	u.globalRate = rate{}
	active := make(map[*flow]struct{})
	for name, c := range collectors {
		previous := u.interfacePrevious[name]
		u.interfaceRates[name] = rate{rx: uint64(float64(c.rxBytes-previous.rx) / seconds), tx: uint64(float64(c.txBytes-previous.tx) / seconds)}
		u.interfacePrevious[name] = counters{c.rxBytes, c.txBytes}
		for _, f := range c.allFlows() {
			active[f] = struct{}{}
			old := u.previous[f]
			r := rate{rx: uint64(float64(f.RX-old.rx) / seconds), tx: uint64(float64(f.TX-old.tx) / seconds)}
			u.rates[f] = r
			u.previous[f] = counters{f.RX, f.TX}
		}
	}
	u.globalRate = u.interfaceRates[u.interfaceName]
	for f := range u.previous {
		if _, ok := active[f]; !ok {
			delete(u.previous, f)
			delete(u.rates, f)
		}
	}
	if u.pidPrevious == nil {
		u.pidPrevious = make(map[processID]ioBytes)
		u.pidRates = make(map[processID]rate)
	}
	for id, total := range collectors[u.interfaceName].pidIO {
		old := u.pidPrevious[id]
		u.pidRates[id] = rate{rx: uint64(float64(total.RX-old.RX) / seconds), tx: uint64(float64(total.TX-old.TX) / seconds)}
		u.pidPrevious[id] = total.ioBytes
	}
	for id := range u.pidPrevious {
		if _, retained := collectors[u.interfaceName].pidIO[id]; !retained {
			delete(u.pidPrevious, id)
			delete(u.pidRates, id)
		}
	}
	u.lastSample = now
}

func (u *terminalUI) rows(c *collector, mode viewMode) []*uiRow {
	if u.processes == nil {
		u.processes = newProcessTable("/proc")
	}
	scope := newProcessScope(u.processes, u.scopeFilter)
	u.scope = scope
	rows := make(map[string]*uiRow)
	namedPID := func(p participant) participant {
		if observed, ok := c.pidIO[p.id()]; ok && observed.Name != "" {
			p.Name = observed.Name
		}
		return p
	}
	addWithKey := func(key, label string, f *flow, ownBytes bool) *uiRow {
		r := rows[key]
		if r == nil {
			r = &uiRow{key: key, label: label}
			rows[key] = r
		}
		r.add(f, u.rates[f], ownBytes)
		return r
	}
	add := func(label string, f *flow, ownBytes bool) *uiRow {
		return addWithKey(label, label, f, ownBytes)
	}
	if mode == viewInterfaces {
		for _, name := range u.interfaces {
			ifaceCollector := u.collectors[name]
			if ifaceCollector == nil {
				continue
			}
			row := &uiRow{
				key: "iface:" + name, label: name, iface: name,
				rx: ifaceCollector.rxBytes, tx: ifaceCollector.txBytes,
				rxRate: u.interfaceRates[name].rx, txRate: u.interfaceRates[name].tx,
			}
			for _, f := range ifaceCollector.allFlows() {
				if scope.flow(f, ifaceCollector) {
					row.add(f, u.rates[f], false)
				}
			}
			rows[row.key] = row
		}
	} else {
		for _, f := range c.allFlows() {
			if !scope.flow(f, c) {
				continue
			}
			switch mode {
			case viewService:
				groups := make(map[string]string)
				for _, p := range flowProcesses(f, c) {
					if scope.process(p.id(), p.Name) {
						key, label := u.processes.group(p.id(), p.Name, u.grouping)
						groups[key] = label
					}
				}
				if len(groups) == 0 {
					add("unknown process", f, false)
				}
				for key, label := range groups {
					addWithKey(key, label, f, false)
				}
			case viewPID:
				participants := make(map[processID]participant)
				if f.Client.PID > 0 {
					participants[f.Client.id()] = f.Client
				}
				if f.Server.PID > 0 {
					participants[f.Server.id()] = f.Server
				}
				for id := range f.IO {
					if _, exists := participants[id]; !exists {
						participants[id] = participant{PID: id.PID, StartNS: id.StartNS, Name: c.pidIO[id].Name}
					}
				}
				for id, actor := range f.TLSActors {
					participants[id] = actor
				}
				switch len(participants) {
				case 0:
					add("unknown PID", f, false)
				default:
					for _, p := range participants {
						if p = namedPID(p); scope.process(p.id(), p.Name) {
							addWithKey(pidGroupKey(p.id()), pidGroupLabel(p), f, false).pidID = p.id()
						}
					}
				}
			case viewSource:
				add(endpointGroup(f.Initiator), f, true)
			case viewTarget:
				add(endpointGroup(f.Target), f, true)
			case viewProtocol:
				label := flowProtocol(f)
				if f.AppProtocol != "" {
					label += " / " + f.AppProtocol
				}
				add(label, f, true)
			case viewDomain:
				if f.Domain != nil && f.Domain.Evidence().Listed() {
					add(f.Domain.Evidence().Label(), f, true)
				}
			}
		}
	}
	if mode == viewSource && scope == nil {
		// A scanning source stays visible after its flows are evicted.
		for source, a := range c.attempts {
			key := source.String()
			r := rows[key]
			if r == nil {
				r = &uiRow{key: key, label: key}
				rows[key] = r
			}
			r.label = key + "  " + a.String()
		}
	}
	if mode == viewService {
		// A group's socket bytes and rates are its processes'.
		for id, io := range c.pidIO {
			if !scope.process(id, io.Name) {
				continue
			}
			key, label := u.processes.group(id, io.Name, u.grouping)
			r := rows[key]
			if r == nil {
				r = &uiRow{key: key, label: label}
				rows[key] = r
			}
			r.rx, r.tx = r.rx+io.RX, r.tx+io.TX
			r.rxRate, r.txRate = r.rxRate+u.pidRates[id].rx, r.txRate+u.pidRates[id].tx
			if r.members == nil {
				r.members = make(map[processID]string)
			}
			r.members[id] = io.Name
		}
	}
	if mode == viewPID {
		for id, io := range c.pidIO {
			if !scope.process(id, io.Name) {
				continue
			}
			key := pidGroupKey(id)
			label := pidGroupLabel(participant{PID: id.PID, StartNS: id.StartNS, Name: io.Name})
			r := rows[key]
			if r == nil {
				r = &uiRow{key: key, label: label}
				rows[key] = r
			} else {
				r.label = label
			}
			r.pidID = id
			r.rx, r.tx = io.RX, io.TX
			r.rxRate, r.txRate = u.pidRates[id].rx, u.pidRates[id].tx
		}
		generations := make(map[int][]*uiRow)
		for _, row := range rows {
			if row.pidID.PID > 0 {
				generations[row.pidID.PID] = append(generations[row.pidID.PID], row)
			}
		}
		for _, samePID := range generations {
			if len(samePID) < 2 {
				continue
			}
			slices.SortFunc(samePID, func(a, b *uiRow) int { return cmp.Compare(a.pidID.StartNS, b.pidID.StartNS) })
			for i, row := range samePID {
				row.label += fmt.Sprintf(" #%d", i+1)
			}
		}
	}
	addSummary := func(label string, rx, tx uint64) {
		if rx+tx == 0 || scope != nil { // These bytes belong to no known process.
			return
		}
		r := rows[label]
		if r == nil {
			r = &uiRow{label: label}
			rows[label] = r
		}
		r.rx += rx
		r.tx += tx
	}
	if mode == viewPID {
		addSummary("unindexed PID socket I/O", c.ioUnindexed.RX, c.ioUnindexed.TX)
		addSummary("expired PID socket I/O detail", c.expiredPIDIO.RX, c.expiredPIDIO.TX)
	} else if mode == viewDomain {
		addSummary("expired domain detail", c.expiredDomainRX, c.expiredDomainTX)
	} else if mode != viewInterfaces {
		addSummary("expired connection detail", c.expiredRX, c.expiredTX)
		addSummary("unindexed packets", c.unindexedRX, c.unindexedTX)
	}
	result := make([]*uiRow, 0, len(rows))
	numericPIDFilter := mode == viewPID && u.filter != "" && strings.IndexFunc(u.filter, func(r rune) bool { return r < '0' || r > '9' }) == -1
	for _, row := range rows {
		if u.filter == "" || numericPIDFilter && strings.HasPrefix(row.label, u.filter) || !numericPIDFilter && rowMatches(row, u.filter) {
			result = append(result, row)
		}
	}
	sortGroups(result, mode, u.mainSort, u.sortRate)
	return result
}

func endpointGroup(endpoint netip.AddrPort) string {
	if !endpoint.IsValid() {
		return "unknown origin"
	}
	return endpoint.Addr().String()
}

func formatFlowEndpoint(endpoint netip.AddrPort, protocol uint8) string {
	switch {
	case !endpoint.IsValid():
		return "-" // A frame without an IP header, other than ARP.
	case protocol == 0 || protocol == 1 || protocol == 58: // ARP and ICMP have no ports.
		return endpoint.Addr().String()
	}
	return endpoint.String()
}

func displayedEndpoints(f *flow) (string, string) {
	if f.Initiator.IsValid() || f.Key.EtherType != 0 {
		return formatFlowEndpoint(f.Initiator, f.Key.Protocol), formatFlowEndpoint(f.Target, f.Key.Protocol)
	}
	// The ordered tuple is still useful, but it does not establish which peer
	// initiated a TCP connection captured after its handshake.
	return "?" + formatFlowEndpoint(f.Key.A, f.Key.Protocol), "?" + formatFlowEndpoint(f.Key.B, f.Key.Protocol)
}

func flowName(f *flow) string {
	if f.Key.EtherType != 0 {
		return l2Description(f)
	}
	if f.Key.Protocol == 1 || f.Key.Protocol == 58 {
		return icmpDescription(f)
	}
	var name string
	if f.Domain != nil && f.Domain.Evidence().Listed() {
		name = f.Domain.Evidence().Label()
	}
	switch detail := appDetail(f); {
	case detail != "" && name != "":
		return name + "; " + detail
	case detail != "":
		return detail
	case name != "":
		return name
	}
	return "unknown"
}

// httpsCoverage reports how much TLS/QUIC IP traffic has a destination name
// and why the rest has none. Connections open before capture began are
// counted apart: their handshakes were never visible.
func httpsCoverage(flows []*flow) string {
	var total, named, dns, before uint64
	unnamed := make(map[string]uint64)
	for _, f := range flows {
		if f.AppProtocol != "TLS" && f.AppProtocol != "QUIC" {
			continue
		}
		bytes := f.RX + f.TX
		if f.Preexisting {
			before += bytes
			continue
		}
		total += bytes
		var e domain.Evidence
		if f.Domain != nil {
			e = f.Domain.Evidence()
		}
		switch {
		case !e.Named():
			unnamed[e.Group()] += bytes
		case e.Kind == "dns":
			named += bytes
			dns += bytes
		default:
			named += bytes
		}
	}
	line := "TLS/QUIC names: no TLS/QUIC connection opened since start"
	if total > 0 {
		percent := func(n uint64) uint64 { return n * 100 / total }
		line = fmt.Sprintf("TLS/QUIC named %d%% of %sB (DNS hint %d%%)", percent(named), human(total), percent(dns))
		if len(unnamed) > 0 {
			var reasons []string
			for _, reason := range slices.Sorted(maps.Keys(unnamed)) {
				reasons = append(reasons, fmt.Sprintf("%s %d%%", reason, percent(unnamed[reason])))
			}
			line += "; unnamed: " + strings.Join(reasons, ", ")
		}
	}
	if before > 0 {
		line += fmt.Sprintf("; %sB on connections open before start", human(before))
	}
	return line
}

// evidenceLine explains where the selected connection's name came from and
// lists every name that recently resolved to its target.
func evidenceLine(f *flow, c *collector) string {
	var parts []string
	if f.Domain != nil {
		if detail := f.Domain.Evidence().Detail(); detail != "" {
			parts = append(parts, detail)
		}
	}
	if f.Preexisting {
		parts = append(parts, "open before capture began")
	}
	if f.NAT != nil {
		parts = append(parts, f.NAT.String())
	}
	for _, peer := range dnsPeers(f) {
		if c.dns == nil || !peer.IsValid() {
			break
		}
		if names := c.dns.Names(peer.Addr()); len(names) > 0 {
			parts = append(parts, "DNS names for "+peer.Addr().String()+": "+strings.Join(names, ", "))
		}
	}
	if len(parts) == 0 {
		return "EVIDENCE -"
	}
	return "EVIDENCE " + strings.Join(parts, "; ")
}

func observedDomainHint(row *uiRow) string {
	names := make(map[string]struct{})
	var hasUnknownTLS bool
	for _, f := range row.flows {
		if f.Domain == nil || !f.Domain.Evidence().Listed() {
			continue
		}
		e := f.Domain.Evidence()
		if e.Named() {
			names[e.Label()] = struct{}{}
		} else if e.Kind == "tls" || e.Kind == "quic" || e.Kind == "openssl" {
			hasUnknownTLS = true
		}
	}
	if len(names) > 0 {
		ordered := slices.Sorted(maps.Keys(names))
		if len(ordered) == 1 {
			return ordered[0]
		}
		return fmt.Sprintf("%s +%d", ordered[0], len(ordered)-1)
	}
	if hasUnknownTLS {
		return "TLS/QUIC unknown"
	}
	return "-"
}

func rowMatches(row *uiRow, filter string) bool {
	filter = strings.ToLower(filter)
	if strings.Contains(strings.ToLower(row.label), filter) {
		return true
	}
	for _, f := range row.flows {
		search := fmt.Sprintf("%s %s %s %s %d %s %d %s %s", f.Key.A, f.Key.B, f.Initiator, f.Target, f.Client.PID, f.Client.Name, f.Server.PID, f.Server.Name, f.AppProtocol)
		if f.Domain != nil {
			e := f.Domain.Evidence()
			search += " " + e.Label() + " " + e.SNI + " " + e.Proxy + " " + e.DNS
		}
		if f.NAT != nil {
			search += " " + f.NAT.String()
		}
		if strings.Contains(strings.ToLower(search), filter) {
			return true
		}
	}
	return false
}

func (u *terminalUI) render(c *collector, probeReceived, probeLost, probeDropped uint64) {
	width, height, err := term.GetSize(int(os.Stdout.Fd()))
	if err != nil {
		width, height = 100, 30
	}
	if width < 20 || height < 13 {
		u.screenWidth, u.screenHeight = width, height
		u.draw([]string{"Resize terminal (min 20x13)"}, max(1, width-1), height)
		return
	}
	width-- // Keep the last terminal cell free so a full-width row cannot auto-wrap.
	rows := u.rows(c, u.mode)
	if u.selectedGroup != "" {
		if index := slices.IndexFunc(rows, func(row *uiRow) bool { return row.identity() == u.selectedGroup }); index >= 0 {
			u.selected = index
		} else {
			u.selectedGroup, u.selectedFlowRef, u.selectedProcessID = "", nil, processID{}
		}
	}
	if u.selected >= len(rows) {
		u.selected = max(0, len(rows)-1)
	}
	u.mainLabels = u.mainLabels[:0]
	for _, row := range rows {
		u.mainLabels = append(u.mainLabels, row.identity())
	}
	if len(rows) > 0 {
		u.selectedGroup = rows[u.selected].identity()
	}
	tableHeight := u.tableRows
	if tableHeight == 0 {
		tableHeight = max(2, height/2-5)
	}
	tableHeight = min(max(tableHeight, 2), max(2, height-11))
	u.screenWidth, u.screenHeight = width, height
	u.dividerY = 4 + tableHeight
	u.bottomStart = u.dividerY + 1
	u.bottomHeight = height - 1 - u.bottomStart
	u.flowStart, u.flowCount = 0, 0
	u.processListStart, u.processListCount, u.processTotal = 0, 0, 0
	u.processEnvY, u.processEnvCount, u.processEnvTotal = 0, 0, 0
	u.tabHits = [2]hitSpan{}
	u.detailCanvas = 0
	u.detailLayout = tableLayout{}
	if u.selected < u.scroll {
		u.scroll = u.selected
	}
	if u.selected >= u.scroll+tableHeight {
		u.scroll = u.selected - tableHeight + 1
	}
	var lines []string
	var parseFailures, namedDomainFlows uint64
	observed := []*collector{c}
	if u.mode == viewInterfaces {
		observed = observed[:0]
		for _, name := range u.interfaces {
			if observedCollector := u.collectors[name]; observedCollector != nil {
				observed = append(observed, observedCollector)
			}
		}
	}
	var dropped, truncated, flowIndex, pidIndex, unindexed uint64
	for _, observedCollector := range observed {
		dropped += observedCollector.kernelDropped
		truncated += observedCollector.truncated
		flowIndex += observedCollector.droppedFlow
		pidIndex += observedCollector.droppedRole
		unindexed += observedCollector.ioUnindexed.RX + observedCollector.ioUnindexed.TX
		for _, f := range observedCollector.allFlows() {
			if f.Domain == nil {
				continue
			}
			e := f.Domain.Evidence()
			if e.ParseError != "" {
				parseFailures++
			}
			if e.Named() {
				namedDomainFlows++
			}
		}
	}
	var sniffLost uint64
	if u.streamStats != nil {
		sniffLost = u.streamStats.KernelLost.Load() + u.streamStats.Dropped.Load()
	}
	// Name each nonzero loss, so the cause shows without the status page.
	var reasons []string
	for _, count := range []struct {
		name string
		n    uint64
	}{
		{"drop", dropped}, {"trunc", truncated}, {"flow-index", flowIndex}, {"pid-index", pidIndex},
		{"pid-lost", probeLost + probeDropped}, {"io-unindexed", unindexed}, {"sniff-lost", sniffLost}, {"parse", parseFailures},
	} {
		if count.n > 0 {
			reasons = append(reasons, fmt.Sprintf("%s=%d", count.name, count.n))
		}
	}
	mark := ""
	if len(reasons) > 0 {
		mark = " INCOMPLETE " + strings.Join(reasons, " ")
	}
	if strings.Contains(u.tlsProbeStatus, "unavailable") || strings.Contains(u.tlsProbeStatus, "stopped") {
		mark += " OPENSSL-PROBE-UNAVAILABLE"
	}
	if strings.Contains(u.streamStatus, "unavailable") || strings.Contains(u.streamStatus, "stopped") {
		mark += " SOCKET-SNIFF-UNAVAILABLE"
	}
	if u.scopeFilter.active() {
		mark += " ONLY " + u.scopeFilter.String()
	}
	u.topLine = fmt.Sprintf("socktrail %s (%d/%d) IP RX %sB/s TX %sB/s%s  a OVERVIEW 1 PID 2 SRC 3 DST 4 PROTO 5 SVC d DOMAINS 0 IFACES i NEXT", u.interfaceName, slices.Index(u.interfaces, u.interfaceName)+1, len(u.interfaces), human(u.globalRate.rx), human(u.globalRate.tx), mark)
	if u.mode == viewInterfaces {
		u.topLine = fmt.Sprintf("socktrail IFACES (%d)%s  a OVERVIEW 1 PID 2 SRC 3 DST 4 PROTO 5 SVC d DOMAINS 0 IFACES i NEXT", len(u.interfaces), mark)
	} else if u.hostScope {
		u.topLine = fmt.Sprintf("socktrail OVERVIEW (%d ifaces)%s  a OVERVIEW 1 PID 2 SRC 3 DST 4 PROTO 5 SVC d DOMAINS 0 IFACES", len(u.interfaces), mark)
	} else if width < 125 {
		u.topLine = fmt.Sprintf("socktrail %s (%d/%d)%s  a OVERVIEW 1 PID 2 SRC 3 DST 4 PROTO 5 SVC d DOMAINS 0 IFACES i NEXT", u.interfaceName, slices.Index(u.interfaces, u.interfaceName)+1, len(u.interfaces), mark)
	}
	lines = append(lines, u.topLine)
	if u.mode == viewInterfaces {
		lines = append(lines, fmt.Sprintf("%d interfaces; IP bytes/rates are per interface, not a host total. Enter opens selected interface; i cycles.", len(rows)))
	} else if u.mode == viewService {
		lines = append(lines, fmt.Sprintf("SERVICES by %s (g: service, cgroup, process tree) | RX/TX: socket bytes of the group's processes | flows %d", groupingNames[u.grouping], len(c.allFlows())))
	} else if u.hostScope && u.mode == viewPID {
		lines = append(lines, fmt.Sprintf("PID: whole-netns socket bytes | IP detail: one capture copy/flow | Host/SNI %d", namedDomainFlows))
	} else if u.hostScope && u.mode == viewDomain {
		lines = append(lines, fmt.Sprintf("%s | %d named flows | OBS IP bytes: one copy/flow", httpsCoverage(c.allFlows()), namedDomainFlows))
	} else if u.hostScope {
		lines = append(lines, fmt.Sprintf("%s: %d flows | OBS IP bytes: one copy/flow, not host total", viewNames[u.mode], len(c.allFlows())))
	} else if u.mode == viewDomain {
		var shown uint64
		for _, row := range rows {
			shown += row.rx + row.tx
		}
		lines = append(lines, fmt.Sprintf("%s | shown %sB / all IP %sB  since %s", httpsCoverage(c.allFlows()), human(shown), human(c.bytes), u.started.Format("15:04:05")))
	} else if u.mode == viewPID {
		lines = append(lines, fmt.Sprintf("PID I/O: whole netns; links and Host/SNI: %s (%d named flows); IP %sB  netns:%d", u.interfaceName, namedDomainFlows, human(c.bytes), u.netNS))
	} else {
		lines = append(lines, fmt.Sprintf("%s  IP bytes %s  flows %d  netns:%d  since %s", viewNames[u.mode], human(c.bytes), len(c.allFlows()), u.netNS, u.started.Format("15:04:05")))
	}
	if width < 110 && u.mode != viewInterfaces && !u.hostScope {
		lines[1] = fmt.Sprintf("IP RX %sB/s TX %sB/s%s | %s", human(u.globalRate.rx), human(u.globalRate.tx), mark, lines[1])
	}
	lines = append(lines, strings.Repeat("─", width))
	layout := groupLayout(rows, u.mode, width)
	u.mainLayout = layout
	u.mainCanvas = layout.width
	u.mainX = min(u.mainX, max(0, layout.width-width))
	lines = append(lines, scrollTableLine(layout.sortedHeader(u.mainSort), u.mainX, width))
	for i := u.scroll; i < u.scroll+tableHeight; i++ {
		if i >= len(rows) {
			lines = append(lines, "")
			continue
		}
		r := rows[i]
		cursor := " "
		if i == u.selected {
			cursor = "▸"
		}
		lines = append(lines, scrollTableLine(groupLine(layout, r, u.mode, cursor), u.mainX, width))
	}
	lines = append(lines, "─ drag to resize ─"+strings.Repeat("─", max(0, width-18)))
	if u.help {
		lines = append(lines, "HELP  a overview (merged interfaces)  0 interfaces  1 PID  2 source IP  3 target IP  4 protocol  5 services (g groups by service, cgroup or process tree)  d domains  i next interface")
		lines = append(lines, "↑↓/jk select  Enter focus details  Tab conns/process  PgUp/PgDn page  c capture  ←→ columns")
		lines = append(lines, "Mouse: click any table header to sort/reverse; click rows/tabs, wheel to scroll, drag divider")
		lines = append(lines, "Names: HTTP Host, TLS/QUIC SNI ([ECH] = ECH offered), PROXY target, OPENSSL process SNI, DNS answer hint. No HTTPS request count.")
	} else if u.status {
		lines = append(lines, u.tlsProbeStatus)
		if u.tlsProbeStats != nil {
			lines = append(lines, fmt.Sprintf("OpenSSL SNI events %d  invalid %d  queue dropped %d", u.tlsProbeStats.Received.Load(), u.tlsProbeStats.Invalid.Load(), u.tlsProbeStats.Dropped.Load()))
		}
		lines = append(lines, u.streamStatus)
		if u.streamStats != nil {
			lines = append(lines, fmt.Sprintf("Socket stream chunks %d  kernel lost %d  queue dropped %d  invalid %d", u.streamStats.Received.Load(), u.streamStats.KernelLost.Load(), u.streamStats.Dropped.Load(), u.streamStats.Invalid.Load()))
		}
		lines = append(lines, u.natStatus)
		if u.nat != nil {
			lines = append(lines, u.nat.stats())
		}
		if u.capturePath != "" {
			lines = append(lines, "PCAPNG: "+u.captureStatus+"  "+u.capturePath)
		}
		if u.mode == viewInterfaces {
			lines = append(lines, "STATUS per interface; IP packet bytes are separate from PID socket I/O")
			for _, name := range u.interfaces {
				ifaceCollector := u.collectors[name]
				if ifaceCollector == nil {
					continue
				}
				lines = append(lines, fmt.Sprintf("%s  IP RX %sB TX %sB  AF_PACKET dropped %d  truncated %d  flow-index drops %d", name, human(ifaceCollector.rxBytes), human(ifaceCollector.txBytes), ifaceCollector.kernelDropped, ifaceCollector.truncated, ifaceCollector.droppedFlow))
			}
			lines = append(lines, fmt.Sprintf("PID events %d  ring lost %d  queue dropped %d; PID I/O belongs to the whole netns", probeReceived, probeLost, probeDropped))
		} else {
			lines = append(lines, "STATUS  IP packet bytes and PID socket I/O bytes are separate measures")
			if u.hostScope {
				lines = append(lines, "OVERVIEW: selected interfaces merged per flow; IP bytes are not an exact whole-host total")
			}
			lines = append(lines, fmt.Sprintf("AF_PACKET delivered %d  dropped %d  truncated %d  flow-index drops %d", c.kernelReceived, c.kernelDropped, c.truncated, c.droppedFlow))
			lines = append(lines, fmt.Sprintf("PID events %d  ring lost %d  queue dropped %d  index dropped %d  parse failures %d", probeReceived, probeLost, probeDropped, c.droppedRole, parseFailures))
			if u.hostScope {
				lines = append(lines, fmt.Sprintf("PID socket I/O without PID index %dB", c.ioUnindexed.RX+c.ioUnindexed.TX))
			} else {
				lines = append(lines, fmt.Sprintf("PID socket I/O without selected flow %dB  unindexed %dB", c.ioUnmatched, c.ioUnindexed.RX+c.ioUnindexed.TX))
			}
			lines = append(lines, "Unknown PID/domain remains visible. lo duplicate delivery is counted once.")
		}
	} else {
		detailCollector := c
		if u.mode == viewInterfaces && len(rows) > 0 {
			if selectedCollector := u.collectors[rows[u.selected].iface]; selectedCollector != nil {
				detailCollector = selectedCollector
			}
		}
		u.renderBottom(&lines, rows, detailCollector)
	}
	if len(lines) > height-1 {
		lines = lines[:height-1]
	}
	for len(lines) < height-1 {
		lines = append(lines, "")
	}
	if u.filtering {
		lines = append(lines, "/"+u.filter+"_")
	} else {
		mainOrder := sortName(u.sortRate)
		if u.mainSort.key != "" {
			arrow := "↑"
			if u.mainSort.desc {
				arrow = "↓"
			}
			mainOrder = u.mainSort.key + arrow
		}
		lines = append(lines, fmt.Sprintf("↑↓ rows  ←→ columns  wheel/Shift+wheel  top:%d/%d detail:%d/%d  /:%s sort:%s s:total c:capture %s ? q", u.mainX, max(0, u.mainCanvas-width), u.detailX, max(0, u.detailCanvas-width), u.filter, mainOrder, u.captureStatus))
	}
	u.draw(lines, width, height)
}

func (u *terminalUI) renderBottom(lines *[]string, rows []*uiRow, c *collector) {
	if len(rows) == 0 {
		if u.mode == viewDomain && u.filter == "" {
			if u.hostScope {
				*lines = append(*lines, "No HTTP, TLS, QUIC, proxy or DNS name evidence on captured host interfaces yet.",
					"Names come from requests and handshakes captured after start, or later DNS answers.", "", "")
			} else {
				*lines = append(*lines, "No HTTP, TLS, QUIC, proxy or DNS name evidence on "+u.interfaceName+" yet.",
					"The client request or ClientHello must cross this interface after capture starts.",
					"If traffic uses a proxy/tunnel, select its interface for outbound handshakes.", "")
			}
		} else {
			*lines = append(*lines, "No matching group", "", "", "")
		}
		return
	}
	row := rows[u.selected]
	if row.identity() != u.processGroup {
		u.processGroup, u.selectedProcess, u.processEnvScroll = row.identity(), 0, 0
		u.selectedFlow, u.selectedFlowRef, u.selectedProcessID = 0, nil, processID{}
	}
	if len(row.flows) == 0 && !(u.tab == 1 && u.mode == viewPID && row.pidID.PID > 0) {
		if u.mode == viewInterfaces {
			*lines = append(*lines, row.label, "No retained connections on this interface yet.", "Select another interface or wait for new traffic.", "")
		} else if u.mode == viewPID && row.pidID.PID > 0 {
			where := u.interfaceName
			if u.hostScope {
				where = "captured host interfaces"
			}
			*lines = append(*lines, row.label, fmt.Sprintf("PID socket I/O in whole netns: RX %sB TX %sB", human(row.rx), human(row.tx)),
				"No matching connection on "+where+". It may predate capture.", "")
		} else {
			*lines = append(*lines, row.label, "Connection detail is no longer retained; bytes remain in session totals.", "", "")
		}
		return
	}
	tabs := make([]string, len(tabNames))
	position := 0
	for i, name := range tabNames {
		tabs[i] = name
		if i == u.tab {
			tabs[i] = "[" + name + "]"
		}
		u.tabHits[i] = hitSpan{position, position + utf8.RuneCountInString(tabs[i])}
		position += utf8.RuneCountInString(tabs[i]) + 2
	}
	*lines = append(*lines, strings.Join(tabs, "  ")+"   "+row.label)
	switch u.tab {
	case 0:
		if u.mode != viewPID && (u.flowSort.key == "PID RX" || u.flowSort.key == "PID TX") {
			u.flowSort = sortSpec{}
		}
		sortFlows(row.flows, row, u.flowSort)
		if u.selectedFlowRef != nil {
			if index := slices.Index(row.flows, u.selectedFlowRef); index >= 0 {
				u.selectedFlow = index
			}
		}
		u.selectedFlow = min(u.selectedFlow, len(row.flows)-1)
		u.selectedFlowRef = row.flows[u.selectedFlow]
		u.flowOrder = slices.Clone(row.flows)
		layout := connectionLayout(row, u.mode)
		u.detailLayout = layout
		u.detailCanvas = layout.width
		u.detailX = min(u.detailX, max(0, layout.width-u.screenWidth))
		*lines = append(*lines, scrollTableLine(layout.sortedHeader(u.flowSort), u.detailX, u.screenWidth))
		visible := max(1, u.bottomHeight-7) // Rows plus tabs, header, APP, TCP, name and EVIDENCE lines.
		start := min(u.flowStart, max(0, len(row.flows)-visible))
		if u.selectedFlow < start {
			start = u.selectedFlow
		} else if u.selectedFlow >= start+visible {
			start = u.selectedFlow - visible + 1
		}
		u.flowStart = start
		u.flowCount = min(visible, len(row.flows)-start)
		for i := start; i < start+u.flowCount; i++ {
			f := row.flows[i]
			cursor := " "
			if u.focusBottom && i == u.selectedFlow {
				cursor = "▸"
			}
			*lines = append(*lines, scrollTableLine(connectionLine(layout, f, row, u.mode, cursor), u.detailX, u.screenWidth))
		}
		selected := row.flows[u.selectedFlow]
		app, source := selected.AppProtocol, selected.AppSource
		if app == "" {
			app, source = "unknown", "no observed signature"
		}
		retx, retxSource := retransmits(selected)
		rtt, rttSource := flowRTT(selected)
		appLine := fmt.Sprintf("APP %s (%s)  RTT %s", app, source, formatSYNRTT(rtt))
		if rttSource != "" {
			appLine += " (" + rttSource + ")"
		}
		appLine += fmt.Sprintf("  RETX %d (%s)", retx, retxSource)
		if selected.DomainConflict {
			appLine += "  DOMAIN CONFLICT"
		}
		if len(selected.TLSActors) > 0 {
			appLine += fmt.Sprintf("  OpenSSL PID %d", slices.SortedFunc(maps.Keys(selected.TLSActors), func(a, b processID) int { return a.PID - b.PID })[0].PID)
		}
		*lines = append(*lines, appLine)
		tcpLine := "TCP -"
		if detail := kernelDetail(selected); detail != "" {
			tcpLine = "TCP " + detail
		}
		*lines = append(*lines, tcpLine)
		*lines = append(*lines, fmt.Sprintf("%s  origin PID %s  target PID %s  first %s  last %s", flowName(selected), formatPIDBrief(selected.Client), formatPIDBrief(selected.Server), displayTime(selected.First), displayTime(selected.Last)))
		*lines = append(*lines, evidenceLine(selected, c))
		if u.mode == viewPID && row.pidID.PID > 0 {
			packetLabel := "connection IP"
			if u.hostScope {
				packetLabel = "single-point observed IP"
			}
			if io, ok := selected.IO[row.pidID]; ok {
				*lines = append(*lines, fmt.Sprintf("Selected PID socket I/O RX %sB TX %sB; %s RX %sB TX %sB", human(io.RX), human(io.TX), packetLabel, human(selected.RX), human(selected.TX)))
			} else {
				*lines = append(*lines, fmt.Sprintf("Selected PID socket I/O unavailable; %s RX %sB TX %sB", packetLabel, human(selected.RX), human(selected.TX)))
			}
			return
		}
		for _, id := range slices.SortedFunc(maps.Keys(selected.IO), func(a, b processID) int { return a.PID - b.PID }) {
			io := selected.IO[id]
			p := participant{PID: id.PID, StartNS: id.StartNS, Name: c.pidIO[id].Name}
			*lines = append(*lines, fmt.Sprintf("socket I/O PID %s RX %sB TX %sB", formatPIDBrief(p), human(io.RX), human(io.TX)))
			if len(*lines) >= 9 {
				break
			}
		}
	case 1:
		seen := make(map[processID]participant)
		if u.mode == viewPID && row.pidID.PID > 0 {
			seen[row.pidID] = participant{PID: row.pidID.PID, StartNS: row.pidID.StartNS, Name: c.pidIO[row.pidID].Name}
		}
		for _, f := range row.flows {
			if f.Client.PID > 0 {
				seen[f.Client.id()] = f.Client
			}
			if f.Server.PID > 0 {
				seen[f.Server.id()] = f.Server
			}
			for id := range f.IO {
				seen[id] = participant{PID: id.PID, StartNS: id.StartNS, Name: c.pidIO[id].Name}
			}
			for id, actor := range f.TLSActors {
				seen[id] = actor
			}
		}
		for id, p := range seen {
			// A service row lists its own processes, not their peers.
			if key, _ := u.processes.group(id, p.Name, u.grouping); u.mode == viewService && key != row.key || !u.scope.process(id, p.Name) {
				delete(seen, id)
			}
		}
		for id, name := range row.members {
			seen[id] = participant{PID: id.PID, StartNS: id.StartNS, Name: name}
		}
		if len(seen) == 0 {
			*lines = append(*lines, "PID unknown: no matching local socket event")
			return
		}
		processes := slices.Collect(maps.Values(seen))
		distinguishProcessNames(processes)
		sortProcesses(processes, c, u.processSort, func(id processID) int {
			if m := u.processes.meta(id); m != nil {
				return m.Parent.PID
			}
			return 0
		})
		var depths map[processID]int
		if u.mode == viewService && u.processSort.key == "" {
			processes, depths = u.processes.treeOrder(processes)
		}
		if u.selectedProcessID.PID > 0 {
			if index := slices.IndexFunc(processes, func(p participant) bool { return p.id() == u.selectedProcessID }); index >= 0 {
				u.selectedProcess = index
			}
		}
		u.selectedProcess = min(u.selectedProcess, len(processes)-1)
		u.selectedProcessID = processes[u.selectedProcess].id()
		u.processOrder = slices.Clone(processes)
		visible := min(len(processes), max(1, min(4, u.bottomHeight/4)))
		start := max(0, u.selectedProcess-visible+1)
		u.processListStart, u.processListCount, u.processTotal = start, visible, len(processes)
		layout := processLayout(processes, depths)
		u.detailLayout = layout
		processLines := []string{layout.sortedHeader(u.processSort)}
		for i := start; i < start+visible; i++ {
			p := processes[i]
			io, observed := c.pidIO[p.id()]
			cursor := " "
			if u.focusBottom && i == u.selectedProcess {
				cursor = "▸"
			}
			var parent processID
			if m := u.processes.meta(p.id()); m != nil {
				parent = m.Parent
			}
			processLines = append(processLines, processLine(layout, p, parent, depths[p.id()], io, observed, cursor))
		}
		p := processes[u.selectedProcess]
		if u.processInfoID != p.id() || time.Since(u.processInfoAt) >= 2*time.Second {
			if u.processInfoID != p.id() {
				u.processEnvScroll = 0
			}
			u.processInfoID, u.processInfo, u.processInfoAt = p.id(), readProcessDetails(p.id()), time.Now()
		}
		info := u.processInfo
		detailLines := make([]string, 0, 8)
		if info.errorText != "" {
			detailLines = append(detailLines, "PROCESS DETAILS: "+info.errorText)
		} else {
			cgroup := u.processes.cgroupOf(u.processes.meta(p.id()))
			_, service := serviceOf(cgroup)
			detailLines = append(detailLines,
				fmt.Sprintf("STARTED %s   PARENT PID %d", info.started, info.parentPID),
				"EXECUTABLE "+info.executable,
				"WORKDIR    "+info.workingDir,
				"COMMAND    "+info.command,
				"CGROUP     "+cgroup+"  ("+service+")",
			)
			detailLines = append(detailLines, "") // Filled after the visible environment range is known.
		}
		u.processEnvTotal = len(info.environment)
		u.processEnvCount = min(u.processEnvTotal, max(0, u.bottomHeight-1-len(processLines)-len(detailLines)))
		u.processEnvScroll = min(u.processEnvScroll, max(0, u.processEnvTotal-u.processEnvCount))
		if info.errorText == "" {
			label := fmt.Sprintf("ENVIRONMENT (exec snapshot) %d-%d/%d; PgUp/PgDn or wheel", min(u.processEnvTotal, u.processEnvScroll+1), u.processEnvScroll+u.processEnvCount, u.processEnvTotal)
			if info.truncated {
				label += " [truncated at 2 MiB]"
			}
			detailLines[len(detailLines)-1] = label
		}
		u.detailCanvas = layout.width
		for _, line := range detailLines {
			u.detailCanvas = max(u.detailCanvas, utf8.RuneCountInString(line))
		}
		for _, line := range info.environment {
			u.detailCanvas = max(u.detailCanvas, utf8.RuneCountInString(line)+2)
		}
		u.detailX = min(u.detailX, max(0, u.detailCanvas-u.screenWidth))
		for _, line := range processLines {
			*lines = append(*lines, scrollTableLine(line, u.detailX, u.screenWidth))
		}
		for _, line := range detailLines {
			*lines = append(*lines, scrollLine(line, u.detailX, u.screenWidth))
		}
		u.processEnvY = len(*lines)
		for _, entry := range info.environment[u.processEnvScroll:min(len(info.environment), u.processEnvScroll+u.processEnvCount)] {
			*lines = append(*lines, scrollLine("  "+entry, u.detailX, u.screenWidth))
		}
	}
}

func fit(line string, width int) string {
	runes := []rune(line)
	if len(runes) > width {
		return string(runes[:width])
	}
	return line
}

func human(n uint64) string {
	switch {
	case n >= 1<<30:
		return strconv.FormatFloat(float64(n)/float64(1<<30), 'f', 1, 64) + "G"
	case n >= 1<<20:
		return strconv.FormatFloat(float64(n)/float64(1<<20), 'f', 1, 64) + "M"
	case n >= 1<<10:
		return strconv.FormatFloat(float64(n)/float64(1<<10), 'f', 1, 64) + "K"
	default:
		return strconv.FormatUint(n, 10)
	}
}

func sortName(byRate bool) string {
	if byRate {
		return "rate"
	}
	return "bytes"
}
