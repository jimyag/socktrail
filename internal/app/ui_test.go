package app

import (
	"net/netip"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/charmbracelet/x/ansi"
	"github.com/jimyag/socktrail/internal/capture"
	"github.com/jimyag/socktrail/internal/domain"
	"github.com/jimyag/socktrail/internal/geoip"
	"github.com/jimyag/socktrail/internal/probe"
)

func TestQuitFromEveryUIState(t *testing.T) {
	for _, state := range []struct {
		name string
		key  string
	}{
		{name: "main"},
		{name: "help", key: "?"},
		{name: "status", key: "!"},
	} {
		t.Run(state.name, func(t *testing.T) {
			u := &terminalUI{}
			if state.key != "" {
				u.handleKey(state.key)
			}
			if !u.handleKey("q") {
				t.Fatal("q did not exit on the first press")
			}
		})
	}
}

func TestGeoAndGroupingKeys(t *testing.T) {
	dir := t.TempDir()
	geo := geoip.Open(dir)
	defer geo.Close()
	u := &terminalUI{mode: viewService, geo: geo, geoDir: dir}
	u.handleKey("b")
	if u.grouping != byCgroup {
		t.Fatalf("b did not cycle service grouping: %v", u.grouping)
	}
	u.handleKey("g")
	if !u.geoPrompt || u.geoDownload {
		t.Fatal("g did not offer download for missing databases")
	}
	u.handleKey("s")
	if u.sortRate {
		t.Fatal("download prompt let a table key through")
	}
	u.handleKey("esc")
	if u.geoPrompt {
		t.Fatal("Esc did not cancel download prompt")
	}
	u.handleKey("s")
	if !u.sortRate {
		t.Fatal("s no longer switches the existing rate sort")
	}
	u.handleKey("g")
	u.handleKey("enter")
	if u.geoPrompt || !u.geoDownload || !u.geoLoading {
		t.Fatal("Enter did not request a background download")
	}
	if !u.handleKey("q") {
		t.Fatal("q did not quit during a GeoIP download")
	}
}

func TestGeoColumnsMatchBothEndpoints(t *testing.T) {
	columns := connectionLayout(&uiRow{}, viewPID, &collector{}, true).columns
	if columns[3].title != "SOURCE" || columns[4].title != "SRC GEO" || columns[5].title != "TARGET" || columns[6].title != "DST GEO" {
		t.Fatalf("GeoIP columns do not follow their addresses: %+v", columns[:7])
	}
	if got := geoCell(&geoip.Location{CountryCode: "US", ASN: 15169, Organization: "Google LLC"}); got != "🇺🇸 AS15169 Google LLC" {
		t.Fatalf("GeoIP cell = %q", got)
	}
	if got := geoCell(&geoip.Location{CountryCode: "AU", ASN: 13335, Organization: "Cloudflare, Inc."}); got != "🇦🇺 AS13335 Cloudflare" {
		t.Fatalf("GeoIP organization was not shortened: %q", got)
	}
	if got := geoCell(&geoip.Location{CountryCode: "DE", ASN: 4294967295, Organization: "A very long organization name"}); displayWidth(got) > 25 {
		t.Fatalf("GeoIP cell overflows its column: %q", got)
	}
	if got := geoCell(nil); got != "-" {
		t.Fatalf("missing GeoIP cell = %q", got)
	}
}

func TestTargetConnectLatencyPercentiles(t *testing.T) {
	flows := make([]*flow, 20)
	for i := range flows {
		flows[i] = &flow{}
		flows[i].Health.ConnectLatency = uint32(20-i) * 1000 // Unsorted milliseconds.
	}
	failed := &flow{}
	failed.Health.ConnectLatency = 3_000_000
	failed.Health.ConnectResult = 110
	flows = append(flows, failed)
	if p50, p95 := connectLatencyPercentiles(flows); p50 != "10ms" || p95 != "19ms" {
		t.Fatalf("destination connect latency = %s/%s, want 10ms/19ms", p50, p95)
	}
	if p50, p95 := connectLatencyPercentiles([]*flow{failed}); p50 != "-" || p95 != "-" {
		t.Fatalf("failed attempts changed successful latency = %s/%s", p50, p95)
	}
	columns := groupLayout([]*uiRow{{label: "127.0.0.1", flows: flows}}, viewTarget, 180).columns
	if columns[12].title != "CONN50" || columns[13].title != "CONN95" {
		t.Fatalf("destination latency columns missing: %+v", columns)
	}
}

func BenchmarkTargetConnectLatencyPercentiles(b *testing.B) {
	flows := make([]*flow, 5000)
	for i := range flows {
		flows[i] = &flow{}
		flows[i].Health.ConnectLatency = uint32((i*7919)%5000 + 1)
	}
	b.ReportAllocs()
	for b.Loop() {
		connectLatencyPercentiles(flows)
	}
}

// A filter can name QUIC or a qq.com host; Ctrl-C still quits from it.
func TestFilterTakesQAsText(t *testing.T) {
	u := &terminalUI{}
	u.handleKey("/")
	for _, key := range []string{"q", "u", "i", "c"} {
		if u.handleKey(key) {
			t.Fatalf("%q quit while typing a filter", key)
		}
	}
	if u.filter != "quic" || !u.handleKey("quit") {
		t.Fatalf("filter %q, or Ctrl-C did not quit", u.filter)
	}
}

func TestPageKeysMoveFocusedTableByVisibleRows(t *testing.T) {
	u := &terminalUI{
		dividerY:     9,
		mainLabels:   []string{"0", "1", "2", "3", "4", "5", "6", "7", "8", "9", "10", "11"},
		bottomHeight: 12,
		flowOrder:    make([]*flow, 20),
	}
	u.handleKey("pagedown")
	if u.selected != 5 || u.selectedGroup != "5" || u.scroll != 5 {
		t.Fatalf("main table did not advance one visible page: selected=%d group=%q scroll=%d", u.selected, u.selectedGroup, u.scroll)
	}
	u.handleKey("pageup")
	if u.selected != 0 {
		t.Fatalf("main table did not return to first row: %d", u.selected)
	}
	u.focusBottom = true
	u.handleKey("pagedown")
	if u.selectedFlow != 8 || u.flowStart != 8 {
		t.Fatalf("connection table did not advance one visible page: selected=%d start=%d", u.selectedFlow, u.flowStart)
	}
	u.handleKey("pageup")
	if u.selectedFlow != 0 {
		t.Fatalf("connection table did not return to first row: %d", u.selectedFlow)
	}
	u.tab, u.processEnvCount, u.processEnvTotal = 1, 5, 20
	u.handleKey("pagedown")
	if u.processEnvScroll != 5 {
		t.Fatalf("process environment did not advance one page: %d", u.processEnvScroll)
	}
}

func TestTabFollowsFocusedArea(t *testing.T) {
	u := &terminalUI{mode: viewPID, hostScope: true, interfaces: []string{"eth0", "lo"}, interfaceName: "eth0"}
	for _, want := range []viewMode{viewSource, viewTarget, viewProtocol, viewService, viewLog, viewDomain, viewInterfaces, viewDomain, viewDomain, viewPID} {
		u.handleKey("tab")
		if u.mode != want || u.focusBottom {
			t.Fatalf("top Tab: mode=%v, focusBottom=%t; want mode=%v", u.mode, u.focusBottom, want)
		}
	}
	if u.hostScope {
		t.Fatal("top Tab did not reach per-interface scope")
	}
	u.handleKey("enter")
	if !u.focusBottom || u.tab != 0 {
		t.Fatalf("Enter did not focus connections: focusBottom=%t tab=%d", u.focusBottom, u.tab)
	}
	u.handleKey("tab")
	if !u.focusBottom || u.tab != 1 || u.mode != viewPID {
		t.Fatalf("bottom Tab did not select processes: focusBottom=%t tab=%d mode=%v", u.focusBottom, u.tab, u.mode)
	}
	u.handleKey("shift-tab")
	if !u.focusBottom || u.tab != 0 {
		t.Fatalf("bottom Shift+Tab did not return to connections: focusBottom=%t tab=%d", u.focusBottom, u.tab)
	}
	u.handleKey("enter")
	u.handleKey("tab")
	if u.focusBottom || u.mode != viewSource {
		t.Fatalf("Enter did not return to top pages: focusBottom=%t mode=%v", u.focusBottom, u.mode)
	}
	u.handleKey("4")
	u.handleKey("tab")
	if u.mode != viewService {
		t.Fatalf("top Tab ignored a direct page selection: mode=%v", u.mode)
	}
	single := &terminalUI{mode: viewInterfaces, returnMode: viewPID, hostScope: true, interfaces: []string{"lo"}, topTabIndex: 7}
	single.handleKey("tab") // a overview
	single.handleKey("tab") // Skip unavailable i and wrap to PID.
	if single.mode != viewPID || !single.hostScope {
		t.Fatalf("single-interface Tab did not skip i: mode=%v hostScope=%t", single.mode, single.hostScope)
	}
	single.handleKey("shift-tab")
	if single.mode != viewInterfaces {
		t.Fatalf("single-interface Shift+Tab did not skip i and a: mode=%v", single.mode)
	}
	reverse := &terminalUI{mode: viewPID, hostScope: true, interfaces: []string{"eth0", "lo"}, interfaceName: "eth0"}
	reverse.handleKey("shift-tab") // i per interface
	if reverse.mode != viewPID || reverse.hostScope {
		t.Fatalf("Shift+Tab did not wrap to interface scope: mode=%v hostScope=%t", reverse.mode, reverse.hostScope)
	}
	reverse.handleKey("shift-tab") // a overview
	if !reverse.hostScope {
		t.Fatal("Shift+Tab did not return to overview")
	}
	reverse.handleKey("shift-tab") // 0 IFACES
	if reverse.mode != viewInterfaces {
		t.Fatalf("Shift+Tab did not reach previous page: mode=%v", reverse.mode)
	}
}

func TestLogPageGroupsRecentChanges(t *testing.T) {
	now := time.Now()
	a := netip.MustParseAddrPort("192.0.2.1:40000")
	b := netip.MustParseAddrPort("198.51.100.1:443")
	f := &flow{Key: keyFor(a, b, 6), Client: participant{PID: 42, StartNS: 1, Name: "curl"}, Direction: "outbound"}
	state := &hostViewState{recentChanges: []flowChange{{ID: 1, Flow: f, Changes: []string{"new"}, At: now}}}
	u := &terminalUI{mode: viewPID, hostScope: true, hostState: state}
	u.handleKey("6")
	if u.mode != viewLog || !u.hostScope {
		t.Fatalf("6 did not open the merged LOG page: mode=%v scope=%t", u.mode, u.hostScope)
	}
	c := &collector{}
	if rows := u.rows(c, viewLog); len(rows) != 1 || rows[0].label != "new" || rows[0].lastEvent != now {
		t.Fatalf("LOG change groups = %+v", rows)
	}
	u.handleKey("b")
	if rows := u.rows(c, viewLog); len(rows) != 1 || rows[0].label != "42(curl)" {
		t.Fatalf("LOG process groups = %+v", rows)
	}
}

func TestDomainLocalAddressesFitWithRemainder(t *testing.T) {
	row := &uiRow{localAddresses: map[netip.Addr]struct{}{
		netip.MustParseAddr("10.0.0.1"): {},
		netip.MustParseAddr("10.0.0.2"): {},
		netip.MustParseAddr("10.0.0.3"): {},
	}}
	if got := localAddressCell(row, 38); got != "10.0.0.1,10.0.0.2,+1" {
		t.Fatalf("LOCAL column = %q", got)
	}
	if got := localAddressCell(row, 14); got != "10.0.0.1,+2" {
		t.Fatalf("narrow LOCAL column = %q", got)
	}
}

func TestSharedPIDAndMultipleHostsDoNotDuplicateBytes(t *testing.T) {
	src := netip.MustParseAddrPort("127.0.0.1:51000")
	dst := netip.MustParseAddrPort("127.0.0.1:8080")
	f := &flow{
		Key: keyFor(src, dst, 6), RX: 80, TX: 120,
		Initiator: src, Target: dst,
		Client: participant{PID: 101, StartNS: 1000, Name: "client"},
		Server: participant{PID: 202, StartNS: 2000, Name: "server"},
		Domain: domain.New(1),
	}
	f.Domain.Add(1, []byte("GET / HTTP/1.1\r\nHost: a.example.test\r\n\r\nGET / HTTP/1.1\r\nHost: b.example.test\r\n\r\n"))
	c := &collector{flows: map[flowKey]*flow{f.Key: f}}
	u := &terminalUI{rates: make(map[*flow]rate)}
	var pidBytes uint64
	var participantRows int
	for _, row := range u.rows(c, viewPID) {
		pidBytes += row.rx + row.tx
		if row.label == "101 client" || row.label == "202 server" {
			participantRows++
			if len(row.flows) != 1 || row.rx+row.tx != 0 {
				t.Fatalf("shared PID row duplicated bytes: %+v", row)
			}
		}
	}
	if pidBytes != 0 || participantRows != 2 {
		t.Fatalf("PID groups: bytes=%d participant rows=%d", pidBytes, participantRows)
	}
	domains := u.rows(c, viewDomain)
	if len(domains) != 1 || domains[0].label != "HTTP multiple Hosts" || domains[0].rx+domains[0].tx != 200 || domains[0].reqs != 2 {
		t.Fatalf("domain groups duplicated bytes or lost Host counts: %+v", domains)
	}
}

func TestHostViewIsDefaultAndInterfaceViewIsOptional(t *testing.T) {
	u := &terminalUI{mode: viewPID, returnMode: viewPID, hostScope: true, interfaces: []string{"br0", "dae0"}, interfaceName: "br0"}
	u.handleKey("0")
	if u.mode != viewInterfaces || !u.hostScope {
		t.Fatalf("interface diagnostics did not open from host view: mode=%d host=%v", u.mode, u.hostScope)
	}
	u.selectedGroup = "iface:dae0"
	u.handleKey("enter")
	if u.mode != viewPID || u.hostScope || u.interfaceName != "dae0" {
		t.Fatalf("interface detail did not open: mode=%d host=%v interface=%s", u.mode, u.hostScope, u.interfaceName)
	}
	u.handleKey("a")
	if u.mode != viewPID || !u.hostScope {
		t.Fatalf("host view was not restored: mode=%d host=%v", u.mode, u.hostScope)
	}
}

func TestProcessTabAvailableForPIDWithoutCapturedFlow(t *testing.T) {
	id := processID{PID: 99999999, StartNS: 1000}
	c := &collector{pidIO: map[processID]processIO{id: {Name: "exited"}}}
	u := &terminalUI{mode: viewPID, tab: 1, screenWidth: 100, bottomHeight: 20}
	var lines []string
	u.renderBottom(&lines, u.rows(c, viewPID), c)
	shown := strings.Join(lines, "\n")
	plain := ansi.Strip(shown)
	if !strings.Contains(shown, styleBar.paint(" process ")) || !strings.Contains(plain, "99999999") || !strings.Contains(plain, "PROCESS DETAILS:") {
		t.Fatalf("PID without selected-interface flow has no process detail: %s", shown)
	}
}

func TestObservedDomainHintUsesCapturedFlowEvidence(t *testing.T) {
	row := &uiRow{}
	if got := observedDomainHint(row); got != "-" {
		t.Fatalf("PID I/O without a captured flow reported a domain: %q", got)
	}

	httpFlow := &flow{Domain: domain.New(1)}
	httpFlow.Domain.Add(1, []byte("GET / HTTP/1.1\r\nHost: api.example.test\r\n\r\n"))
	row.flows = []*flow{httpFlow}
	if got := observedDomainHint(row); got != "HTTP api.example.test" {
		t.Fatalf("captured Host is missing from group hint: %q", got)
	}
}

func TestResponsiveTablesKeepFullEndpointsAndDomain(t *testing.T) {
	source := netip.MustParseAddrPort("[2001:db8:1111:2222:3333:4444:5555:6666]:51000")
	target := netip.MustParseAddrPort("[2001:db8:aaaa:bbbb:cccc:dddd:eeee:ffff]:443")
	host := "a-very-long-service-name-for-the-responsive-terminal.example.test"
	f := &flow{Key: keyFor(source, target, 6), Initiator: source, Target: target, Direction: "outbound", TCPState: "established", Domain: domain.New(1)}
	f.Domain.Add(1, []byte("GET / HTTP/1.1\r\nHost: "+host+"\r\n\r\n"))
	row := &uiRow{label: "101 client", pidID: processID{101, 1000}, flows: []*flow{f}}
	mainWide := groupLayout([]*uiRow{row}, viewPID, 300)
	if len([]rune(mainWide.header())) != 300 {
		t.Fatalf("wide main table did not fill viewport: %d", len([]rune(mainWide.header())))
	}
	mainNarrow := groupLayout([]*uiRow{row}, viewPID, 79)
	if got := groupLine(mainNarrow, row, viewPID, "▸"); !strings.HasSuffix(strings.TrimSpace(got), "+1") {
		t.Fatalf("narrow layout did not count the hidden domain: %q", got)
	}
	detail := connectionLayout(row, viewPID, &collector{}, false)
	line := connectionLine(detail, f, row, viewPID, &collector{}, nil, false, "▸")
	if !strings.Contains(line, source.String()) || !strings.Contains(line, target.String()) || !strings.Contains(line, host) {
		t.Fatalf("connection layout truncated IPv6 endpoints or Host: %q", line)
	}
	var recovered strings.Builder
	for offset := 0; offset < len([]rune(line)); offset += 79 {
		recovered.WriteString(scrollLine(line, offset, 79))
	}
	if recovered.String() != line {
		t.Fatal("horizontal scroll could not reveal every connection column")
	}
	if got := scrollTableLine("▸ABCDEF", 3, 4); got != "▸DEF" {
		t.Fatalf("horizontal scrolling lost the selected-row marker: %q", got)
	}
}

func TestGroupColumnsExpandWhenViewportFits(t *testing.T) {
	previous := captureInterfaces
	captureInterfaces = []string{"eth0", "br0", "veth123"}
	t.Cleanup(func() { captureInterfaces = previous })

	first := &flow{Domain: domain.New(1)}
	first.Domain.Add(1, []byte("GET / HTTP/1.1\r\nHost: api.example.test\r\n\r\n"))
	second := &flow{Domain: domain.New(1)}
	second.Domain.Add(1, []byte("GET / HTTP/1.1\r\nHost: web.example.test\r\n\r\n"))
	row := &uiRow{label: "101 client", flows: []*flow{first, second}}
	for index := range captureInterfaces {
		row.ifaces.add(index)
	}

	wide := groupLayout([]*uiRow{row}, viewPID, 300)
	if got := groupLine(wide, row, viewPID, "▸"); !strings.Contains(got, "eth0,br0,veth123") || !strings.Contains(got, "HTTP api.example.test, HTTP web.example.test") {
		t.Fatalf("wide table kept folded values: %q", got)
	}
	narrow := groupLayout([]*uiRow{row}, viewPID, 100)
	if got := groupLine(narrow, row, viewPID, "▸"); !strings.Contains(got, "eth0,br0 +1") || !strings.Contains(got, "HTTP api.example.test +1") {
		t.Fatalf("narrow table lost compact values: %q", got)
	}

	first.Initiator, first.Target = netip.MustParseAddrPort("192.0.2.1:5000"), netip.MustParseAddrPort("192.0.2.2:443")
	second.Initiator, second.Target = netip.MustParseAddrPort("192.0.2.3:5001"), netip.MustParseAddrPort("192.0.2.4:443")
	domainWide := groupLayout([]*uiRow{row}, viewDomain, 300)
	if got := groupLine(domainWide, row, viewDomain, "▸"); !strings.Contains(got, "192.0.2.1 → 192.0.2.2") || !strings.Contains(got, "192.0.2.3 → 192.0.2.4") {
		t.Fatalf("wide domain page kept only one peer: %q", got)
	}
}

func TestGroupHintsFitAsManyAsPossibleWithRemainder(t *testing.T) {
	row := &uiRow{label: "101 client"}
	var names []string
	for i := range 7 {
		name := "service-" + strconv.Itoa(i) + ".example.test"
		names = append(names, "HTTP "+name)
		f := &flow{Domain: domain.New(1)}
		f.Domain.Add(1, []byte("GET / HTTP/1.1\r\nHost: "+name+"\r\n\r\n"))
		row.flows = append(row.flows, f)
	}
	want := strings.Join(names[:5], ", ") + " +2"
	hintWidth := displayWidth(want)
	base := groupLayout([]*uiRow{row}, viewPID, 0)
	viewport := base.width + hintWidth - base.columns[len(base.columns)-1].width
	layout := groupLayout([]*uiRow{row}, viewPID, viewport)
	got := groupLine(layout, row, viewPID, "▸")
	if !strings.Contains(got, want) || strings.Contains(got, names[5]) {
		t.Fatalf("expected five visible domains and +2: %q", got)
	}
	if displayWidth(got) != viewport || displayWidth(fitItems(names, ", ", hintWidth)) > hintWidth {
		t.Fatalf("group row or +N exceeded viewport %d: %q", viewport, got)
	}
}

func TestGroupColumnFitsCurrentPageContent(t *testing.T) {
	short := &uiRow{label: "123 curl"}
	long := &uiRow{label: "456 worker-with-long-name"}
	for _, viewport := range []int{120, 300} {
		shortLayout := groupLayout([]*uiRow{short}, viewPID, viewport)
		longLayout := groupLayout([]*uiRow{long}, viewPID, viewport)
		if got := shortLayout.columns[0].width; got != displayWidth(short.label) {
			t.Errorf("viewport %d: short PID GROUP width = %d, want %d", viewport, got, displayWidth(short.label))
		}
		if got := longLayout.columns[0].width; got != displayWidth(long.label) {
			t.Errorf("viewport %d: long PID GROUP width = %d, want %d", viewport, got, displayWidth(long.label))
		}
		if shortLayout.width < viewport || longLayout.width < viewport {
			t.Errorf("viewport %d: table did not fill the terminal", viewport)
		}
	}
}

func TestPIDSocketIOIsSeparateFromPacketBytes(t *testing.T) {
	a := netip.MustParseAddrPort("127.0.0.1:51000")
	b := netip.MustParseAddrPort("127.0.0.1:8080")
	f := &flow{Key: keyFor(a, b, 6), RX: 180, TX: 220}
	c := &collector{flows: map[flowKey]*flow{f.Key: f}, maxFlows: 10}
	c.event(probe.Event{Protocol: 6, Operation: "send", AppBytes: 100, Role: "out", PID: 101, StartNS: 1000, Process: "client", Local: a, Remote: b})
	c.event(probe.Event{Protocol: 6, Operation: "recv", AppBytes: 70, Role: "in", PID: 202, StartNS: 2000, Process: "server", Local: b, Remote: a})
	rows := (&terminalUI{}).rows(c, viewPID)
	if len(rows) != 2 || c.pidIO[processID{101, 1000}].TX != 100 || c.pidIO[processID{202, 2000}].RX != 70 {
		t.Fatalf("PID I/O was not attributed to executing processes: rows=%+v totals=%+v", rows, c.pidIO)
	}
	var socketBytes uint64
	for _, row := range rows {
		socketBytes += row.rx + row.tx
		if len(row.flows) != 1 {
			t.Fatalf("PID lost connection link: %+v", row)
		}
	}
	if socketBytes != 170 || f.RX+f.TX != 400 || f.Client.PID != 0 || f.Server.PID != 0 {
		t.Fatalf("socket bytes mixed with wire bytes or I/O guessed connection roles: socket=%d flow=%+v", socketBytes, f)
	}
}

func TestPIDFilterSelectsOnlyThatProcess(t *testing.T) {
	a := netip.MustParseAddrPort("127.0.0.1:51000")
	b := netip.MustParseAddrPort("127.0.0.1:8080")
	f := &flow{Key: keyFor(a, b, 6), Client: participant{PID: 101, StartNS: 1000, Name: "client"}, Server: participant{PID: 202, StartNS: 2000, Name: "server"}}
	c := &collector{flows: map[flowKey]*flow{f.Key: f}}
	rows := (&terminalUI{filter: "101"}).rows(c, viewPID)
	if len(rows) != 1 || rows[0].pidID != (processID{101, 1000}) {
		t.Fatalf("numeric PID filter included another participant: %+v", rows)
	}
}

func TestPIDConnectionDetailUsesSelectedProcessIO(t *testing.T) {
	client := processID{101, 1000}
	server := processID{202, 2000}
	a := netip.MustParseAddrPort("127.0.0.1:51000")
	b := netip.MustParseAddrPort("127.0.0.1:8080")
	f := &flow{
		Key: keyFor(a, b, 6), Initiator: a, Target: b, RX: 80, TX: 120,
		Client: participant{PID: client.PID, StartNS: client.StartNS, Name: "client"},
		Server: participant{PID: server.PID, StartNS: server.StartNS, Name: "server"},
		IO:     map[processID]ioBytes{client: {RX: 10, TX: 20}, server: {RX: 30, TX: 40}},
	}
	row := &uiRow{label: "101 client", pidID: client, flows: []*flow{f}}
	u := &terminalUI{mode: viewPID}
	var lines []string
	u.renderBottom(&lines, []*uiRow{row}, &collector{})
	detail := ansi.Strip(strings.Join(lines, "\n"))
	if !strings.Contains(detail, "Selected PID socket I/O RX 10B TX 20B; connection IP RX 80B TX 120B") || strings.Contains(detail, "socket I/O PID 202") {
		t.Fatalf("connection detail did not isolate selected PID I/O: %s", detail)
	}
}

func TestSocketIOEventBeforePacketAttachesOnce(t *testing.T) {
	a := netip.MustParseAddrPort("127.0.0.1:51000")
	b := netip.MustParseAddrPort("127.0.0.1:8080")
	c := &collector{flows: make(map[flowKey]*flow), maxFlows: 10}
	id := processID{PID: 101, StartNS: 1000}
	c.event(probe.Event{Protocol: 6, Operation: "send", AppBytes: 79, Role: "out", PID: id.PID, StartNS: id.StartNS, Process: "curl", Local: a, Remote: b})
	if c.pendingIOCount != 1 || c.pidIO[id].TX != 79 {
		t.Fatalf("early I/O not retained: pending=%d pid=%+v", c.pendingIOCount, c.pidIO[id])
	}
	c.packet(capture.Packet{Source: a, Destination: b, Protocol: 6, SYN: true, TCPSeq: 100, IPBytes: 40})
	f := c.flows[keyFor(a, b, 6)]
	if f.IO[id].TX != 79 || c.ioUnmatched != 0 || c.pendingIOCount != 0 || c.pidIO[id].TX != 79 {
		t.Fatalf("pending I/O was lost or doubled: flow=%+v pid=%+v unmatched=%d pending=%d", f.IO, c.pidIO[id], c.ioUnmatched, c.pendingIOCount)
	}
}

func TestInterfaceSelectionDoesNotMergeCapturedFlows(t *testing.T) {
	var names interfaceFlags
	if err := names.Set("lo,br0"); err != nil {
		t.Fatal(err)
	}
	if err := names.Set("lo"); err == nil {
		t.Fatal("duplicate interface was accepted")
	}
	a := netip.MustParseAddrPort("127.0.0.1:51000")
	b := netip.MustParseAddrPort("127.0.0.1:8080")
	lo := &collector{flows: make(map[flowKey]*flow), maxFlows: 10, loopback: true}
	bridge := &collector{flows: make(map[flowKey]*flow), maxFlows: 10}
	lo.packet(capture.Packet{Source: a, Destination: b, Protocol: 6, IPBytes: 40})
	u := &terminalUI{interfaces: names, interfaceName: "lo", rates: make(map[*flow]rate)}
	if len(u.rows(lo, viewProtocol)) != 1 || len(u.rows(bridge, viewProtocol)) != 0 {
		t.Fatal("interface flows were merged")
	}
	u.handleKey("i")
	if u.interfaceName != "br0" {
		t.Fatalf("interface switch selected %q", u.interfaceName)
	}
	u.hostScope = true
	if u.handleKey("i"); u.hostScope || u.interfaceName != "br0" {
		t.Fatalf("i from the overview opened %q, not the current interface", u.interfaceName)
	}
}

func TestInterfaceOverviewKeepsEachInterfaceSeparate(t *testing.T) {
	var names interfaceFlags
	if err := names.Set("lo,br0"); err != nil {
		t.Fatal(err)
	}
	a := netip.MustParseAddrPort("127.0.0.1:51000")
	b := netip.MustParseAddrPort("127.0.0.1:8080")
	lo := &collector{flows: make(map[flowKey]*flow), maxFlows: 10}
	bridge := &collector{flows: make(map[flowKey]*flow), maxFlows: 10}
	packet := capture.Packet{Source: a, Destination: b, Protocol: 6, IPBytes: 40, Outgoing: true}
	lo.packet(packet)
	bridge.packet(packet) // The same tuple can be observed on both interfaces.
	collectors := map[string]*collector{"lo": lo, "br0": bridge}
	u := &terminalUI{interfaces: names, interfaceName: "lo", collectors: collectors, mode: viewInterfaces, lastSample: time.Now().Add(-time.Second), previous: make(map[*flow]counters), rates: make(map[*flow]rate)}
	u.sampleAll(collectors, time.Now())
	rows := u.rows(lo, viewInterfaces)
	if len(rows) != 2 || rows[0].label != "br0" || rows[1].label != "lo" {
		t.Fatalf("interface overview omitted a selected interface: %+v", rows)
	}
	for _, row := range rows {
		if row.rx != 0 || row.tx != 40 || len(row.flows) != 1 || row.txRate == 0 {
			t.Fatalf("interface bytes were merged or rate missing: %+v", row)
		}
	}
	if u.globalRate.tx == 0 || u.globalRate.tx > 40 {
		t.Fatalf("selected-interface rate includes another interface: %+v", u.globalRate)
	}
	u.selectedGroup = rows[0].identity()
	u.returnMode = viewPID
	u.handleKey("enter")
	if u.mode != viewPID || u.interfaceName != "br0" {
		t.Fatalf("Enter did not open the selected interface: mode=%d iface=%s", u.mode, u.interfaceName)
	}
}

func TestPIDReuseHasSeparateRows(t *testing.T) {
	a := netip.MustParseAddrPort("192.0.2.10:51000")
	b := netip.MustParseAddrPort("198.51.100.20:443")
	first := &flow{Key: keyFor(a, b, 6), RX: 40, Client: participant{PID: 101, StartNS: 1000, Name: "client"}}
	second := &flow{Key: keyFor(a, b, 6), RX: 60, Client: participant{PID: 101, StartNS: 2000, Name: "client"}}
	c := &collector{flows: map[flowKey]*flow{first.Key: second}, retired: []*flow{first}}
	u := &terminalUI{rates: make(map[*flow]rate)}
	rows := u.rows(c, viewPID)
	if len(rows) != 2 || rows[0].label != "101 client #1" || rows[1].label != "101 client #2" || rows[0].identity() == rows[1].identity() {
		t.Fatalf("PID reuse merged rows: %+v, %+v", rows[0], rows[1])
	}
	if got := formatPIDBrief(first.Client); got != "101(client)" {
		t.Fatalf("connection PID still exposes the raw startup nanoseconds: %q", got)
	}
	processes := []participant{first.Client, second.Client}
	distinguishProcessNames(processes)
	if processes[0].Name != "client #1" || processes[1].Name != "client #2" || strings.Contains(processLayout(processes, nil).header(), "START NS") {
		t.Fatalf("process table did not simplify reused PID display: %+v", processes)
	}
}

func TestReusedPIDDoesNotClaimPreviousTCPGeneration(t *testing.T) {
	a := netip.MustParseAddrPort("192.0.2.10:51000")
	b := netip.MustParseAddrPort("198.51.100.20:443")
	key := keyFor(a, b, 6)
	c := &collector{flows: make(map[flowKey]*flow), roles: make(map[flowKey]roles), roleSeen: make(map[flowKey]time.Time), maxFlows: 10}
	connect := func(start uint64) {
		c.event(probe.Event{Protocol: 6, Operation: "connect", Role: "out", PID: 101, StartNS: start, Process: "client", Local: a, Remote: b})
	}
	syn := func(seq uint32) {
		c.packet(capture.Packet{Source: a, Destination: b, Protocol: 6, SYN: true, TCPSeq: seq, Outgoing: true, IPBytes: 40})
	}
	connect(1000)
	syn(100)
	previous := c.flows[key]
	connect(2000)
	if previous.Client.StartNS != 1000 {
		t.Fatalf("new process claimed previous connection: %+v", previous.Client)
	}
	syn(200)
	current := c.flows[key]
	if len(c.retired) != 1 || c.retired[0] != previous || current.Client.StartNS != 2000 || previous.Client.StartNS != 1000 {
		t.Fatalf("PID reuse was merged across generations: old=%+v new=%+v", previous.Client, current.Client)
	}
}

func TestSharedTCPSocketKeepsAcceptorAndIOWorkerSeparate(t *testing.T) {
	client := netip.MustParseAddrPort("127.0.0.1:51000")
	server := netip.MustParseAddrPort("127.0.0.1:18920")
	c := &collector{flows: make(map[flowKey]*flow), roles: make(map[flowKey]roles), roleSeen: make(map[flowKey]time.Time), maxFlows: 10}
	c.event(probe.Event{Protocol: 6, Operation: "connect", Role: "out", PID: 101, StartNS: 1000, Process: "client", Local: client, Remote: server})
	c.packet(capture.Packet{Source: client, Destination: server, Protocol: 6, SYN: true, TCPSeq: 100, Outgoing: true, IPBytes: 40})
	c.event(probe.Event{Protocol: 6, Operation: "accept", Role: "in", PID: 202, StartNS: 2000, Process: "acceptor", Local: server, Remote: client})
	worker := processID{PID: 303, StartNS: 3000}
	c.event(probe.Event{Protocol: 6, Operation: "recv", Role: "in", AppBytes: 45, PID: worker.PID, StartNS: worker.StartNS, Process: "worker", Local: server, Remote: client})
	c.event(probe.Event{Protocol: 6, Operation: "send", Role: "out", AppBytes: 62, PID: worker.PID, StartNS: worker.StartNS, Process: "worker", Local: server, Remote: client})
	f := c.flows[keyFor(client, server, 6)]
	if f.Client.PID != 101 || f.Server.PID != 202 || f.IO[worker].RX != 45 || f.IO[worker].TX != 62 {
		t.Fatalf("shared socket roles or worker I/O were merged: flow=%+v", f)
	}
	rows := (&terminalUI{}).rows(c, viewPID)
	if len(rows) != 3 {
		t.Fatalf("expected client, acceptor and worker PID rows; got %d", len(rows))
	}
}

func TestPIDIOExpiryRetainsTotalWithoutStaleFlowDetail(t *testing.T) {
	id := processID{PID: 101, StartNS: 1000}
	a := netip.MustParseAddrPort("127.0.0.1:51000")
	b := netip.MustParseAddrPort("127.0.0.1:8080")
	f := &flow{Key: keyFor(a, b, 6), First: time.Now(), Last: time.Now(), IO: map[processID]ioBytes{id: {RX: 10, TX: 20}}}
	c := &collector{
		flows:   map[flowKey]*flow{f.Key: f},
		pidIO:   map[processID]processIO{id: {Name: "curl", ioBytes: ioBytes{RX: 10, TX: 20}}},
		pidSeen: map[processID]time.Time{id: time.Now().Add(-6 * time.Minute)},
	}
	c.expire(time.Now())
	if len(c.pidIO) != 0 || len(c.pidSeen) != 0 || len(f.IO) != 0 || c.expiredPIDIO.RX != 10 || c.expiredPIDIO.TX != 20 || c.expiredPIDCount != 1 {
		t.Fatalf("PID detail did not expire cleanly: pid=%+v flow=%+v expired=%+v", c.pidIO, f.IO, c.expiredPIDIO)
	}
	rows := (&terminalUI{}).rows(c, viewPID)
	var bytes uint64
	var foundSummary bool
	for _, row := range rows {
		bytes += row.rx + row.tx
		if row.label == "expired PID socket I/O detail" && row.rx == 10 && row.tx == 20 {
			foundSummary = true
		}
	}
	if !foundSummary || bytes != 30 {
		t.Fatalf("expired socket bytes disappeared or duplicated: rows=%+v bytes=%d", rows, bytes)
	}
}

func TestTCPFourTupleReuseKeepsGenerationsSeparate(t *testing.T) {
	src := netip.MustParseAddrPort("192.0.2.10:51000")
	dst := netip.MustParseAddrPort("198.51.100.20:443")
	c := &collector{
		flows: make(map[flowKey]*flow), roles: make(map[flowKey]roles),
		roleSeen: make(map[flowKey]time.Time), maxFlows: 10,
	}
	connect := func(pid int) {
		c.event(probe.Event{Protocol: 6, Role: "out", PID: pid, StartNS: uint64(pid), Process: "client", Local: src, Remote: dst})
	}
	syn := func(seq uint32) {
		c.packet(capture.Packet{Source: src, Destination: dst, Protocol: 6, Outgoing: true, HasPorts: true, SYN: true, TCPSeq: seq, IPBytes: 40})
	}
	request := func(seq uint32, host string) {
		payload := []byte("GET / HTTP/1.1\r\nHost: " + host + "\r\n\r\n")
		c.packet(capture.Packet{Source: src, Destination: dst, Protocol: 6, Outgoing: true, HasPorts: true, TCPSeq: seq, IPBytes: uint32(40 + len(payload)), Payload: payload})
	}
	connect(101)
	syn(1000)
	request(1001, "a.example.test")
	c.packet(capture.Packet{Source: src, Destination: dst, Protocol: 6, Outgoing: true, FIN: true, IPBytes: 40})
	connect(303)
	syn(2000)
	request(2001, "b.example.test")
	flows := c.allFlows()
	if len(flows) != 2 {
		t.Fatalf("same tuple should retain two TCP generations, got %d", len(flows))
	}
	byHost := make(map[string]int)
	var flowBytes uint64
	for _, f := range flows {
		byHost[f.Domain.Evidence().Group()] = f.Client.PID
		flowBytes += f.RX + f.TX
	}
	if byHost["a.example.test"] != 101 || byHost["b.example.test"] != 303 || flowBytes != c.bytes {
		t.Fatalf("tuple reuse merged PID, domain or bytes: hosts=%v flow bytes=%d total=%d", byHost, flowBytes, c.bytes)
	}
}

func TestTCPFinLifecycleAndTupleReuse(t *testing.T) {
	a := netip.MustParseAddrPort("192.0.2.10:51000")
	b := netip.MustParseAddrPort("198.51.100.20:443")
	c := &collector{flows: make(map[flowKey]*flow), roles: make(map[flowKey]roles), roleSeen: make(map[flowKey]time.Time), maxFlows: 10}
	send := func(src, dst netip.AddrPort, seq uint32, syn, ack, fin, rst bool) {
		c.packet(capture.Packet{Source: src, Destination: dst, Protocol: 6, TCPSeq: seq, SYN: syn, ACK: ack, FIN: fin, RST: rst, IPBytes: 40})
	}
	send(a, b, 100, true, false, false, false)
	f := c.flows[keyFor(a, b, 6)]
	if f.TCPState != "syn" {
		t.Fatalf("initial TCP state = %q", f.TCPState)
	}
	send(b, a, 900, true, true, false, false)
	send(a, b, 101, false, true, false, false)
	if f.TCPState != "established" {
		t.Fatalf("handshake state = %q", f.TCPState)
	}
	send(a, b, 102, false, true, true, false)
	if f.Closed || f.TCPState != "closing" {
		t.Fatalf("first FIN prematurely closed flow: %+v", f)
	}
	c.event(probe.Event{Protocol: 6, Operation: "accept", Role: "in", PID: 202, StartNS: 2000, Process: "server", Local: b, Remote: a})
	if f.Server.PID != 202 {
		t.Fatalf("late accept lost while half closed: %+v", f.Server)
	}
	send(b, a, 901, false, true, true, false)
	if !f.Closed || f.TCPState != "closed" {
		t.Fatalf("second FIN did not close flow: %+v", f)
	}
	send(a, b, 300, true, false, false, false)
	if len(c.retired) != 1 || c.flows[keyFor(a, b, 6)] == f || c.flows[keyFor(a, b, 6)].TCPState != "syn" {
		t.Fatalf("tuple reuse lost lifecycle generation")
	}
	if server := c.flows[keyFor(a, b, 6)].Server; server.PID != 0 {
		t.Fatalf("new connection inherited the previous acceptor: %+v", server)
	}
	send(b, a, 700, false, true, false, true)
	newFlow := c.flows[keyFor(a, b, 6)]
	if !newFlow.Closed || newFlow.TCPState != "reset" {
		t.Fatalf("RST did not close new flow: %+v", newFlow)
	}
}

// The accept event can be read before the inbound SYN behind it: the packet
// and eBPF channels are drained in no fixed order.
func TestAcceptReadBeforeInboundSYNNamesServer(t *testing.T) {
	a, b := netip.MustParseAddrPort("203.0.113.5:50000"), netip.MustParseAddrPort("192.0.2.10:443")
	c := &collector{flows: make(map[flowKey]*flow), roles: make(map[flowKey]roles), roleSeen: make(map[flowKey]time.Time), maxFlows: 10}
	c.event(probe.Event{Protocol: 6, Operation: "accept", Role: "in", PID: 202, StartNS: 2000, Process: "server", Local: b, Remote: a})
	c.packet(capture.Packet{Source: a, Destination: b, Protocol: 6, TCPSeq: 100, SYN: true, IPBytes: 60})
	if f := c.flows[keyFor(a, b, 6)]; f == nil || f.Server.PID != 202 || f.Direction != "inbound" {
		t.Fatalf("early accept event lost: %+v", f)
	}
}

func TestUDPWildcardPIDBecomesAmbiguousAcrossLocalIPs(t *testing.T) {
	remote := netip.MustParseAddrPort("198.51.100.1:53")
	localA := netip.MustParseAddrPort("192.0.2.10:40000")
	localB := netip.MustParseAddrPort("192.0.2.11:40000")
	c := &collector{
		flows: make(map[flowKey]*flow), wildcards: make(map[wildcardKey]participant),
		wildcardSeen: make(map[wildcardKey]time.Time), maxFlows: 10,
	}
	c.event(probe.Event{Protocol: 17, Role: "out", PID: 123, StartNS: 456, Process: "dns", Local: netip.MustParseAddrPort("0.0.0.0:40000"), Remote: remote})
	c.packet(capture.Packet{Source: localA, Destination: remote, Protocol: 17, HasPorts: true, Outgoing: true, IPBytes: 40})
	c.reconcileWildcards()
	if got := c.flows[keyFor(localA, remote, 17)].Client.PID; got != 123 {
		t.Fatalf("unique UDP wildcard mapping PID=%d, want 123", got)
	}
	c.packet(capture.Packet{Source: localB, Destination: remote, Protocol: 17, HasPorts: true, Outgoing: true, IPBytes: 40})
	c.reconcileWildcards()
	if got := c.flows[keyFor(localA, remote, 17)].Client.PID; got > 0 {
		t.Fatalf("ambiguous UDP wildcard mapping retained PID=%d", got)
	}
}

func TestUDPReplyDoesNotReplaceInitialEndpointPID(t *testing.T) {
	client := netip.MustParseAddrPort("127.0.0.1:51000")
	server := netip.MustParseAddrPort("127.0.0.1:18890")
	c := &collector{flows: make(map[flowKey]*flow), roles: make(map[flowKey]roles), roleSeen: make(map[flowKey]time.Time), maxFlows: 10}
	c.packet(capture.Packet{Source: client, Destination: server, Protocol: 17, IPBytes: 33})
	io := func(pid int, local, remote netip.AddrPort, operation string) {
		role := "out"
		if operation == "recv" {
			role = "in"
		}
		c.event(probe.Event{Protocol: 17, Operation: operation, Role: role, AppBytes: 5, PID: pid, StartNS: uint64(pid), Process: "python", Local: local, Remote: remote})
	}
	io(101, client, server, "send")
	io(202, server, client, "recv")
	c.packet(capture.Packet{Source: server, Destination: client, Protocol: 17, IPBytes: 33})
	io(202, server, client, "send")
	io(101, client, server, "recv")
	f := c.flows[keyFor(client, server, 17)]
	if f.Client.PID != 101 || f.Server.PID != 202 || c.pidIO[processID{101, 101}].RX != 5 || c.pidIO[processID{202, 202}].TX != 5 {
		t.Fatalf("UDP response reassigned request endpoint: client=%+v server=%+v io=%+v", f.Client, f.Server, c.pidIO)
	}
}

// PID events trail their packets by up to the ring's drain interval, so a
// short connection can close before its connect, accept and I/O events
// arrive. They still belong to it.
func TestLateEventsReachAJustClosedFlow(t *testing.T) {
	client, server := netip.MustParseAddrPort("127.0.0.1:40100"), netip.MustParseAddrPort("127.0.0.1:8080")
	c := &collector{flows: make(map[flowKey]*flow), roles: make(map[flowKey]roles), roleSeen: make(map[flowKey]time.Time), maxFlows: 10}
	c.packet(capture.Packet{Source: client, Destination: server, Protocol: 6, HasPorts: true, SYN: true, TCPSeq: 1, IPBytes: 60, Outgoing: true})
	c.packet(capture.Packet{Source: server, Destination: client, Protocol: 6, HasPorts: true, SYN: true, ACK: true, TCPSeq: 500, IPBytes: 60})
	c.packet(capture.Packet{Source: client, Destination: server, Protocol: 6, HasPorts: true, ACK: true, FIN: true, TCPSeq: 2, IPBytes: 52})
	c.packet(capture.Packet{Source: server, Destination: client, Protocol: 6, HasPorts: true, ACK: true, FIN: true, TCPSeq: 501, IPBytes: 52})
	c.event(probe.Event{Protocol: 6, Operation: "connect", Role: "out", PID: 101, StartNS: 1, Process: "curl", Local: client, Remote: server})
	c.event(probe.Event{Protocol: 6, Operation: "accept", Role: "in", PID: 202, StartNS: 2, Process: "server", Local: server, Remote: client})
	c.event(probe.Event{Protocol: 6, Operation: "send", Role: "out", AppBytes: 20, PID: 101, StartNS: 1, Process: "curl", Local: client, Remote: server})
	f := c.flows[keyFor(client, server, 6)]
	if !f.Closed || f.Client.PID != 101 || f.Server.PID != 202 || f.IO[processID{101, 1}].TX != 20 {
		t.Fatalf("late events lost: closed=%v client=%+v server=%+v io=%+v", f.Closed, f.Client, f.Server, f.IO)
	}
}
