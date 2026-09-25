package app

import (
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jimyag/socktrail/internal/probe"
)

// fakeProc writes /proc entries for pid: the stat fields parseProcessStat
// reads, the name and the cgroup file.
func fakeProc(t *testing.T, root string, pid, parent int, name, cgroup string) processID {
	t.Helper()
	clockTicks, err := systemClockTicks()
	if err != nil {
		t.Skip(err)
	}
	ticks := uint64(1000 + pid)
	dir := filepath.Join(root, fmt.Sprint(pid))
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	for file, data := range map[string]string{
		"stat":   fmt.Sprintf("%d (%s) S %d %s%d", pid, name, parent, strings.Repeat("0 ", 17), ticks),
		"comm":   name + "\n",
		"cgroup": "0::" + cgroup + "\n",
	} {
		if err := os.WriteFile(filepath.Join(dir, file), []byte(data), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return processID{PID: pid, StartNS: ticksToNS(ticks, clockTicks)}
}

// A command run from a script in a terminal, and a server's worker: the
// table learns the ancestors that never used the network, groups each
// process by service, cgroup and tree, and --pid follows descendants even
// after an ancestor exits.
func TestProcessTreesAndServices(t *testing.T) {
	root := t.TempDir()
	session, nginx := "/user.slice/user-1000.slice/session-3.scope", "/system.slice/nginx.service"
	bash := fakeProc(t, root, 100, 1, "bash", session)
	script := fakeProc(t, root, 200, 100, "deploy.sh", session)
	curl := fakeProc(t, root, 300, 200, "curl", session)
	master := fakeProc(t, root, 400, 1, "nginx", nginx)
	worker := fakeProc(t, root, 401, 400, "nginx", nginx)
	table := newProcessTable(root)
	for _, e := range []probe.Event{
		{PID: curl.PID, StartNS: curl.StartNS, Process: "curl", ParentPID: script.PID, ParentStartNS: script.StartNS, CgroupID: 11},
		{PID: worker.PID, StartNS: worker.StartNS, Process: "nginx", ParentPID: master.PID, ParentStartNS: master.StartNS, CgroupID: 22},
	} {
		table.observe(e)
	}
	os.RemoveAll(filepath.Join(root, "200")) // The script exits; the table keeps it.

	if m := table.procs[script]; m == nil || m.Name != "deploy.sh" || m.Parent != bash {
		t.Fatalf("ancestor not read from /proc: %+v", m)
	}
	pidFilter := processFilter{pids: pidList{100}}
	if !table.matches(pidFilter, curl, "") || table.matches(pidFilter, worker, "") {
		t.Fatal("--pid 100 must select its grandchild curl and nothing of nginx")
	}
	if key, label := table.group(worker, "", byService); key != "service:"+nginx || label != "nginx.service" {
		t.Fatalf("service group %q %q", key, label)
	}
	if key, label := table.group(curl, "", byCgroup); key != "cgroup:"+session || label != session {
		t.Fatalf("cgroup group %q %q", key, label)
	}
	if _, label := table.group(curl, "curl", byTree); label != "100 bash" {
		t.Fatalf("curl's tree is rooted at %q, want the terminal's shell", label)
	}
	if _, label := table.group(worker, "nginx", byTree); label != "400 nginx" {
		t.Fatalf("worker's tree is rooted at %q, want the master", label)
	}
	ordered, depths := table.treeOrder([]participant{{PID: 401, StartNS: worker.StartNS, Name: "nginx"}, {PID: 300, StartNS: curl.StartNS, Name: "curl"}, {PID: 400, StartNS: master.StartNS, Name: "nginx"}})
	if ordered[0].PID != 300 || ordered[1].PID != 400 || ordered[2].PID != 401 || depths[worker] != 1 || depths[curl] != 0 {
		t.Fatalf("tree order %+v depths %v", ordered, depths)
	}
	// A later process of the same cgroup that is already gone still gets
	// the path, learned from the cgroup ID.
	table.observe(probe.Event{PID: 500, StartNS: 1, Process: "worker", CgroupID: 22})
	if path := table.cgroupOf(table.procs[processID{PID: 500, StartNS: 1}]); path != nginx {
		t.Fatalf("cgroup of an exited process: %q", path)
	}
}

// The service page puts a flow under the service of each process in it, and
// a service's socket bytes are its processes'. A --process filter hides the
// flows and processes it does not select.
func TestServicePageAndProcessFilter(t *testing.T) {
	root := t.TempDir()
	curl := fakeProc(t, root, 300, 1, "curl", "/user.slice/user-1000.slice/session-3.scope")
	worker := fakeProc(t, root, 401, 1, "nginx", "/system.slice/nginx.service")
	c := newTestCollector()
	c.pidIO = map[processID]processIO{curl: {"curl", ioBytes{RX: 100, TX: 10}}, worker: {"nginx", ioBytes{RX: 10, TX: 100}}}
	local := keyFor(netip.MustParseAddrPort("127.0.0.1:40000"), netip.MustParseAddrPort("127.0.0.1:80"), 6)
	upstream := keyFor(netip.MustParseAddrPort("192.0.2.1:41000"), netip.MustParseAddrPort("198.51.100.2:443"), 6)
	c.flows[local] = &flow{Key: local, Client: participant{PID: 300, StartNS: curl.StartNS, Name: "curl"}, Server: participant{PID: 401, StartNS: worker.StartNS, Name: "nginx"},
		IO: map[processID]ioBytes{curl: {RX: 100, TX: 10}, worker: {RX: 10, TX: 100}}}
	c.flows[upstream] = &flow{Key: upstream, Client: participant{PID: 401, StartNS: worker.StartNS, Name: "nginx"}}
	u := &terminalUI{processes: newProcessTable(root)}

	byLabel := func(rows []*uiRow) map[string]*uiRow {
		m := make(map[string]*uiRow)
		for _, r := range rows {
			m[r.label] = r
		}
		return m
	}
	rows := byLabel(u.rows(c, viewService))
	nginx, session := rows["nginx.service"], rows["session-3.scope"]
	if len(rows) != 2 || nginx == nil || session == nil || len(nginx.flows) != 2 || len(session.flows) != 1 || nginx.rx != 10 || nginx.tx != 100 || len(nginx.members) != 1 {
		t.Fatalf("service rows: %+v", rows)
	}
	// The connection table leads with the row's processes that did the I/O:
	// the group's own on the service page, not its peer in another service;
	// the selected one on the PID page; every one on the other pages.
	curlRow := &uiRow{pidID: curl, flows: []*flow{c.flows[local]}}
	for _, tc := range []struct {
		row  *uiRow
		mode viewMode
		f    *flow
		want string
	}{
		{nginx, viewService, c.flows[local], "401(nginx)"},
		{nginx, viewService, c.flows[upstream], "-"},
		{curlRow, viewPID, c.flows[local], "300(curl)"},
		{&uiRow{flows: []*flow{c.flows[local]}}, viewProtocol, c.flows[local], "300(curl),401(nginx)"},
	} {
		layout := connectionLayout(tc.row, tc.mode, c, false)
		if got := strings.Fields(connectionLine(layout, tc.f, tc.row, tc.mode, c, nil, false, " "))[0]; got != tc.want {
			t.Errorf("%s page: I/O PID of %s is %q, want %q", viewNames[tc.mode], tc.f.Key.A, got, tc.want)
		}
	}

	u.scopeFilter = processFilter{names: patternList{"curl"}}
	if rows := byLabel(u.rows(c, viewService)); len(rows) != 1 || rows["session-3.scope"] == nil {
		t.Fatalf("filtered service rows: %+v", rows)
	}
	if rows := u.rows(c, viewPID); len(rows) != 1 || rows[0].pidID != curl {
		t.Fatalf("filtered PID rows: %+v", rows)
	}
	scope := newProcessScope(u.processes, u.scopeFilter)
	if flows := reportFlows(c, scope); len(flows) != 1 || flows[0].Key != local {
		t.Fatalf("filtered snapshot flows: %d", len(flows))
	}
}

func TestExecutableNameGroupingMergesDifferentPaths(t *testing.T) {
	root := t.TempDir()
	first := fakeProc(t, root, 301, 1, "curl", "/user.slice/session-1.scope")
	second := fakeProc(t, root, 302, 1, "renamed", "/user.slice/session-2.scope")
	other := fakeProc(t, root, 303, 1, "wget", "/user.slice/session-2.scope")
	for pid, target := range map[int]string{301: "/usr/bin/curl", 302: "/test/curl (deleted)", 303: "/usr/bin/wget"} {
		if err := os.Symlink(target, filepath.Join(root, fmt.Sprint(pid), "exe")); err != nil {
			t.Fatal(err)
		}
	}
	c := newTestCollector()
	c.pidIO = map[processID]processIO{
		first:  {Name: "curl", ioBytes: ioBytes{RX: 10, TX: 2}},
		second: {Name: "renamed", ioBytes: ioBytes{RX: 20, TX: 3}},
		other:  {Name: "wget", ioBytes: ioBytes{RX: 4, TX: 5}},
	}
	for i, p := range []struct {
		id   processID
		name string
	}{{first, "curl"}, {second, "renamed"}, {other, "wget"}} {
		source := netip.MustParseAddrPort(fmt.Sprintf("192.0.2.%d:5000", i+1))
		target := netip.MustParseAddrPort("198.51.100.1:443")
		key := keyFor(source, target, 6)
		c.flows[key] = &flow{Key: key, Client: participant{PID: p.id.PID, StartNS: p.id.StartNS, Name: p.name}}
	}
	u := &terminalUI{processes: newProcessTable(root), grouping: byExecutable}
	rows := make(map[string]*uiRow)
	for _, row := range u.rows(c, viewService) {
		rows[row.label] = row
	}
	if len(rows) != 2 || rows["curl"] == nil || rows["wget"] == nil || rows["curl"].rx != 30 || rows["curl"].tx != 5 || len(rows["curl"].members) != 2 || len(rows["curl"].flows) != 2 {
		t.Fatalf("executable groups did not merge curl paths: %+v", rows)
	}
	stale := processID{PID: first.PID, StartNS: first.StartNS + 1_000_000_000}
	if _, label := u.processes.group(stale, "old process", byExecutable); label != "old process" {
		t.Fatalf("reused PID inherited the live process executable: %q", label)
	}
	u.mode, u.grouping = viewService, byTree
	u.handleKey("b")
	if u.grouping != byExecutable {
		t.Fatalf("b did not reach executable-name grouping: %v", u.grouping)
	}
	u.handleKey("b")
	if u.grouping != byService {
		t.Fatalf("b did not wrap to service grouping: %v", u.grouping)
	}
}

func TestProcessAndCgroupPatterns(t *testing.T) {
	for _, tc := range []struct {
		pattern, name string
		want          bool
	}{
		{"nginx", "nginx", true},
		{"python*", "python3", true},
		{"nginx", "nginx-worker", false},
		{"systemd-resolved", "systemd-resolve", true}, // The kernel keeps 15 bytes.
		{"systemd-resolved", "systemd-resolv", false},
	} {
		if got := nameMatches(tc.pattern, tc.name); got != tc.want {
			t.Errorf("--process %q vs %q: %v", tc.pattern, tc.name, got)
		}
	}
	for _, tc := range []struct {
		pattern, path string
		want          bool
	}{
		{"nginx.service", "/system.slice/nginx.service", true},
		{"docker-*", "/system.slice/docker-" + strings.Repeat("ab", 32) + ".scope", true},
		{"/system.slice", "/system.slice/nginx.service", true},
		{"/system.slice/nginx", "/system.slice/nginx.service", false}, // A prefix ends at a directory.
		{"system.slice", "/user.slice/user-1000.slice", false},
		{"/", "/init.scope", true},
	} {
		if got := cgroupMatches(tc.pattern, tc.path); got != tc.want {
			t.Errorf("--cgroup %q vs %q: %v", tc.pattern, tc.path, got)
		}
	}
}

func TestServiceOfCgroupPaths(t *testing.T) {
	id := strings.Repeat("3f", 32)
	for path, want := range map[string]string{
		"/system.slice/nginx.service":                               "nginx.service",
		"/system.slice/docker-" + id + ".scope":                     "docker-3f3f3f3f3f3f.scope",
		"/user.slice/user-1000.slice/user@1000.service/app.slice/x": "user@1000.service",
		"/kubepods.slice/pod.slice/cri-containerd-" + id + ".scope": "cri-containerd-3f3f3f3f3f3f.scope",
		"/": "/",
		"":  "unknown cgroup",
	} {
		if _, label := serviceOf(path); label != want {
			t.Errorf("service of %q is %q, want %q", path, label, want)
		}
	}
}

func TestReadCgroupPath(t *testing.T) {
	dir := t.TempDir()
	for content, want := range map[string]string{
		"0::/system.slice/nginx.service\n":                                 "/system.slice/nginx.service",
		"1:name=systemd:/system.slice/cron.service\n0::/\n":                "/system.slice/cron.service", // Hybrid: v2 unused.
		"12:cpu,cpuacct:/foo\n1:name=systemd:/system.slice/sshd.service\n": "/system.slice/sshd.service",
	} {
		if err := os.WriteFile(filepath.Join(dir, "cgroup"), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
		if got := readCgroupPath(dir); got != want {
			t.Errorf("cgroup file %q: %q, want %q", content, got, want)
		}
	}
}
