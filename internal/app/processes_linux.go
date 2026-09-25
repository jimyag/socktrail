package app

import (
	"cmp"
	"fmt"
	"maps"
	"os"
	"os/user"
	pathpkg "path"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/jimyag/socktrail/internal/probe"
	"github.com/jimyag/socktrail/internal/procname"
)

const (
	maxProcesses   = 65536
	maxCgroups     = 4096
	processIdle    = 10 * time.Minute
	maxAncestors   = 32
	processExpiry  = 30 * time.Second // How often idle processes are dropped.
	kernelNameSize = 15               // Bytes of a process name the kernel keeps.
)

// processMeta places a process in the process tree and the cgroup
// hierarchy. Events carry both for a process doing socket I/O; /proc fills
// in its ancestors, which may never touch the network.
type processMeta struct {
	Name           string
	ExecutableName string
	ExeChecked     bool
	UID            int       // Effective user ID; -1 when unknown.
	UIDChecked     bool      // Whether UID was read from /proc.
	Parent         processID // Zero for PID 1, or when unknown.
	Cgroup         string    // Its cgroup v2 path, such as /system.slice/nginx.service; empty when unknown.
	CgroupID       uint64
	seen           time.Time
}

// processTable remembers the processes of socket events and their
// ancestors. All interfaces share it: a process owns sockets on every one.
type processTable struct {
	procRoot   string
	procs      map[processID]*processMeta
	cgroups    map[uint64]string // Paths of the cgroup IDs events carried, learned from /proc.
	containers *containerNames
	userNames  map[int]string // User names by UID, looked up once.
	expired    time.Time
}

func newProcessTable(procRoot string) *processTable {
	return &processTable{procRoot: procRoot, procs: make(map[processID]*processMeta), cgroups: make(map[uint64]string), containers: newContainerNames(), userNames: make(map[int]string)}
}

// observe records the process of a socket event whose start time
// tickStartNS already rounded.
func (t *processTable) observe(e probe.Event) {
	if e.PID <= 0 {
		return
	}
	id := processID{PID: e.PID, StartNS: e.StartNS}
	if m := t.procs[id]; m != nil {
		m.seen = time.Now()
		if e.Process != "" {
			if m.Name != e.Process {
				m.ExecutableName, m.ExeChecked = "", false
				m.UIDChecked = false // A set-user-ID executable changes it.
			}
			m.Name = e.Process // exec changes the name, not the identity.
		}
		return
	}
	if len(t.procs) >= maxProcesses {
		return
	}
	m := &processMeta{Name: e.Process, CgroupID: e.CgroupID, seen: time.Now()}
	if e.ParentPID > 0 {
		m.Parent = processID{PID: e.ParentPID, StartNS: tickStartNS(e.ParentStartNS)}
	}
	// The event names the cgroup by ID; its path comes from /proc while the
	// process lives, and serves every later process of that cgroup.
	if m.Cgroup = t.cgroups[e.CgroupID]; m.Cgroup == "" {
		m.Cgroup = readCgroupPath(filepath.Join(t.procRoot, strconv.Itoa(e.PID)))
		if m.Cgroup != "" && e.CgroupID != 0 && len(t.cgroups) < maxCgroups {
			t.cgroups[e.CgroupID] = m.Cgroup
		}
	}
	t.procs[id] = m
	t.addAncestors(m.Parent)
}

// meta returns what the table knows about a process. One it has never seen,
// such as the owner of a socket opened before startup, is read from /proc
// once.
func (t *processTable) meta(id processID) *processMeta {
	if m, ok := t.procs[id]; ok {
		return m
	}
	if id.PID <= 0 || len(t.procs) >= maxProcesses {
		return nil
	}
	m := t.readProc(id)
	t.procs[id] = m // An unreadable process is not read again.
	if m.Name != "" {
		t.addAncestors(m.Parent)
	}
	return m
}

// addAncestors reads the ancestors the table lacks from /proc while they
// are alive, so trees and --pid still hold once they exit.
func (t *processTable) addAncestors(id processID) {
	for depth := 0; depth < maxAncestors && id.PID > 1 && len(t.procs) < maxProcesses; depth++ {
		if _, known := t.procs[id]; known {
			return
		}
		m := t.readProc(id)
		t.procs[id] = m
		if m.Name == "" {
			return
		}
		id = m.Parent
	}
}

// ancestry names the observed process and the known parents, marking a
// service or container boundary when the parent's cgroup unit changes.
func (t *processTable) ancestry(p participant) string {
	if p.PID <= 0 {
		return ""
	}
	id := p.id()
	seen := make(map[processID]bool)
	var parts []string
	var childUnit string
	for range maxAncestors {
		if seen[id] {
			parts = append(parts, "[cycle]")
			break
		}
		seen[id] = true
		m := t.meta(id)
		name := ""
		if m != nil {
			name = m.Name
		}
		if len(parts) == 0 && p.Name != "" {
			name = p.Name
		}
		if name == "" {
			parts = append(parts, fmt.Sprintf("?%d", id.PID))
			break
		}
		label := fmt.Sprintf("%s(%d)", name, id.PID)
		path := t.cgroupOf(m)
		unit, _ := serviceOf(path)
		if len(parts) > 0 && unit != "" && childUnit != "" && unit != childUnit {
			_, boundary, _ := t.serviceFor(path)
			label = "[" + boundary + "] " + label
		}
		parts = append(parts, label)
		if m == nil || m.Parent.PID <= 0 {
			break
		}
		childUnit, id = unit, m.Parent
	}
	return strings.Join(parts, " ← ")
}

// readProc reads a live process from /proc; its Name is empty when the PID
// is gone or belongs to a later process.
func (t *processTable) readProc(id processID) *processMeta {
	m := &processMeta{seen: time.Now()}
	dir := filepath.Join(t.procRoot, strconv.Itoa(id.PID))
	//nolint:gosec // G304: procfs path is built from an internal root, numeric PID, or fixed leaf name.
	stat, err := os.ReadFile(filepath.Join(dir, "stat"))
	if err != nil {
		return m
	}
	parent, ticks, err := parseProcessStat(stat)
	clockTicks, clockErr := systemClockTicks()
	if err != nil || clockErr != nil || !processStartMatches(id.StartNS, ticks, clockTicks) {
		return m
	}
	//nolint:gosec // G304: procfs path is built from an internal root, numeric PID, or fixed leaf name.
	comm, _ := os.ReadFile(filepath.Join(dir, "comm"))
	m.Name, m.Cgroup = procname.Clean(comm), readCgroupPath(dir)
	//nolint:gosec // G703: parent is a numeric PID parsed from procfs.
	if parentStat, err := os.ReadFile(filepath.Join(t.procRoot, strconv.Itoa(parent), "stat")); err == nil && parent > 0 {
		if _, parentTicks, err := parseProcessStat(parentStat); err == nil {
			m.Parent = processID{PID: parent, StartNS: ticksToNS(parentTicks, clockTicks)}
		}
	}
	return m
}

// expire drops processes idle for processIdle, keeping the ancestors of
// the rest.
func (t *processTable) expire(now time.Time) {
	if now.Sub(t.expired) < processExpiry {
		return
	}
	t.expired = now
	keep := make(map[processID]bool)
	for id, m := range t.procs {
		if now.Sub(m.seen) > processIdle {
			continue
		}
		for depth := 0; depth <= maxAncestors && id.PID > 0 && !keep[id]; depth++ {
			keep[id] = true
			if m = t.procs[id]; m == nil {
				break
			}
			id = m.Parent
		}
	}
	for id := range t.procs {
		if !keep[id] {
			delete(t.procs, id)
		}
	}
}

func (t *processTable) cgroupOf(m *processMeta) string {
	if m == nil {
		return ""
	}
	if m.Cgroup == "" && m.CgroupID != 0 {
		m.Cgroup = t.cgroups[m.CgroupID] // Learned from another process since.
	}
	return m.Cgroup
}

// readCgroupPath returns a process's cgroup v2 path; under cgroup v1 alone,
// its systemd hierarchy path.
func readCgroupPath(procDir string) string {
	//nolint:gosec // G304: procfs path is built from an internal root, numeric PID, or fixed leaf name.
	data, err := os.ReadFile(filepath.Join(procDir, "cgroup"))
	if err != nil {
		return ""
	}
	var v2, v1 string
	for line := range strings.SplitSeq(strings.TrimSpace(string(data)), "\n") {
		if path, ok := strings.CutPrefix(line, "0::"); ok {
			v2 = path
		} else if _, path, ok := strings.Cut(line, ":name=systemd:"); ok {
			v1 = path
		}
	}
	if v2 == "" || v2 == "/" && v1 != "" { // A hybrid host may leave cgroup v2 unused.
		return v1
	}
	return v2
}

var containerID = regexp.MustCompile(`[0-9a-f]{64}`)

// serviceOf returns the systemd unit or container a cgroup path belongs to:
// the path through its innermost .service or .scope directory, and the
// unit's name with any container ID cut to 12 characters. A path without a
// unit, as outside systemd, is its own service.
func serviceOf(path string) (string, string) {
	if path == "" {
		return "", "unknown cgroup"
	}
	parts := strings.Split(strings.Trim(path, "/"), "/")
	for i, part := range slices.Backward(parts) {
		if strings.HasSuffix(part, ".service") || strings.HasSuffix(part, ".scope") {
			short := containerID.ReplaceAllStringFunc(part, func(id string) string { return id[:12] })
			return "/" + strings.Join(parts[:i+1], "/"), short
		}
	}
	return path, path
}

func (t *processTable) serviceFor(path string) (string, string, *containerInfo) {
	key, label := serviceOf(path)
	if t.containers != nil {
		if info, resolved := t.containers.lookup(path); info != nil {
			if resolved {
				label = info.label()
			}
			return key, label, info
		}
	}
	return key, label, nil
}

// processGrouping is how the service page groups processes.
type processGrouping uint8

const (
	byService processGrouping = iota
	byCgroup
	byTree
	byExecutable
	byUser
)

var groupingNames = [...]string{"service", "cgroup", "process tree", "executable name", "user"}

// group returns the selected group for a process.
func (t *processTable) group(id processID, name string, by processGrouping) (string, string) {
	m := t.meta(id)
	switch by {
	case byExecutable:
		if m != nil && !m.ExeChecked {
			m.ExecutableName = t.executableName(id)
			m.ExeChecked = true
		}
		if m != nil && m.ExecutableName != "" {
			name = m.ExecutableName
		} else if name == "" && m != nil {
			name = m.Name
		}
		name = filepath.Base(name)
		if name == "." {
			name = "unknown executable"
		}
		return "executable:" + name, name
	case byUser:
		uid, user := t.user(id)
		if uid < 0 {
			return "user:", "unknown user"
		}
		return "user:" + strconv.Itoa(uid), user
	case byCgroup:
		path := t.cgroupOf(m)
		if path == "" {
			return "cgroup:", "unknown cgroup"
		}
		return "cgroup:" + path, path
	case byTree:
		root := t.treeRoot(id)
		if root != id {
			name = ""
		}
		if rm := t.procs[root]; name == "" && rm != nil {
			name = rm.Name
		}
		return "tree:" + pidGroupKey(root), pidGroupLabel(participant{PID: root.PID, StartNS: root.StartNS, Name: name})
	}
	key, label, _ := t.serviceFor(t.cgroupOf(m))
	return "service:" + key, label
}

// user returns a live process's effective user ID and name, reading /proc
// once per process; -1 and an empty name when unknown, as for a process
// that exited before socktrail looked.
func (t *processTable) user(id processID) (int, string) {
	m := t.meta(id)
	if m == nil {
		return -1, ""
	}
	if !m.UIDChecked {
		m.UID, m.UIDChecked = t.readUID(id), true
	}
	if m.UID < 0 {
		return -1, ""
	}
	name, ok := t.userNames[m.UID]
	if !ok {
		name = lookupUserName(m.UID)
		if len(t.userNames) < maxCgroups {
			t.userNames[m.UID] = name
		}
	}
	return m.UID, name
}

// lookupUserName names a UID from the passwd database, falling back to the
// number, as ps does. Containers' users are named by the host's database.
var lookupUserName = func(uid int) string {
	if u, err := user.LookupId(strconv.Itoa(uid)); err == nil && u.Username != "" {
		return u.Username
	}
	return strconv.Itoa(uid)
}

// readUID reads the effective UID of the process's Uid line in
// /proc/PID/status, or -1 when the PID is gone or reused.
func (t *processTable) readUID(id processID) int {
	if id.PID <= 0 || t.procRoot == "" { // An offline recording has no /proc.
		return -1
	}
	dir := filepath.Join(t.procRoot, strconv.Itoa(id.PID))
	//nolint:gosec // G304: procfs path is built from an internal root, numeric PID, or fixed leaf name.
	status, err := os.ReadFile(filepath.Join(dir, "status"))
	if err != nil {
		return -1
	}
	//nolint:gosec // G304: procfs path is built from an internal root, numeric PID, or fixed leaf name.
	stat, err := os.ReadFile(filepath.Join(dir, "stat"))
	if err != nil {
		return -1
	}
	_, ticks, err := parseProcessStat(stat)
	clockTicks, clockErr := systemClockTicks()
	if err != nil || clockErr != nil || !processStartMatches(id.StartNS, ticks, clockTicks) {
		return -1
	}
	return parseStatusUID(status)
}

// parseStatusUID returns the effective UID of a status file: the second of
// the real, effective, saved and filesystem IDs on its Uid line.
func parseStatusUID(status []byte) int {
	for line := range strings.Lines(string(status)) {
		rest, ok := strings.CutPrefix(line, "Uid:")
		if !ok {
			continue
		}
		fields := strings.Fields(rest)
		if len(fields) < 2 {
			return -1
		}
		uid, err := strconv.ParseUint(fields[1], 10, 32)
		if err != nil {
			return -1
		}
		return int(uid)
	}
	return -1
}

func (t *processTable) executableName(id processID) string {
	if id.PID <= 0 {
		return ""
	}
	dir := filepath.Join(t.procRoot, strconv.Itoa(id.PID))
	target, err := os.Readlink(filepath.Join(dir, "exe"))
	if err != nil {
		return ""
	}
	//nolint:gosec // G304: procfs path is built from an internal root, numeric PID, or fixed leaf name.
	stat, err := os.ReadFile(filepath.Join(dir, "stat"))
	if err != nil {
		return ""
	}
	_, ticks, err := parseProcessStat(stat)
	clockTicks, clockErr := systemClockTicks()
	if err != nil || clockErr != nil || !processStartMatches(id.StartNS, ticks, clockTicks) {
		return ""
	}
	return filepath.Base(strings.TrimSuffix(target, " (deleted)"))
}

// treeRoot climbs from a process to its farthest ancestor in the same
// service: the master of a server's workers, or the shell a command ran in.
func (t *processTable) treeRoot(id processID) processID {
	service, _ := serviceOf(t.cgroupOf(t.meta(id)))
	for range maxAncestors {
		m := t.procs[id]
		if m == nil || m.Parent.PID <= 1 {
			break
		}
		parentService, _ := serviceOf(t.cgroupOf(t.procs[m.Parent]))
		if t.procs[m.Parent] == nil || parentService != service {
			break
		}
		id = m.Parent
	}
	return id
}

// treeOrder returns processes so ordered that each comes right after its
// parent when its parent is among them, and each one's depth for indenting.
// It reuses the slice.
func (t *processTable) treeOrder(processes []participant) ([]participant, map[processID]int) {
	among := make(map[processID]bool, len(processes))
	for _, p := range processes {
		among[p.id()] = true
	}
	children := make(map[processID][]participant)
	var roots []participant
	for _, p := range processes {
		if m := t.procs[p.id()]; m != nil && among[m.Parent] && m.Parent != p.id() {
			children[m.Parent] = append(children[m.Parent], p)
		} else {
			roots = append(roots, p)
		}
	}
	byPID := func(a, b participant) int {
		return cmp.Or(cmp.Compare(a.PID, b.PID), cmp.Compare(a.StartNS, b.StartNS))
	}
	depths := make(map[processID]int, len(processes))
	ordered := processes[:0] // roots and children hold copies of every element.
	var visit func(p participant, depth int)
	visit = func(p participant, depth int) {
		if _, done := depths[p.id()]; done || depth > maxAncestors {
			return
		}
		depths[p.id()] = depth
		ordered = append(ordered, p)
		kids := children[p.id()]
		slices.SortFunc(kids, byPID)
		for _, kid := range kids {
			visit(kid, depth+1)
		}
	}
	slices.SortFunc(roots, byPID)
	for _, root := range roots {
		visit(root, 0)
	}
	return ordered, depths
}

// processFilter selects processes by name, by PID with all their
// descendants, or by cgroup; a process that meets any of them is selected.
type processFilter struct {
	names      patternList
	pids       pidList
	cgroups    patternList
	containers patternList
}

func (f processFilter) active() bool {
	return len(f.names)+len(f.pids)+len(f.cgroups)+len(f.containers) > 0
}

func (f processFilter) String() string {
	var parts []string
	if len(f.names) > 0 {
		parts = append(parts, "process="+f.names.String())
	}
	if len(f.pids) > 0 {
		parts = append(parts, "pid="+f.pids.String())
	}
	if len(f.cgroups) > 0 {
		parts = append(parts, "cgroup="+f.cgroups.String())
	}
	if len(f.containers) > 0 {
		parts = append(parts, "container="+f.containers.String())
	}
	return strings.Join(parts, " ")
}

// patternList is a flag of comma-separated globs.
type patternList []string

func (l *patternList) String() string { return strings.Join(*l, ",") }

func (l *patternList) Set(value string) error {
	for pattern := range strings.SplitSeq(value, ",") {
		if pattern = strings.TrimSpace(pattern); pattern == "" {
			return fmt.Errorf("empty pattern")
		}
		if _, err := pathpkg.Match(pattern, ""); err != nil {
			return fmt.Errorf("pattern %q: %w", pattern, err)
		}
		*l = append(*l, pattern)
	}
	return nil
}

// pidList is a flag of comma-separated PIDs.
type pidList []int

func (l *pidList) String() string {
	texts := make([]string, len(*l))
	for i, pid := range *l {
		texts[i] = strconv.Itoa(pid)
	}
	return strings.Join(texts, ",")
}

func (l *pidList) Set(value string) error {
	for text := range strings.SplitSeq(value, ",") {
		pid, err := strconv.Atoi(strings.TrimSpace(text))
		if err != nil || pid <= 0 {
			return fmt.Errorf("invalid PID %q", text)
		}
		*l = append(*l, pid)
	}
	return nil
}

// nameMatches tests a --process pattern against a process name. The kernel
// keeps 15 bytes of a name, so a longer literal matches its first 15.
func nameMatches(pattern, name string) bool {
	if ok, _ := pathpkg.Match(pattern, name); ok {
		return true
	}
	return len(pattern) > kernelNameSize && !strings.ContainsAny(pattern, `*?[\`) && pattern[:kernelNameSize] == name
}

// cgroupMatches tests a --cgroup pattern: one with a slash is a path prefix
// ending at a directory; one without is a glob on any directory of the
// path, such as nginx.service or docker-*.
func cgroupMatches(pattern, path string) bool {
	if path == "" {
		return false
	}
	if strings.Contains(pattern, "/") {
		prefix := "/" + strings.Trim(pattern, "/")
		return prefix == "/" || path == prefix || strings.HasPrefix(path, prefix+"/")
	}
	for component := range strings.SplitSeq(strings.Trim(path, "/"), "/") {
		if ok, _ := pathpkg.Match(pattern, component); ok {
			return true
		}
	}
	return false
}

func containerMatches(pattern, id string, info *containerInfo) bool {
	if len(pattern) >= 12 && strings.HasPrefix(id, pattern) {
		return true
	}
	if info == nil {
		return false
	}
	for _, name := range []string{info.Name, info.Pod, info.ComposeService} {
		if matched, _ := pathpkg.Match(pattern, name); name != "" && matched {
			return true
		}
	}
	return false
}

// matches reports whether the filter selects a process.
func (t *processTable) matches(f processFilter, id processID, name string) bool {
	m := t.meta(id)
	if m != nil && m.Name != "" {
		name = m.Name
	}
	for _, pattern := range f.names {
		if nameMatches(pattern, name) {
			return true
		}
	}
	if path := t.cgroupOf(m); path != "" {
		for _, pattern := range f.cgroups {
			if cgroupMatches(pattern, path) {
				return true
			}
		}
		if len(f.containers) > 0 {
			containerID, _ := containerIdentity(path)
			if containerID != "" {
				var info *containerInfo
				if t.containers != nil {
					info, _ = t.containers.lookup(path)
				}
				for _, pattern := range f.containers {
					if containerMatches(pattern, containerID, info) {
						return true
					}
				}
			}
		}
	}
	for depth := 0; len(f.pids) > 0 && id.PID > 0 && depth <= maxAncestors; depth++ {
		if slices.Contains(f.pids, id.PID) {
			return true
		}
		if m = t.procs[id]; m == nil {
			break
		}
		id = m.Parent
	}
	return false
}

// processScope decides what a filtered session shows: the selected
// processes, and the flows and I/O they take part in. It caches its answers
// for one screen or report; nil shows everything.
type processScope struct {
	table  *processTable
	filter processFilter
	memo   map[processID]bool
}

func newProcessScope(table *processTable, filter processFilter) *processScope {
	if !filter.active() {
		return nil
	}
	return &processScope{table: table, filter: filter, memo: make(map[processID]bool)}
}

func (s *processScope) process(id processID, name string) bool {
	if s == nil {
		return true
	}
	selected, ok := s.memo[id]
	if !ok {
		selected = s.table.matches(s.filter, id, name)
		s.memo[id] = selected
	}
	return selected
}

func (s *processScope) flow(f *flow, c *collector) bool {
	if s == nil {
		return true
	}
	for _, p := range flowProcesses(f, c) {
		if s.process(p.id(), p.Name) {
			return true
		}
	}
	return false
}

// serviceTotal is one service's socket I/O, processes and connections.
type serviceTotal struct {
	Label, Cgroup string
	RX, TX        uint64
	Processes     []processID
	Connections   int
}

// serviceTotals sums the socket I/O of the processes in scope by service,
// most bytes first, and counts the connections they take part in.
func serviceTotals(c *collector, t *processTable, scope *processScope) []*serviceTotal {
	byKey := make(map[string]*serviceTotal)
	service := func(id processID, name string) *serviceTotal {
		key, label := t.group(id, name, byService)
		s := byKey[key]
		if s == nil {
			s = &serviceTotal{Label: label, Cgroup: strings.TrimPrefix(key, "service:")}
			byKey[key] = s
		}
		return s
	}
	for id, io := range c.pidIO {
		if scope.process(id, io.Name) {
			s := service(id, io.Name)
			s.RX, s.TX = s.RX+io.RX, s.TX+io.TX
			s.Processes = append(s.Processes, id)
		}
	}
	for _, f := range c.allFlows() {
		counted := make(map[*serviceTotal]bool)
		for _, p := range flowProcesses(f, c) {
			if !scope.process(p.id(), p.Name) {
				continue
			}
			if s := service(p.id(), p.Name); !counted[s] {
				counted[s] = true
				s.Connections++
			}
		}
	}
	return slices.SortedFunc(maps.Values(byKey), func(a, b *serviceTotal) int {
		return cmp.Or(cmp.Compare(b.RX+b.TX, a.RX+a.TX), cmp.Compare(b.Connections, a.Connections), strings.Compare(a.Label, b.Label))
	})
}

// flowProcesses lists every process a flow involves: its two ends, the
// processes that did its I/O, and those OpenSSL named it for.
func flowProcesses(f *flow, c *collector) []participant {
	var processes []participant
	add := func(p participant) {
		if p.PID > 0 && !slices.ContainsFunc(processes, func(q participant) bool { return q.id() == p.id() }) {
			processes = append(processes, p)
		}
	}
	add(f.Client)
	add(f.Server)
	for id := range f.IO {
		add(participant{PID: id.PID, StartNS: id.StartNS, Name: c.pidIO[id].Name})
	}
	for _, actor := range f.TLSActors {
		add(actor)
	}
	return processes
}
