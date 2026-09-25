package app

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/jimyag/socktrail/internal/capture"
	"github.com/jimyag/socktrail/internal/domain"
	"github.com/jimyag/socktrail/internal/geoip"
	"github.com/jimyag/socktrail/internal/pcapng"
	"github.com/jimyag/socktrail/internal/probe"
	"golang.org/x/term"
)

var recordingField = regexp.MustCompile(`[a-z_]+=(?:"(?:\\.|[^"\\])*"|[^ ]+)`)

func recordingFields(comment string) map[string]string {
	if !strings.HasPrefix(comment, "socktrail ") {
		return nil
	}
	fields := make(map[string]string)
	for _, field := range recordingField.FindAllString(comment, -1) {
		key, value, _ := strings.Cut(field, "=")
		if strings.HasPrefix(value, `"`) {
			unquoted, err := strconv.Unquote(value)
			if err != nil {
				continue
			}
			value = unquoted
		}
		fields[key] = value
	}
	return fields
}

func recordedParticipant(fields map[string]string, prefix string) participant {
	pid, _ := strconv.Atoi(fields[prefix+"_pid"])
	start, _ := strconv.ParseUint(fields[prefix+"_start_ns"], 10, 64)
	if pid <= 0 {
		return participant{}
	}
	return participant{PID: pid, StartNS: start, Name: fields[prefix+"_process"]}
}

func readRecording(r io.Reader, port uint16) (map[string]*collector, []string, *processTable, time.Time, error) {
	collectors := make(map[string]*collector)
	processes := newProcessTable("") // Every known identity comes from the recording; no live /proc lookup.
	dns := new(domain.DNSCache)
	labels := make(map[*flow]string)
	var names []string
	var first time.Time
	err := pcapng.Read(r, func(item pcapng.RecordedPacket) error {
		c := collectors[item.Interface]
		if c == nil {
			c = &collector{flows: make(map[flowKey]*flow), dns: dns, roles: make(map[flowKey]roles), wildcards: make(map[wildcardKey]participant), roleSeen: make(map[flowKey]time.Time), wildcardSeen: make(map[wildcardKey]time.Time), pidIO: make(map[processID]processIO), pidSeen: make(map[processID]time.Time), maxFlows: 20_000, filterPort: port, loopback: strings.HasSuffix(item.Interface, ":lo") || item.Interface == "lo", interfaceIndex: len(names)}
			collectors[item.Interface] = c
			names = append(names, item.Interface)
		}
		fields := recordingFields(item.Comment)
		p, ok := capture.Decode(item.Frame, fields["packet_direction"] == "tx")
		if !ok {
			return nil
		}
		p.Interface, p.CapturedAt, p.Truncated = item.Interface, item.At, uint64(item.WireLen) > uint64(len(item.Frame))
		p.FrameLen = int(item.WireLen)
		if first.IsZero() || item.At.Before(first) {
			first = item.At
		}
		c.packet(p)
		if !c.acceptPort(p.Source, p.Destination) {
			return nil
		}
		f := c.flows[packetKey(p)]
		if f == nil {
			return nil
		}
		if f.First.After(item.At) {
			f.First = item.At
		}
		if f.Last.Before(item.At) || f.Last.After(item.At.Add(time.Minute)) {
			f.Last = item.At
		}
		for _, side := range []struct {
			prefix string
			dst    *participant
		}{{"origin", &f.Client}, {"target", &f.Server}} {
			if p := recordedParticipant(fields, side.prefix); p.PID > 0 {
				*side.dst = p
				if _, known := processes.procs[p.id()]; !known && len(processes.procs) < maxProcesses {
					processes.procs[p.id()] = &processMeta{Name: p.Name}
				}
			}
		}
		if f.AppProtocol == "" {
			f.AppProtocol, f.AppSource = fields["app"], fields["app_source"]
		}
		if f.Direction == "unknown" && fields["flow_direction"] != "" {
			f.Direction = fields["flow_direction"]
		}
		if fields["domain"] != "" {
			labels[f] = fields["domain"]
		}
		return nil
	})
	if err != nil {
		return nil, nil, nil, time.Time{}, err
	}
	if len(names) == 0 {
		return nil, nil, nil, time.Time{}, fmt.Errorf("PCAPNG has no decodable packets")
	}
	for f, label := range labels {
		if f.Domain == nil || !f.Domain.Evidence().Named() {
			f.Domain = domain.NewRecordedLabel(label)
		}
	}
	captureInterfaces = names
	return collectors, names, processes, first, nil
}

func replayPCAPNG(path, output string, limit int, port uint16, filter processFilter, conditions []condition, geo *geoip.DB) error {
	//nolint:gosec // G304: --read explicitly names the recording to inspect.
	file, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("open PCAPNG: %w", err)
	}
	defer func() { _ = file.Close() }()
	if info, err := file.Stat(); err != nil {
		return err
	} else if !info.Mode().IsRegular() || info.Size() > recordingLimit {
		return fmt.Errorf("--read requires a regular socktrail recording no larger than %d MiB", recordingLimit>>20)
	}
	collectors, names, processes, first, err := readRecording(file, port)
	if err != nil {
		return fmt.Errorf("read PCAPNG: %w", err)
	}
	host, _, members := hostCollector(names, collectors)
	var state hostViewState
	state.update(host, members)
	scope := newProcessScope(processes, filter)
	if output == "json" {
		snapshot := jsonSnapshot{Version: 1, Source: "pcapng", Interfaces: names, GeoIP: geo.Status(), Probes: jsonProbes{PID: jsonProbe{Status: "offline recording"}, OpenSSL: jsonProbe{Status: "offline recording"}, SocketStream: jsonProbe{Status: "offline recording"}, NAT: jsonNAT{Status: "offline recording"}}, Reports: []jsonReport{reportJSON(host, "OVERVIEW", limit, processes, scope, geo, state.displayedIDs(), conditions)}, Processes: processesJSON(host, limit, processes, scope), Services: servicesJSON(host, processes, scope)}
		encoder := json.NewEncoder(os.Stdout)
		encoder.SetIndent("", "  ")
		return encoder.Encode(snapshot)
	}
	if !term.IsTerminal(int(os.Stdin.Fd())) || !term.IsTerminal(int(os.Stdout.Fd())) {
		fmt.Printf("socktrail PCAPNG replay: %s (%d interfaces)\n", path, len(names))
		printReport(*host, "OVERVIEW", limit, new(probe.Statistics), scope, flowFilter{conditions, processes, geo})
		return nil
	}
	u, err := openUI(names, 0, collectors)
	if err != nil {
		return err
	}
	defer u.close()
	u.offline, u.started, u.processes, u.scopeFilter, u.hostState = true, first, processes, filter, &state
	u.geo, u.showGeo = geo, geo.Available()
	u.tlsProbeStatus, u.streamStatus, u.connectStatus = "Offline PCAPNG; probes were not recorded", "Offline PCAPNG", "Offline PCAPNG"
	u.render(host, 0, 0, 0)
	current := func() *collector {
		if !u.hostScope && u.mode != viewLog && u.mode != viewPorts && u.mode != viewInterfaces {
			return collectors[u.interfaceName]
		}
		return host
	}
	for input := range u.keys {
		if u.handleInput(input, current()) {
			break
		}
		u.render(current(), 0, 0, 0)
	}
	return nil
}
