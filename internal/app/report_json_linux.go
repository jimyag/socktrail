package app

import (
	"slices"
	"strings"
	"time"

	"github.com/jimyag/socktrail/internal/domain"
	"github.com/jimyag/socktrail/internal/geoip"
)

// jsonSnapshot is the --output json document. docs/user/usage.md lists its
// fields; a change other than an added field raises Version.
type jsonSnapshot struct {
	Version    int             `json:"version"`
	Netns      uint64          `json:"netns"`
	Interfaces []string        `json:"interfaces"`
	Filter     string          `json:"filter,omitempty"` // The --process, --pid and --cgroup selection, when given.
	Probes     jsonProbes      `json:"probes"`
	GeoIP      string          `json:"geoip"`
	Reports    []jsonReport    `json:"reports"`
	Processes  []jsonProcessIO `json:"processes"`
	Services   []jsonService   `json:"services"`
}

// jsonService is one systemd unit or container: the socket I/O of its
// processes and the connections they take part in.
type jsonService struct {
	Service     string `json:"service"`
	Cgroup      string `json:"cgroup,omitempty"`
	Processes   int    `json:"processes"`
	Connections int    `json:"connections"`
	RXBytes     uint64 `json:"rx_bytes"`
	TXBytes     uint64 `json:"tx_bytes"`
}

type jsonProbes struct {
	PID          jsonProbe `json:"pid"`
	OpenSSL      jsonProbe `json:"openssl"`
	SocketStream jsonProbe `json:"socket_stream"`
	NAT          jsonNAT   `json:"nat"`
}

// jsonProbe counts one probe's events. The OpenSSL probe does not count
// kernel ring losses.
type jsonProbe struct {
	Status     string `json:"status,omitempty"`
	Received   uint64 `json:"received"`
	KernelLost uint64 `json:"kernel_lost"`
	Dropped    uint64 `json:"dropped"`
	Invalid    uint64 `json:"invalid"`
}

type jsonNAT struct {
	Status     string `json:"status"`
	Lookups    uint64 `json:"lookups"`
	Translated uint64 `json:"translated"`
	QueueFull  uint64 `json:"queue_full"`
	Failed     uint64 `json:"failed"`
	LastError  string `json:"last_error,omitempty"`
}

// jsonReport is one table of the text snapshot: OVERVIEW, or one interface
// when --interface names them.
type jsonReport struct {
	Scope              string        `json:"scope"`
	IPPackets          uint64        `json:"ip_packets"`
	IPBytes            uint64        `json:"ip_bytes"`
	CaptureDelivered   uint64        `json:"capture_delivered"`
	CaptureDropped     uint64        `json:"capture_dropped"`
	TruncatedPackets   uint64        `json:"truncated_packets"`
	ExpiredFlows       uint64        `json:"expired_flows"`
	PacketsWithoutFlow uint64        `json:"packets_without_flow"`
	PIDIndexDropped    uint64        `json:"pid_index_dropped"`
	ParseFailures      int           `json:"parse_failures"`
	HTTPSCoverage      string        `json:"https_coverage"`
	Flows              []jsonFlow    `json:"flows"`
	Domains            []jsonDomain  `json:"domains"`
	InboundAttempts    []jsonAttempt `json:"inbound_attempts"`
}

type jsonFlow struct {
	Protocol         string           `json:"protocol"`
	App              string           `json:"app,omitempty"`
	State            string           `json:"state,omitempty"`
	Direction        string           `json:"direction,omitempty"`
	Interfaces       []string         `json:"interfaces,omitempty"` // The capture interfaces that saw it.
	Source           string           `json:"source"`
	Target           string           `json:"target"`
	SourceGeo        *geoip.Location  `json:"source_geo,omitempty"`
	TargetGeo        *geoip.Location  `json:"target_geo,omitempty"`
	InitiatorUnknown bool             `json:"initiator_unknown,omitempty"`
	RXBytes          uint64           `json:"rx_bytes"`
	TXBytes          uint64           `json:"tx_bytes"`
	Packets          uint64           `json:"packets"`
	FirstSeen        time.Time        `json:"first_seen"`
	LastSeen         time.Time        `json:"last_seen"`
	SYNRTTMicros     int64            `json:"syn_rtt_us,omitempty"`
	RTTMicros        int64            `json:"rtt_us,omitempty"`
	RTTSource        string           `json:"rtt_source,omitempty"`
	Retransmits      uint64           `json:"retransmits"`
	RetransmitSource string           `json:"retransmit_source,omitempty"`
	KernelTCP        []jsonKernelTCP  `json:"kernel_tcp,omitempty"`
	Client           *jsonProcess     `json:"client,omitempty"`
	Server           *jsonProcess     `json:"server,omitempty"`
	Name             string           `json:"name,omitempty"`
	Detail           string           `json:"detail,omitempty"`
	Evidence         *domain.Evidence `json:"evidence,omitempty"`
	OpenSSLPIDs      []int            `json:"openssl_pids,omitempty"`
	DomainConflict   bool             `json:"domain_conflict,omitempty"`
	NAT              string           `json:"nat,omitempty"`
}

// jsonKernelTCP is a local end's socket as the kernel last reported it.
type jsonKernelTCP struct {
	Local        string `json:"local"`
	RTTMicros    int64  `json:"rtt_us"`
	RTTVarMicros int64  `json:"rttvar_us"`
	Cwnd         uint32 `json:"cwnd"`
	DataSegsOut  uint32 `json:"data_segs_out"`
	Retransmits  uint32 `json:"retransmits"`
}

// jsonProcess identifies a process; PID -1 means several processes share
// the socket.
type jsonProcess struct {
	PID     int    `json:"pid"`
	StartNS uint64 `json:"start_ns,omitempty"`
	Name    string `json:"name,omitempty"`
	PPID    int    `json:"ppid,omitempty"`
	Cgroup  string `json:"cgroup,omitempty"`
	Service string `json:"service,omitempty"`
}

type jsonProcessIO struct {
	jsonProcess
	RXBytes uint64 `json:"rx_bytes"`
	TXBytes uint64 `json:"tx_bytes"`
}

type jsonDomain struct {
	Label        string `json:"label"`
	Connections  uint64 `json:"connections"`
	RXBytes      uint64 `json:"rx_bytes"`
	TXBytes      uint64 `json:"tx_bytes"`
	HTTPRequests uint64 `json:"http_requests"`
	UnknownPID   uint64 `json:"unknown_pid"`
}

type jsonAttempt struct {
	Source     string `json:"source"`
	Ports      int    `json:"ports"`
	Refused    uint64 `json:"refused"`
	Unanswered uint64 `json:"unanswered"`
}

func processJSON(p participant, processes *processTable) *jsonProcess {
	switch {
	case p.PID == 0:
		return nil
	case p.PID < 0:
		return &jsonProcess{PID: -1}
	}
	j := &jsonProcess{PID: p.PID, StartNS: p.StartNS, Name: p.Name}
	if m := processes.meta(p.id()); m != nil {
		j.PPID, j.Cgroup = m.Parent.PID, processes.cgroupOf(m)
		if j.Cgroup != "" {
			_, j.Service = serviceOf(j.Cgroup)
		}
	}
	return j
}

// reportJSON holds the same rows as printReport, the first limit flows by
// bytes.
func reportJSON(c *collector, name string, limit int, processes *processTable, scope *processScope, geo *geoip.DB) jsonReport {
	flows := reportFlows(c, scope)
	r := jsonReport{
		Scope: name, IPPackets: c.packets, IPBytes: c.bytes,
		CaptureDelivered: c.kernelReceived, CaptureDropped: c.kernelDropped, TruncatedPackets: c.truncated,
		ExpiredFlows: c.expiredFlows, PacketsWithoutFlow: c.droppedFlow, PIDIndexDropped: c.droppedRole,
		ParseFailures: parseFailures(flows), HTTPSCoverage: httpsCoverage(flows),
		Flows: []jsonFlow{}, Domains: []jsonDomain{}, InboundAttempts: []jsonAttempt{},
	}
	for _, f := range flows[:min(limit, len(flows))] {
		source, target := displayedEndpoints(f)
		row := jsonFlow{
			Protocol: flowProtocol(f), App: f.AppProtocol, State: flowState(f), Direction: f.Direction, Interfaces: interfacesOf(f.Interfaces),
			Source: strings.TrimPrefix(source, "?"), Target: strings.TrimPrefix(target, "?"), InitiatorUnknown: strings.HasPrefix(source, "?"),
			RXBytes: f.RX, TXBytes: f.TX, Packets: f.Packets, FirstSeen: f.First, LastSeen: f.Last,
			SYNRTTMicros: f.Health.SynRTT.Microseconds(),
			Client:       processJSON(f.Client, processes), Server: processJSON(f.Server, processes),
			Name: flowName(f), DomainConflict: f.DomainConflict,
		}
		if geo != nil {
			sourceIP, targetIP := endpointAddresses(f)
			row.SourceGeo, row.TargetGeo = geo.Lookup(sourceIP), geo.Lookup(targetIP)
		}
		if f.Key.EtherType == 0 && f.Key.Protocol == 6 {
			row.Retransmits, row.RetransmitSource = retransmits(f)
			rtt, source := flowRTT(f)
			row.RTTMicros, row.RTTSource = rtt.Microseconds(), source
			for _, side := range kernelSides(f) {
				k, local := f.Health.Kernel[side], f.Key.A
				if side == 1 {
					local = f.Key.B
				}
				row.KernelTCP = append(row.KernelTCP, jsonKernelTCP{local.String(), k.RTT.Microseconds(), k.RTTVar.Microseconds(), k.Cwnd, k.SegsOut, k.Retransmits})
			}
		}
		if f.Domain != nil {
			e := f.Domain.Evidence()
			row.Evidence, row.Detail = &e, e.Detail()
		}
		for id := range f.TLSActors {
			row.OpenSSLPIDs = append(row.OpenSSLPIDs, id.PID)
		}
		slices.Sort(row.OpenSSLPIDs)
		if f.NAT != nil {
			row.NAT = f.NAT.String()
		}
		r.Flows = append(r.Flows, row)
	}
	totals, labels := domainSummary(flows)
	for _, label := range labels {
		t := totals[label]
		r.Domains = append(r.Domains, jsonDomain{label, t.Connections, t.RX, t.TX, t.Requests, t.UnknownPID})
	}
	for _, source := range attemptSources(c.attempts) {
		if scope != nil {
			break // Attempts have no process.
		}
		a := c.attempts[source]
		r.InboundAttempts = append(r.InboundAttempts, jsonAttempt{source.String(), len(a.Ports), a.Refused, a.Unanswered})
	}
	return r
}

// processesJSON lists PID socket I/O like printPIDIO.
func processesJSON(c *collector, limit int, processes *processTable, scope *processScope) []jsonProcessIO {
	rows := []jsonProcessIO{}
	for _, id := range pidIOOrder(c.pidIO) {
		if v := c.pidIO[id]; scope.process(id, v.Name) && len(rows) < limit {
			rows = append(rows, jsonProcessIO{*processJSON(participant{PID: id.PID, StartNS: id.StartNS, Name: v.Name}, processes), v.RX, v.TX})
		}
	}
	return rows
}

// servicesJSON lists socket I/O by service like printServices, all of them.
func servicesJSON(c *collector, processes *processTable, scope *processScope) []jsonService {
	rows := []jsonService{}
	for _, s := range serviceTotals(c, processes, scope) {
		rows = append(rows, jsonService{s.Label, s.Cgroup, len(s.Processes), s.Connections, s.RX, s.TX})
	}
	return rows
}
