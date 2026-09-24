package main

import (
	"slices"
	"strings"
	"time"

	"github.com/jimyag/socktrail/internal/domain"
)

// jsonSnapshot is the --output json document. docs/usage.md lists its
// fields; a change other than an added field raises Version.
type jsonSnapshot struct {
	Version    int             `json:"version"`
	Netns      uint64          `json:"netns"`
	Interfaces []string        `json:"interfaces"`
	Probes     jsonProbes      `json:"probes"`
	Reports    []jsonReport    `json:"reports"`
	Processes  []jsonProcessIO `json:"processes"`
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
	Source           string           `json:"source"`
	Target           string           `json:"target"`
	InitiatorUnknown bool             `json:"initiator_unknown,omitempty"`
	RXBytes          uint64           `json:"rx_bytes"`
	TXBytes          uint64           `json:"tx_bytes"`
	Packets          uint64           `json:"packets"`
	FirstSeen        time.Time        `json:"first_seen"`
	LastSeen         time.Time        `json:"last_seen"`
	SYNRTTMicros     int64            `json:"syn_rtt_us,omitempty"`
	Retransmits      uint64           `json:"retransmits"`
	RetransmitSource string           `json:"retransmit_source,omitempty"`
	Client           *jsonProcess     `json:"client,omitempty"`
	Server           *jsonProcess     `json:"server,omitempty"`
	Name             string           `json:"name,omitempty"`
	Detail           string           `json:"detail,omitempty"`
	Evidence         *domain.Evidence `json:"evidence,omitempty"`
	OpenSSLPIDs      []int            `json:"openssl_pids,omitempty"`
	DomainConflict   bool             `json:"domain_conflict,omitempty"`
	NAT              string           `json:"nat,omitempty"`
}

// jsonProcess identifies a process; PID -1 means several processes share
// the socket.
type jsonProcess struct {
	PID     int    `json:"pid"`
	StartNS uint64 `json:"start_ns,omitempty"`
	Name    string `json:"name,omitempty"`
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

func processJSON(p participant) *jsonProcess {
	switch {
	case p.PID == 0:
		return nil
	case p.PID < 0:
		return &jsonProcess{PID: -1}
	}
	return &jsonProcess{PID: p.PID, StartNS: p.StartNS, Name: p.Name}
}

// reportJSON holds the same rows as printReport, the first limit flows by
// bytes.
func reportJSON(c *collector, scope string, limit int) jsonReport {
	flows := reportFlows(c)
	r := jsonReport{
		Scope: scope, IPPackets: c.packets, IPBytes: c.bytes,
		CaptureDelivered: c.kernelReceived, CaptureDropped: c.kernelDropped, TruncatedPackets: c.truncated,
		ExpiredFlows: c.expiredFlows, PacketsWithoutFlow: c.droppedFlow, PIDIndexDropped: c.droppedRole,
		ParseFailures: parseFailures(flows), HTTPSCoverage: httpsCoverage(flows),
		Flows: []jsonFlow{}, Domains: []jsonDomain{}, InboundAttempts: []jsonAttempt{},
	}
	for _, f := range flows[:min(limit, len(flows))] {
		source, target := displayedEndpoints(f)
		row := jsonFlow{
			Protocol: flowProtocol(f), App: f.AppProtocol, State: flowState(f), Direction: f.Direction,
			Source: strings.TrimPrefix(source, "?"), Target: strings.TrimPrefix(target, "?"), InitiatorUnknown: strings.HasPrefix(source, "?"),
			RXBytes: f.RX, TXBytes: f.TX, Packets: f.Packets, FirstSeen: f.First, LastSeen: f.Last,
			SYNRTTMicros: f.Health.SynRTT.Microseconds(),
			Client:       processJSON(f.Client), Server: processJSON(f.Server),
			Name: flowName(f), DomainConflict: f.DomainConflict,
		}
		if f.Key.EtherType == 0 && f.Key.Protocol == 6 {
			row.Retransmits, row.RetransmitSource = retransmits(f)
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
		a := c.attempts[source]
		r.InboundAttempts = append(r.InboundAttempts, jsonAttempt{source.String(), len(a.Ports), a.Refused, a.Unanswered})
	}
	return r
}

// processesJSON lists PID socket I/O like printPIDIO.
func processesJSON(c *collector, limit int) []jsonProcessIO {
	rows := []jsonProcessIO{}
	for _, id := range pidIOOrder(c.pidIO)[:min(limit, len(c.pidIO))] {
		v := c.pidIO[id]
		rows = append(rows, jsonProcessIO{jsonProcess{id.PID, id.StartNS, v.Name}, v.RX, v.TX})
	}
	return rows
}
