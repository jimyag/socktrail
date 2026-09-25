package app

import (
	"encoding/json"
	"net/netip"
	"testing"
	"time"

	"github.com/jimyag/socktrail/internal/capture"
)

func TestReportJSONIncludesStableHostFlowIDAndEnd(t *testing.T) {
	now := time.Now().Add(-3 * time.Second)
	a := netip.MustParseAddrPort("192.0.2.1:40000")
	b := netip.MustParseAddrPort("198.51.100.1:443")
	key := keyFor(a, b, 6)
	c := &collector{flows: map[flowKey]*flow{key: {Key: key, First: now, Last: now, Closed: true, TCPState: "reset"}}}
	host, _, members := hostCollector([]string{"eth0"}, map[string]*collector{"eth0": c})
	var state hostViewState
	state.updateAt(host, members, now.Add(3*time.Second))
	report := reportJSON(host, "OVERVIEW", 10, newProcessTable(t.TempDir()), nil, nil, state.displayedIDs())
	if len(report.Flows) != 1 || report.Flows[0].ID == 0 || report.Flows[0].End != "reset" {
		t.Fatalf("host flow id/end missing: %+v", report.Flows)
	}
}

// The JSON snapshot names what the text one prints, under the documented
// field names.
func TestReportJSON(t *testing.T) {
	client, server := netip.MustParseAddrPort("192.0.2.10:40000"), netip.MustParseAddrPort("192.0.2.80:80")
	c := newTestCollector()
	c.packet(capture.Packet{Source: client, Destination: server, Protocol: 6, HasPorts: true, SYN: true, TCPSeq: 1, IPBytes: 60, Outgoing: true})
	c.packet(tcpPacket(client, server, 2, []byte("GET / HTTP/1.1\r\nHost: api.example.test\r\n\r\n")))
	c.flows[keyFor(client, server, 6)].Client = participant{PID: 42, StartNS: 7, Name: "curl"}
	c.pidIO = map[processID]processIO{{42, 7}: {"curl", ioBytes{RX: 10, TX: 20}}}

	processes := newProcessTable(t.TempDir())
	out, err := json.Marshal(jsonSnapshot{Version: 1, Reports: []jsonReport{reportJSON(c, "eth0", 10, processes, nil, nil, nil)}, Processes: processesJSON(c, 10, processes, nil)})
	if err != nil {
		t.Fatal(err)
	}
	var got struct {
		Reports []struct {
			Scope string
			Flows []struct {
				Protocol, Source, Target string
				RetransmitSource         string `json:"retransmit_source"`
				Client                   struct{ PID int }
				Evidence                 struct {
					Kind  string
					Hosts map[string]int
				}
			}
			Domains []struct {
				Label          string
				HTTPRequests   int `json:"http_requests"`
				Outbound       int
				LocalAddresses []string `json:"local_addresses"`
			}
		}
		Processes []struct {
			PID     int
			Name    string
			TXBytes int `json:"tx_bytes"`
		}
	}
	if err := json.Unmarshal(out, &got); err != nil {
		t.Fatal(err)
	}
	r := got.Reports[0]
	f := r.Flows[0]
	if r.Scope != "eth0" || f.Protocol != "TCP" || f.Source != client.String() || f.Target != server.String() || f.RetransmitSource != "kernel" ||
		f.Client.PID != 42 || f.Evidence.Kind != "http" || f.Evidence.Hosts["api.example.test"] != 1 {
		t.Fatalf("flow %+v in %s", f, out)
	}
	if len(r.Domains) != 1 || r.Domains[0].Label != "HTTP api.example.test" || r.Domains[0].HTTPRequests != 1 || r.Domains[0].Outbound != 1 || len(r.Domains[0].LocalAddresses) != 1 || r.Domains[0].LocalAddresses[0] != client.Addr().String() {
		t.Fatalf("domains %+v", r.Domains)
	}
	if len(got.Processes) != 1 || got.Processes[0].PID != 42 || got.Processes[0].Name != "curl" || got.Processes[0].TXBytes != 20 {
		t.Fatalf("processes %+v", got.Processes)
	}
}
