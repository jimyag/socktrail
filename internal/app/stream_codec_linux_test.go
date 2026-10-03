package app

import (
	"bytes"
	"encoding/json"
	"fmt"
	"maps"
	"slices"
	"testing"
	"time"

	"github.com/vmihailenco/msgpack/v5"

	"github.com/jimyag/socktrail/internal/domain"
	"github.com/jimyag/socktrail/internal/geoip"
)

// decodedJSON is the row as the documented JSON encoding shows it.
func decodedJSON(t *testing.T, v any) map[string]any {
	t.Helper()
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal json: %v", err)
	}
	out := map[string]any{}
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("unmarshal json: %v", err)
	}
	return out
}

// decodedMsgpack is the same row through the stream codec, so a test compares
// the two encodings field by field.
func decodedMsgpack(t *testing.T, v any) map[string]any {
	t.Helper()
	codec, err := newStreamCodec("msgpack")
	if err != nil {
		t.Fatalf("newStreamCodec: %v", err)
	}
	frame, err := codec.encode(v)
	if err != nil {
		t.Fatalf("encode msgpack: %v", err)
	}
	out := map[string]any{}
	decoder := msgpack.NewDecoder(bytes.NewReader(frame))
	decoder.SetCustomStructTag("json")
	if err := decoder.Decode(&out); err != nil {
		t.Fatalf("decode msgpack: %v", err)
	}
	return out
}

// assertSameKeys walks both encodings and reports every map whose key set
// differs. Nested maps and slices of maps are compared recursively.
func assertSameKeys(t *testing.T, path string, fromJSON, fromMsgpack any) {
	t.Helper()
	switch value := fromJSON.(type) {
	case map[string]any:
		other, ok := fromMsgpack.(map[string]any)
		if !ok {
			t.Errorf("%s: json is an object, msgpack is %T", path, fromMsgpack)
			return
		}
		jsonKeys, msgpackKeys := slices.Sorted(maps.Keys(value)), slices.Sorted(maps.Keys(other))
		if !slices.Equal(jsonKeys, msgpackKeys) {
			t.Errorf("%s: keys differ\n json:    %v\n msgpack: %v", path, jsonKeys, msgpackKeys)
		}
		for key, nested := range value {
			if otherNested, ok := other[key]; ok {
				assertSameKeys(t, path+"."+key, nested, otherNested)
			}
		}
	case []any:
		other, ok := fromMsgpack.([]any)
		if !ok {
			t.Errorf("%s: json is an array, msgpack is %T", path, fromMsgpack)
			return
		}
		for i := range min(len(value), len(other)) {
			assertSameKeys(t, fmt.Sprintf("%s[%d]", path, i), value[i], other[i])
		}
	}
}

// MsgpackFlow covers every nested type a flow frame can carry, so the two
// encodings are compared where the fields actually nest.
func MsgpackFlow() jsonFlow {
	ja4 := "t13d1516h2_8daaf6152771_b186095e22b6"
	actor := jsonProcess{PID: 4412, StartNS: 812345, Name: "curl"}
	return jsonFlow{
		ID: 7, End: "fin", Changes: []string{"new"}, Protocol: "tcp", App: "tls",
		State: "established", Direction: "outbound", Interfaces: []string{"eth0"},
		Source: "10.0.0.1:40000", Target: "93.184.216.34:443",
		SourceGeo: &geoip.Location{CountryCode: "US", Country: "United States", ASN: 15133, Organization: "Edgecast"},
		TargetGeo: &geoip.Location{CountryCode: "NL"},
		RXBytes:   4096, TXBytes: 512, Packets: 12,
		FirstSeen:    time.Date(2025, time.January, 2, 3, 4, 5, 0, time.UTC),
		LastSeen:     time.Date(2025, time.January, 2, 3, 4, 6, 500000000, time.UTC),
		SYNRTTMicros: 18000, ConnectResult: "connected", ConnectLatencyUS: 19000,
		RTTMicros: 17500, RTTSource: "kernel", Retransmits: 2, RetransmitSource: "kernel",
		KernelTCP: []jsonKernelTCP{{
			Local: "10.0.0.1:40000", RTTMicros: 17500, RTTVarMicros: 2000, Cwnd: 10,
			DataSegsOut: 4, Retransmits: 2, BusyMS: 30, DeliveryBPS: 8000000, Limit: "cwnd",
		}},
		Client: &jsonProcess{
			PID: 4412, StartNS: 812345, Name: "curl", PPID: 4390,
			Cgroup: "/user.slice/session-3.scope", Service: "session-3.scope",
			Container: &containerInfo{Name: "web", Runtime: "docker", Pod: "api-0", Namespace: "default", ComposeProject: "stack", ComposeService: "api"},
		},
		Server: &jsonProcess{PID: 1},
		IO:     []jsonProcessIO{{jsonProcess: actor, RXBytes: 4096, TXBytes: 512}},
		Name:   "TLS example.com", Detail: "TLS ClientHello server_name",
		Evidence: &domain.Evidence{
			Kind: "tls", SNI: "example.com", ALPN: []string{"h2"}, JA4: &ja4,
			Hosts: map[string]uint64{"example.com": 3}, TLSVersion: "1.3", GRPC: true,
		},
		DNS: &jsonDNS{
			Queries: 2, Responses: 2, Name: "example.com", Type: "A", RCode: "NOERROR", RTTMicros: 500,
			Recent: []jsonDNSQuery{{
				Name: "example.com", Type: "A", RCode: "NOERROR",
				Addresses: []string{"93.184.216.34"}, RTTMicros: 500, At: time.Unix(1700000000, 0).UTC(), Answered: true,
			}},
		},
		OpenSSLPIDs: []int{4412}, DomainConflict: true, NAT: "10.0.0.1:40000",
		Drops: map[string]uint64{"no_socket": 2}, Diagnosis: "retransmits point at a lossy path",
	}
}

func TestMsgpackMatchesJSONFields(t *testing.T) {
	row := MsgpackFlow()
	assertSameKeys(t, "flow", decodedJSON(t, row), decodedMsgpack(t, row))
}

// A zero-valued flow is where omitzero and omitempty have to agree: json drops
// the field through omitzero, msgpack drops it through the explicit tag.
func TestMsgpackOmitsZeroFieldsLikeJSON(t *testing.T) {
	row := jsonFlow{Protocol: "tcp", Source: "a", Target: "b"}
	fromJSON, fromMsgpack := decodedJSON(t, row), decodedMsgpack(t, row)
	assertSameKeys(t, "flow", fromJSON, fromMsgpack)
	for _, field := range []string{"id", "connect_latency_us"} {
		if _, present := fromMsgpack[field]; present {
			t.Errorf("msgpack kept zero-valued %q, json drops it", field)
		}
	}
}

// The snapshot types go through the same codec for the socket output.
func TestMsgpackMatchesJSONSnapshotFields(t *testing.T) {
	actor := jsonProcess{PID: 4412, Name: "curl"}
	snapshot := jsonSnapshot{
		Version: 1, Netns: 42, Interfaces: []string{"eth0"}, Filter: "--process curl",
		Reports: []jsonReport{{
			Scope: "OVERVIEW", IPPackets: 10, IPBytes: 900, HTTPSCoverage: "partial",
			Flows:           []jsonFlow{MsgpackFlow()},
			Domains:         []jsonDomain{{Label: "example.com", Connections: 1, RXBytes: 4096, LocalAddresses: []string{"10.0.0.1"}}},
			InboundAttempts: []jsonAttempt{{Source: "10.0.0.9", Ports: 2, Refused: 1}},
		}},
		Processes: []jsonProcessIO{{jsonProcess: actor, RXBytes: 4096, TXBytes: 512}},
		Services:  []jsonService{{Service: "session-3.scope", Connections: 1, RXBytes: 4096}},
		Failures: []jsonFailure{{
			Reason: "refused", Process: "curl", PID: 4412, Target: "10.0.0.9:80",
			Count: 1, First: time.Unix(1700000000, 0).UTC(), Last: time.Unix(1700000001, 0).UTC(), IDs: []uint64{7},
		}},
		Listeners: []jsonListener{{Protocol: "tcp", Bind: "0.0.0.0", Port: 8080, Process: "nginx", Active: 1, Queue: new(uint32)}},
		Drops:     []jsonDrop{{Reason: "no_socket", Count: 2}},
	}
	assertSameKeys(t, "snapshot", decodedJSON(t, snapshot), decodedMsgpack(t, snapshot))
}

// Times travel as MessagePack timestamps, not RFC3339 strings. Field names and
// absolute instants match the JSON encoding, and a consumer using a MessagePack
// library gets time.Time back. The alternative, wrapping every time field in a
// string type to make the two encodings byte-comparable, costs a wrapper type
// plus custom json marshalling and buys nothing the library does not already do.
func TestMsgpackEncodesTimesAsTimestamps(t *testing.T) {
	at := time.Date(2025, time.January, 2, 3, 4, 5, 0, time.UTC)
	row := jsonFlow{Protocol: "tcp", FirstSeen: at}
	fromJSON, fromMsgpack := decodedJSON(t, row), decodedMsgpack(t, row)
	if _, ok := fromJSON["first_seen"].(string); !ok {
		t.Fatalf("json first_seen should be a string, got %T", fromJSON["first_seen"])
	}
	got, ok := fromMsgpack["first_seen"].(time.Time)
	if !ok {
		t.Fatalf("msgpack first_seen should decode to time.Time, got %T", fromMsgpack["first_seen"])
	}
	if !got.Equal(at) {
		t.Errorf("msgpack first_seen = %v, want %v", got, at)
	}
}

// Rows written one after another must decode back one at a time. MessagePack
// frames are self-delimiting and the stream output relies on that; NDJSON
// relies on the newline json.Encoder appends.
func TestStreamFramesDecodeInSequence(t *testing.T) {
	rows := []jsonFlow{
		{Protocol: "tcp", Source: "10.0.0.1:1", Target: "10.0.0.2:443", Changes: []string{"new"}},
		{Protocol: "udp", Source: "10.0.0.3:53", Target: "10.0.0.4:40000", Changes: []string{"refresh"}},
	}
	t.Run("msgpack", func(t *testing.T) {
		codec, err := newStreamCodec("msgpack")
		if err != nil {
			t.Fatal(err)
		}
		var out bytes.Buffer
		for _, row := range rows {
			if err := emit(codec, &out, row); err != nil {
				t.Fatalf("emit: %v", err)
			}
		}
		decoder := msgpack.NewDecoder(&out)
		decoder.SetCustomStructTag("json")
		for i, want := range rows {
			var got jsonFlow
			if err := decoder.Decode(&got); err != nil {
				t.Fatalf("frame %d: %v", i, err)
			}
			if got.Protocol != want.Protocol || got.Source != want.Source || !slices.Equal(got.Changes, want.Changes) {
				t.Errorf("frame %d = %+v, want %+v", i, got, want)
			}
		}
	})
	t.Run("ndjson", func(t *testing.T) {
		codec, err := newStreamCodec("ndjson")
		if err != nil {
			t.Fatal(err)
		}
		var out bytes.Buffer
		for _, row := range rows {
			if err := emit(codec, &out, row); err != nil {
				t.Fatalf("emit: %v", err)
			}
		}
		decoder := json.NewDecoder(&out)
		for i, want := range rows {
			var got jsonFlow
			if err := decoder.Decode(&got); err != nil {
				t.Fatalf("frame %d: %v", i, err)
			}
			if got.Protocol != want.Protocol || got.Source != want.Source || !slices.Equal(got.Changes, want.Changes) {
				t.Errorf("frame %d = %+v, want %+v", i, got, want)
			}
		}
	})
}
