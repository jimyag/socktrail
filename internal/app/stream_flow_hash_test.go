package app

import (
	"reflect"
	"testing"
	"time"

	"github.com/jimyag/socktrail/internal/domain"
	"github.com/jimyag/socktrail/internal/geoip"
)

func testFlowRow() jsonFlow {
	seen := time.Date(2026, 10, 17, 20, 0, 0, 123456789, time.UTC)
	ja4 := "t13d301200_1d37bd780c83_ecd0401ec68b"
	appLimited := true
	return jsonFlow{
		ID: 4242, End: "fin", Protocol: "TCP", App: "HTTP", State: "established",
		Direction: "outbound", Interfaces: []string{"eno1"},
		Source: "192.0.2.1:5065", Target: "198.51.100.1:22224",
		SourceGeo:        &geoip.Location{CountryCode: "US", Country: "United States", ASN: 15169, Organization: "Example"},
		TargetGeo:        &geoip.Location{CountryCode: "CN", Country: "China", ASN: 4134, Organization: "Example"},
		InitiatorUnknown: true, RXBytes: 1234567, TXBytes: 7654321, Packets: 9876,
		FirstSeen: seen, LastSeen: seen.Add(time.Minute), SYNRTTMicros: 4321,
		ConnectResult: "ok", ConnectLatencyUS: 18002, RTTMicros: 12000,
		RTTSource: "kernel", Retransmits: 3, RetransmitSource: "kernel",
		KernelTCP: []jsonKernelTCP{{
			Local: "192.0.2.1:5065", RTTMicros: 12000, RTTVarMicros: 3000,
			Cwnd: 10, DataSegsOut: 100, Retransmits: 2, BusyMS: 5, RwndMS: 6,
			SndbufMS: 7, DeliveryBPS: 1000000, AppLimited: &appLimited, Limit: "peer window",
		}},
		Client: &jsonProcess{
			PID: 1234, StartNS: 661526840000000, Name: "example-client",
			PPID: 974, Cgroup: "/user.slice/app.slice/app-x.service", Service: "app-x.service",
			Container: &containerInfo{Name: "example", Runtime: "docker", Pod: "pod", Namespace: "default", ComposeProject: "project", ComposeService: "service"},
		},
		Server: &jsonProcess{PID: 3310, StartNS: 12345678, Name: "example-server"},
		IO: []jsonProcessIO{
			{jsonProcess: jsonProcess{PID: 1234, StartNS: 661526840000000, Name: "example-client"}, RXBytes: 100, TXBytes: 200}, //nolint:modernize // Name the embedded field explicitly.
		},
		Name: "example.org", Detail: "JA4 " + ja4,
		Evidence:    &domain.Evidence{Kind: "tls", SNI: "example.org", JA4: &ja4, Hosts: map[string]uint64{"example.org": 3}, ALPN: []string{"h2"}},
		DNS:         &jsonDNS{Queries: 2, Responses: 2, Failures: 1, Name: "example.org", Type: "A", RCode: "NOERROR", RTTMicros: 8000, Recent: []jsonDNSQuery{{Name: "example.org", Type: "A", RCode: "NOERROR", Addresses: []string{"192.0.2.2"}, RTTMicros: 7000, At: seen, Answered: true}}},
		OpenSSLPIDs: []int{1234}, DomainConflict: true, NAT: "192.0.2.1:5065 -> 192.0.2.2:443",
		Drops: map[string]uint64{"qdisc": 3}, Diagnosis: "Retransmissions suggest network trouble",
	}
}

// Follow one wire-field path, creating optional objects so nil fields are
// covered too. Reflection stays in tests, never in the capture loop.
func mutateJSONField(t *testing.T, row *jsonFlow, indices []int) {
	t.Helper()
	indirect := func(v reflect.Value) reflect.Value {
		for v.Kind() == reflect.Pointer || v.Kind() == reflect.Slice {
			if v.Kind() == reflect.Pointer {
				if v.IsNil() {
					v.Set(reflect.New(v.Type().Elem()))
				}
				v = v.Elem()
			} else {
				if v.Len() == 0 {
					v.Set(reflect.MakeSlice(v.Type(), 1, 1))
				}
				v = v.Index(0)
			}
		}
		return v
	}
	v := reflect.ValueOf(row).Elem()
	for _, index := range indices {
		v = indirect(v).Field(index)
	}
	v = indirect(v)
	if v.Type() == reflect.TypeFor[time.Time]() {
		v.Set(reflect.ValueOf(v.Interface().(time.Time).Add(time.Second)))
		return
	}
	switch v.Kind() {
	case reflect.String:
		v.SetString(v.String() + "_changed")
	case reflect.Bool:
		v.SetBool(!v.Bool())
	case reflect.Int, reflect.Int64:
		v.SetInt(v.Int() + 1)
	case reflect.Uint, reflect.Uint32, reflect.Uint64:
		v.SetUint(v.Uint() + 1)
	case reflect.Map:
		if v.IsNil() {
			v.Set(reflect.MakeMap(v.Type()))
		}
		v.SetMapIndex(reflect.ValueOf("_changed"), reflect.ValueOf(uint64(1)))
	default:
		t.Fatalf("no mutation defined for %v", v.Type())
	}
}
