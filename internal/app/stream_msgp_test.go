package app

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"math"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/vmihailenco/msgpack/v5"
)

// Compare decoded objects, not bytes: integer widths and map order can differ
// without changing MessagePack values. JSON normalization preserves uint64
// exactly and normalizes the integer widths chosen by the two encoders.
func assertMessagePackCompatible(t *testing.T, v any) {
	t.Helper()
	var old bytes.Buffer
	encoder := msgpack.NewEncoder(&old)
	encoder.SetCustomStructTag("json")
	if err := encoder.Encode(v); err != nil {
		t.Fatal(err)
	}
	codec, err := newStreamCodec("msgpack")
	if err != nil {
		t.Fatal(err)
	}
	generated, err := codec.encode(v)
	if err != nil {
		t.Fatal(err)
	}
	normalize := func(raw []byte) []byte {
		t.Helper()
		decoder := msgpack.NewDecoder(bytes.NewReader(raw))
		var value any
		if err := decoder.Decode(&value); err != nil {
			t.Fatal(err)
		}
		var extra any
		if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
			t.Fatalf("extra bytes after frame: %v", err)
		}
		normalizeOptionalContainers(value, reflect.TypeOf(v))
		out, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		return out
	}
	if got, want := normalize(generated), normalize(old.Bytes()); !bytes.Equal(got, want) {
		t.Fatalf("generated codec changed the wire values:\n got: %s\nwant: %s", got, want)
	}
}

// msgp retains non-nil empty optional containers; the old codec omits them.
// Only normalize that permitted representation difference. Required fields,
// pointer presence (including pointers to empty objects), scalars and values
// remain subject to exact equality.
func normalizeOptionalContainers(value any, typ reflect.Type) {
	for typ.Kind() == reflect.Pointer {
		typ = typ.Elem()
	}
	if object, ok := value.(map[string]any); ok && typ.Kind() == reflect.Struct {
		for field := range typ.Fields() {
			if field.Anonymous {
				normalizeOptionalContainers(value, field.Type)
				continue
			}
			key, options, _ := strings.Cut(field.Tag.Get("json"), ",")
			nested, present := object[key]
			if !present || nested == nil {
				continue
			}
			if strings.Contains(options, "omitempty") && (field.Type.Kind() == reflect.Slice || field.Type.Kind() == reflect.Map) {
				if reflect.ValueOf(nested).Len() == 0 {
					delete(object, key)
					continue
				}
			}
			normalizeOptionalContainers(nested, field.Type)
		}
	} else if array, ok := value.([]any); ok && typ.Kind() == reflect.Slice {
		for _, nested := range array {
			normalizeOptionalContainers(nested, typ.Elem())
		}
	}
}

func TestGeneratedMessagePackMatchesReflective(t *testing.T) {
	at := time.Date(2026, 10, 25, 12, 0, 0, 123456789, time.UTC)
	row := testFlowRow()
	for name, value := range map[string]any{
		"populated": streamFrame{Kind: streamKindFlow, Flow: &row},
		"bare":      row,
		"zero":      jsonFlow{},
		"hello": streamFrame{Kind: streamKindHello, Hello: &streamHello{
			Version: 1, Mode: "live", Started: at, Interfaces: []string{"eno1", "lo"},
		}},
		"stats": streamFrame{Kind: streamKindStats, Stats: &streamSummary{
			At: at, IPPackets: math.MaxUint64, IPBytes: math.MaxUint64,
			ProcessIO: row.IO, IOUnindexed: streamIOBytes{RXBytes: 7, TXBytes: 9},
			Probes: jsonProbes{PID: jsonProbe{Received: math.MaxUint64}},
		}},
		"nil_process_io":   streamFrame{Kind: streamKindStats, Stats: &streamSummary{}},
		"empty_process_io": streamFrame{Kind: streamKindStats, Stats: &streamSummary{ProcessIO: []jsonProcessIO{}}},
	} {
		t.Run(name, func(t *testing.T) { assertMessagePackCompatible(t, value) })
	}
}

// A regenerated encoder must keep every leaf, including embedded process
// fields, optional pointers, maps and future fields added to the schema.
func TestGeneratedMessagePackCoversFlowFields(t *testing.T) {
	var walk func(reflect.Type, string, []int)
	walk = func(typ reflect.Type, path string, indices []int) {
		for typ.Kind() == reflect.Pointer || typ.Kind() == reflect.Slice {
			typ = typ.Elem()
		}
		if typ.Kind() == reflect.Struct && typ != reflect.TypeFor[time.Time]() {
			for i := range typ.NumField() {
				field := typ.Field(i)
				if field.Tag.Get("json") == "-" {
					continue
				}
				walk(field.Type, path+"/"+field.Name, append(slices.Clone(indices), i))
			}
			return
		}
		t.Run(path, func(t *testing.T) {
			row := testFlowRow()
			mutateJSONField(t, &row, indices)
			assertMessagePackCompatible(t, row)
		})
	}
	walk(reflect.TypeFor[jsonFlow](), "flow", nil)
}

func TestGeneratedMessagePackTimestampsAndIntegerLimits(t *testing.T) {
	for _, at := range []time.Time{
		{},
		time.Unix(0, 0).UTC(), time.Unix(-1, 123456789).UTC(),
		time.Unix(1700000000, 0).UTC(), time.Unix(1700000000, 999999999).UTC(),
		time.Unix(1<<34, 123).UTC(),
	} {
		t.Run(at.String(), func(t *testing.T) {
			row := testFlowRow()
			row.FirstSeen, row.LastSeen, row.DNS.Recent[0].At = at, at, at
			row.ID, row.RXBytes, row.TXBytes = math.MaxUint64, math.MaxUint64, math.MaxUint64
			row.Client.PID, row.RTTMicros = -1, math.MinInt64
			assertMessagePackCompatible(t, streamFrame{Kind: streamKindFlow, Flow: &row})
		})
	}
}

// Guard the generator configuration as well as emitted code: native
// time.Time uses the standard extension, and IO actors stay flattened.
func TestGeneratedMessagePackRoundTrip(t *testing.T) {
	row := testFlowRow()
	frame := streamFrame{Kind: streamKindFlow, Flow: &row}
	raw, err := frame.MarshalMsg(nil)
	if err != nil {
		t.Fatal(err)
	}
	var back streamFrame
	rest, err := back.UnmarshalMsg(raw)
	if err != nil || len(rest) != 0 {
		t.Fatalf("decode: %v (%d bytes remaining)", err, len(rest))
	}
	if !reflect.DeepEqual(frame, back) {
		t.Fatalf("round trip changed frame: got %+v, want %+v", back, frame)
	}
	var decoded map[string]any
	if err := msgpack.Unmarshal(raw, &decoded); err != nil {
		t.Fatal(err)
	}
	flow := decoded["flow"].(map[string]any)
	if _, ok := flow["first_seen"].(time.Time); !ok {
		t.Fatalf("first_seen is %T, not a standard timestamp", flow["first_seen"])
	}
	actor := flow["io"].([]any)[0].(map[string]any)
	if _, nested := actor["jsonProcess"]; nested || actor["pid"] == nil {
		t.Fatalf("IO process must be flattened: %v", actor)
	}
	// Reusing a decoder target must clear previously present optional fields.
	empty := streamFrame{Kind: streamKindFlow, Flow: &jsonFlow{Protocol: "UDP"}}
	raw, err = empty.MarshalMsg(raw[:0])
	if err != nil {
		t.Fatal(err)
	}
	if _, err := back.UnmarshalMsg(raw); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(empty, back) {
		t.Fatalf("decoder retained omitted fields: %+v", back.Flow)
	}
}

// Custom msg tags are generator-only; they must not change JSON field names.
func TestGeneratedMessagePackTags(t *testing.T) {
	field, ok := reflect.TypeFor[jsonProcessIO]().FieldByName("jsonProcess")
	if !ok || !strings.Contains(field.Tag.Get("msg"), "flatten") {
		t.Fatal("embedded IO process must use msgp flatten")
	}
}

func TestGeneratedMessagePackOptionalValues(t *testing.T) {
	for _, empty := range []bool{false, true} {
		t.Run(map[bool]string{false: "nil", true: "empty"}[empty], func(t *testing.T) {
			row := testFlowRow()
			row.Interfaces, row.IO, row.KernelTCP, row.Drops, row.OpenSSLPIDs = nil, nil, nil, nil, nil
			row.Evidence.ALPN, row.Evidence.Certificate, row.Evidence.Hosts = nil, nil, nil
			row.Evidence.JA4, row.Evidence.ProxyAuthority = nil, nil
			row.DNS.Recent, row.DNS.Name = nil, ""
			row.Client.Container, row.Server = nil, nil
			if empty {
				emptyString := ""
				row.Interfaces, row.IO, row.KernelTCP = []string{}, []jsonProcessIO{}, []jsonKernelTCP{}
				row.Drops, row.OpenSSLPIDs = map[string]uint64{}, []int{}
				row.Evidence.ALPN, row.Evidence.Certificate = []string{}, []string{}
				row.Evidence.Hosts = map[string]uint64{}
				row.Evidence.JA4, row.Evidence.ProxyAuthority = &emptyString, &emptyString
				row.DNS.Recent = []jsonDNSQuery{}
			}
			assertMessagePackCompatible(t, streamFrame{Kind: streamKindFlow, Flow: &row})
		})
	}
	row := testFlowRow()
	value := false
	row.KernelTCP[0].AppLimited = &value
	assertMessagePackCompatible(t, row)
}
