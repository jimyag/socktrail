package app

import (
	"bytes"
	"testing"

	"github.com/vmihailenco/msgpack/v5"
)

// The generated path: one MarshalMsg call, no reflection.
func BenchmarkMessagePackGenerated(b *testing.B) {
	row := testFlowRow()
	frame := streamFrame{Kind: streamKindFlow, Flow: &row}
	buf := make([]byte, 0, 4096)
	b.ReportAllocs()
	for b.Loop() {
		var err error
		buf, err = frame.MarshalMsg(buf[:0])
		if err != nil {
			b.Fatal(err)
		}
	}
	b.ReportMetric(float64(len(buf)), "wire_bytes")
}

// The reflective path the sink uses today.
func BenchmarkMessagePackReflective(b *testing.B) {
	row := testFlowRow()
	var buf bytes.Buffer
	enc := msgpack.NewEncoder(&buf)
	enc.SetCustomStructTag("json")
	frame := streamFrame{Kind: streamKindFlow, Flow: &row}
	size := 0
	b.ReportAllocs()
	for b.Loop() {
		buf.Reset()
		if err := enc.Encode(frame); err != nil {
			b.Fatal(err)
		}
		size = buf.Len()
	}
	b.ReportMetric(float64(size), "wire_bytes")
}

func BenchmarkMessagePackCodec(b *testing.B) {
	row := testFlowRow()
	frame := streamFrame{Kind: streamKindFlow, Flow: &row}
	codec, err := newStreamCodec("msgpack")
	if err != nil {
		b.Fatal(err)
	}
	if _, err := codec.encode(frame); err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	for b.Loop() {
		if _, err := codec.encode(frame); err != nil {
			b.Fatal(err)
		}
	}
}
