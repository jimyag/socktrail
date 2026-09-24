package domain

import (
	"bytes"
	"encoding/binary"
	"testing"

	"golang.org/x/net/http2/hpack"
)

// h2cClient writes what a cleartext HTTP/2 client sends: the preface,
// SETTINGS, then per request a header block and a DATA frame of dataLen.
// The second request's block is split into HEADERS and CONTINUATION.
func h2cClient(t *testing.T, dataLen int, requests ...[]hpack.HeaderField) []byte {
	t.Helper()
	var out, block bytes.Buffer
	frame := func(kind, flags byte, stream uint32, payload []byte) {
		out.Write([]byte{byte(len(payload) >> 16), byte(len(payload) >> 8), byte(len(payload)), kind, flags})
		out.Write(binary.BigEndian.AppendUint32(nil, stream))
		out.Write(payload)
	}
	out.Write(h2Preface)
	frame(4, 0, 0, nil) // SETTINGS
	encoder := hpack.NewEncoder(&block)
	for i, fields := range requests {
		block.Reset()
		for _, field := range fields {
			if err := encoder.WriteField(field); err != nil {
				t.Fatal(err)
			}
		}
		stream, fragment := uint32(2*i+1), block.Bytes()
		if i == 1 {
			frame(1, 0, stream, fragment[:2])   // HEADERS without END_HEADERS,
			frame(9, 0x4, stream, fragment[2:]) // then CONTINUATION.
		} else {
			frame(1, 0x4, stream, fragment)
		}
		frame(0, 0x1, stream, make([]byte, dataLen)) // DATA with END_STREAM.
	}
	return out.Bytes()
}

var grpcRequest = []hpack.HeaderField{
	{Name: ":method", Value: "POST"}, {Name: ":scheme", Value: "http"},
	{Name: ":authority", Value: "orders.internal.test:50051"}, {Name: ":path", Value: "/orders.Orders/Get"},
	{Name: "content-type", Value: "application/grpc"},
}

// Internal gRPC often runs over cleartext HTTP/2. The second request refers
// to HPACK's dynamic table, so every block must be decoded in order.
func TestHTTP2CleartextCountsRequestsPerAuthority(t *testing.T) {
	data := h2cClient(t, 1000, grpcRequest, grpcRequest)
	s := New(1)
	for offset := 0; offset < len(data); offset += 7 { // Odd segment sizes split frames anywhere.
		s.Add(uint32(1+offset), data[offset:min(offset+7, len(data))])
	}
	e := s.Evidence()
	if e.Kind != "http2" || !e.GRPC || e.Hosts["orders.internal.test"] != 2 || e.ParseError != "" || e.Label() != "HTTP/2 orders.internal.test" {
		t.Fatalf("h2c evidence: %+v label %q", e, e.Label())
	}
}

// A client may reach cleartext HTTP/2 through an HTTP/1.1 Upgrade. The
// preface follows only if the server switched; otherwise HTTP/1.1 goes on.
func TestHTTP2CleartextUpgrade(t *testing.T) {
	upgrade := []byte("GET / HTTP/1.1\r\nHost: orders.internal.test\r\nConnection: Upgrade, HTTP2-Settings\r\nUpgrade: h2c\r\nHTTP2-Settings: AAMAAABkAAQAAP__\r\n\r\n")
	for name, tc := range map[string]struct {
		next []byte
		kind string
	}{
		"switched": {h2cClient(t, 10, grpcRequest), "http2"},
		"refused":  {[]byte("GET /next HTTP/1.1\r\nHost: orders.internal.test\r\n\r\n"), "http"},
	} {
		data := append(bytes.Clone(upgrade), tc.next...)
		s := New(1)
		for offset := 0; offset < len(data); offset += 7 {
			s.Add(uint32(1+offset), data[offset:min(offset+7, len(data))])
		}
		if e := s.Evidence(); e.Kind != tc.kind || e.Hosts["orders.internal.test"] != 2 || e.ParseError != "" {
			t.Fatalf("%s: %+v", name, e)
		}
	}
}

// A DATA frame the capture cut short is skipped by length; the next
// request's headers still count.
func TestHTTP2SkipsUncapturedDataFrames(t *testing.T) {
	data := h2cClient(t, 20000, grpcRequest, grpcRequest)
	first := bytes.Index(data, make([]byte, 20000)) // Start of the first DATA payload.
	s := New(1)
	s.Add(1, data[:first+100])
	s.AddSegment(uint32(1+first+100), nil, 19900) // Wire length only, no bytes.
	s.Add(uint32(1+first+20000), data[first+20000:])
	if e := s.Evidence(); e.Hosts["orders.internal.test"] != 2 || e.ParseError != "" {
		t.Fatalf("after a truncated DATA frame: %+v", e)
	}
}
