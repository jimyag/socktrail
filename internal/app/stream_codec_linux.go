package app

import (
	"bytes"
	"encoding/json"
	"fmt"
	"time"

	"github.com/vmihailenco/msgpack/v5"
)

type streamFrame struct {
	Kind  string         `json:"kind"`
	Hello *streamHello   `json:"hello,omitempty"`
	Flow  *jsonFlow      `json:"flow,omitempty"`
	Stats *streamSummary `json:"stats,omitempty"`
}

// Frame kinds on the socket stream. Standard output stays one bare row per
// change; only the subscription protocol needs to tell frames apart.
const (
	streamKindHello = "hello"
	streamKindFlow  = "flow"
	streamKindStats = "stats"
)

// streamHello is the first frame of every connection.
type streamHello struct {
	Version    int        `json:"version"`
	Mode       string     `json:"mode"`
	Interfaces []string   `json:"interfaces"`
	Filter     string     `json:"filter,omitempty"`
	Probes     jsonProbes `json:"probes"`
	Started    time.Time  `json:"started"`
}

// streamSummary is the periodic summary. It is what lets a subscriber total
// per-process traffic without undercounting: process_io is the whole pidIO
// table, while the other fields name the bytes that never reached a flow.
type streamSummary struct {
	At               time.Time       `json:"at"`
	IPPackets        uint64          `json:"ip_packets"`
	IPBytes          uint64          `json:"ip_bytes"`
	ProcessIO        []jsonProcessIO `json:"process_io"`
	IOUnmatchedBytes uint64          `json:"io_unmatched_bytes"`
	IOUnindexed      streamIOBytes   `json:"io_unindexed"`
	ExpiredPIDIO     streamIOBytes   `json:"expired_pid_io"`
	ExpiredPIDCount  uint64          `json:"expired_pid_count"`
	Probes           jsonProbes      `json:"probes"`
}

// streamIOBytes is a byte count per direction. These are socket I/O bytes, not
// IP packet bytes, and the two are never added together.
type streamIOBytes struct {
	RXBytes uint64 `json:"rx_bytes"`
	TXBytes uint64 `json:"tx_bytes"`
}

// streamingOutput reports whether --output writes one row per change instead
// of the interactive screen or a one-shot snapshot.
func streamingOutput(format string) bool {
	return format == "ndjson" || format == "msgpack"
}

// streamCodec serializes one streamed row per call. It hands back bytes rather
// than writing to a writer so that the same code path can serve standard output
// and a socket hub that broadcasts to several clients.
type streamCodec struct {
	json    *json.Encoder
	msgpack *msgpack.Encoder
	buf     bytes.Buffer
}

func newStreamCodec(format string) (*streamCodec, error) {
	c := &streamCodec{}
	switch format {
	case "msgpack":
		encoder := msgpack.NewEncoder(&c.buf)
		// Reuse the json tags so MessagePack and JSON stay one data model.
		encoder.SetCustomStructTag("json")
		c.msgpack = encoder
	case "ndjson", "text":
		c.json = json.NewEncoder(&c.buf)
	default:
		return nil, fmt.Errorf("unsupported stream format %q", format)
	}
	return c, nil
}

// encode returns the bytes of one row. json.Encoder appends a newline;
// MessagePack frames carry their own length and need no separator.
//
// The returned slice points into the codec's buffer and is valid only until
// the next call. A caller that keeps it longer must copy.
// ponytail: one reused buffer, per-row allocation only if a future caller has
// to retain frames alongside the next encode.
func (c *streamCodec) encode(v any) ([]byte, error) {
	c.buf.Reset()
	if c.msgpack != nil {
		if err := c.msgpack.Encode(v); err != nil {
			return nil, err
		}
	} else if err := c.json.Encode(v); err != nil {
		return nil, err
	}
	return c.buf.Bytes(), nil
}
