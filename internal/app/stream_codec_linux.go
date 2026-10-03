package app

import (
	"bytes"
	"encoding/json"
	"fmt"

	"github.com/vmihailenco/msgpack/v5"
)

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
