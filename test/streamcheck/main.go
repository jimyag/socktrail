// Command streamcheck verifies a MessagePack stream produced by socktrail.
// It decodes frames generically, without socktrail's types, which is also what
// any other consumer has to do.
//
//	streamcheck pipe   <file>   # a bare row-per-object stream from --output msgpack
//	streamcheck socket <path>   # the subscription protocol on a Unix socket
package main

import (
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"time"

	"github.com/vmihailenco/msgpack/v5"
)

func main() {
	if len(os.Args) != 3 {
		fail("usage: streamcheck pipe <file> | streamcheck socket <path>")
	}
	switch os.Args[1] {
	case "pipe":
		checkPipe(os.Args[2])
	case "socket":
		checkSocket(os.Args[2])
	default:
		fail("unknown mode %q: use pipe or socket", os.Args[1])
	}
}

// checkPipe decodes a bare stream: one jsonFlow per object, no frame envelope.
func checkPipe(path string) {
	file, err := os.Open(path) //nolint:gosec // The path comes from the command line.
	if err != nil {
		fail("open %s: %v", path, err)
	}
	defer func() { _ = file.Close() }()
	decoder := msgpack.NewDecoder(file)

	frames := 0
	for {
		var row map[string]any
		if err := decoder.Decode(&row); err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			fail("decode frame %d: %v", frames, err)
		}
		for _, key := range []string{"protocol", "source", "target"} {
			if _, ok := row[key]; !ok {
				fail("frame %d has no %q field: %v", frames, key, row)
			}
		}
		if _, ok := row["kind"]; ok {
			fail("frame %d carries a frame envelope, but standard output stays one bare row", frames)
		}
		frames++
	}
	if frames == 0 {
		fail("the stream had no frames")
	}
	fmt.Printf("streamcheck pipe: %d rows\n", frames)
}

// checkSocket checks the subscription protocol: hello first, then a full
// snapshot, then a summary, so a subscriber never guesses the state it joined.
func checkSocket(path string) {
	conn, err := net.Dial("unix", path) //nolint:gosec // The path comes from the command line.
	if err != nil {
		fail("dial %s: %v", path, err)
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetReadDeadline(time.Now().Add(30 * time.Second))
	decoder := msgpack.NewDecoder(conn)

	var hello map[string]any
	if err := decoder.Decode(&hello); err != nil {
		fail("read the first frame: %v", err)
	}
	if hello["kind"] != "hello" {
		fail("first frame kind = %v, want hello", hello["kind"])
	}
	if body, ok := hello["hello"].(map[string]any); !ok || body["version"] == nil {
		fail("the hello frame carries no version: %v", hello["hello"])
	}

	snapshots, summaries := 0, 0
	for snapshots == 0 || summaries == 0 {
		var frame map[string]any
		if err := decoder.Decode(&frame); err != nil {
			fail("decode frame: %v (snapshots=%d summaries=%d)", err, snapshots, summaries)
		}
		switch frame["kind"] {
		case "flow":
			row, ok := frame["flow"].(map[string]any)
			if !ok {
				fail("a flow frame carries no flow object: %v", frame)
			}
			if changes, ok := row["changes"].([]any); ok {
				for _, change := range changes {
					if change == "snapshot" {
						snapshots++
					}
				}
			}
		case "stats":
			body, ok := frame["stats"].(map[string]any)
			if !ok {
				fail("a stats frame carries no stats object: %v", frame)
			}
			if _, ok := body["process_io"]; !ok {
				fail("the stats frame has no process_io, so per-process totals are unavailable")
			}
			summaries++
		default:
			fail("unexpected frame kind %v", frame["kind"])
		}
	}
	fmt.Printf("streamcheck socket: hello, %d snapshot rows, %d summaries\n", snapshots, summaries)
}

func fail(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "streamcheck: "+format+"\n", args...)
	os.Exit(1)
}
