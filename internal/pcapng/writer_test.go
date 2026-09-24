package pcapng

import (
	"bytes"
	"encoding/binary"
	"errors"
	"testing"
	"time"
)

// A frame the capture cut short keeps its wire length, so readers show it
// as truncated rather than as a short packet.
func TestWriterRecordsWireLength(t *testing.T) {
	var output bytes.Buffer
	w, err := New(&output, []string{"lo"}, 1024)
	if err != nil {
		t.Fatal(err)
	}
	start := output.Len()
	if err := w.Packet(0, []byte{1, 2, 3, 4}, 1500, time.Unix(1, 0), ""); err != nil {
		t.Fatal(err)
	}
	block := output.Bytes()[start:]
	if captured, original := binary.LittleEndian.Uint32(block[20:24]), binary.LittleEndian.Uint32(block[24:28]); captured != 4 || original != 1500 {
		t.Fatalf("captured %d original %d", captured, original)
	}
}

func TestWriterProducesAlignedBlocksAndAnnotatedPacket(t *testing.T) {
	var output bytes.Buffer
	w, err := New(&output, []string{"lo"}, 1024)
	if err != nil {
		t.Fatal(err)
	}
	frame := []byte{0, 1, 2, 3, 4}
	at := time.Unix(1234, 456000000)
	if err := w.Packet(0, frame, len(frame), at, "pid=42 app=DNS"); err != nil {
		t.Fatal(err)
	}
	data := output.Bytes()
	wantTypes := []uint32{sectionHeader, interfaceDescription, enhancedPacket}
	for _, kind := range wantTypes {
		if len(data) < 12 || binary.LittleEndian.Uint32(data[:4]) != kind {
			t.Fatalf("missing block %x", kind)
		}
		length := int(binary.LittleEndian.Uint32(data[4:8]))
		if length%4 != 0 || length > len(data) || binary.LittleEndian.Uint32(data[length-4:length]) != uint32(length) {
			t.Fatalf("invalid block length %d", length)
		}
		if kind == enhancedPacket {
			body := data[8 : length-4]
			stamp := uint64(binary.LittleEndian.Uint32(body[4:8]))<<32 | uint64(binary.LittleEndian.Uint32(body[8:12]))
			if stamp != uint64(at.UnixMicro()) || binary.LittleEndian.Uint32(body[12:16]) != uint32(len(frame)) || !bytes.Equal(body[20:25], frame) || !bytes.Contains(body, []byte("pid=42 app=DNS")) {
				t.Fatalf("packet data, timestamp, or comment wrong: %x", body)
			}
		}
		data = data[length:]
	}
	if len(data) != 0 || w.Packets != 1 {
		t.Fatalf("unexpected trailing bytes or packet count: %d, %d", len(data), w.Packets)
	}
	w.maxBytes = w.Bytes() + 4
	if err := w.Packet(0, frame, len(frame), at, "next"); !errors.Is(err, ErrLimit) || w.Packets != 1 {
		t.Fatalf("size limit did not stop an entire packet block: error=%v packets=%d", err, w.Packets)
	}
}
