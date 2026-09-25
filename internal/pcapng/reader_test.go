package pcapng

import (
	"bytes"
	"encoding/binary"
	"strings"
	"testing"
	"time"
)

func TestReadWriterRoundTrip(t *testing.T) {
	var out bytes.Buffer
	w, err := New(&out, []string{"pid:123:eth0", "lo"}, 0)
	if err != nil {
		t.Fatal(err)
	}
	at := time.Unix(1234, 456000000)
	if err := w.Packet(1, []byte{1, 2, 3, 4, 5}, 1500, at, `socktrail origin_pid=42 domain="TLS api.test"`); err != nil {
		t.Fatal(err)
	}
	var got []RecordedPacket
	if err := Read(bytes.NewReader(out.Bytes()), func(p RecordedPacket) error { got = append(got, p); return nil }); err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Interface != "lo" || got[0].WireLen != 1500 || !got[0].At.Equal(at) || !bytes.Equal(got[0].Frame, []byte{1, 2, 3, 4, 5}) || !strings.Contains(got[0].Comment, "origin_pid=42") {
		t.Fatalf("round trip: %+v", got)
	}
	corrupt := bytes.Clone(out.Bytes())
	binary.LittleEndian.PutUint32(corrupt[4:8], 1<<30)
	if err := Read(bytes.NewReader(corrupt), func(RecordedPacket) error { return nil }); err == nil {
		t.Fatal("accepted oversized block")
	}
}
