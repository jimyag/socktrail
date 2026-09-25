package app

import (
	"bytes"
	"encoding/binary"
	"testing"
	"time"

	"github.com/jimyag/socktrail/internal/capture"
	"github.com/jimyag/socktrail/internal/pcapng"
)

func TestReadRecordingRestoresPacketAnnotation(t *testing.T) {
	var out bytes.Buffer
	w, err := pcapng.New(&out, []string{"pid:123:eth0"}, 0)
	if err != nil {
		t.Fatal(err)
	}
	payload := []byte("GET / HTTP/1.1\r\nHost: api.example.test\r\n\r\n")
	ip := make([]byte, 40+len(payload))
	ip[0] = 0x45
	binary.BigEndian.PutUint16(ip[2:4], uint16(len(ip)))
	ip[8], ip[9] = 64, 6
	copy(ip[12:16], []byte{192, 0, 2, 1})
	copy(ip[16:20], []byte{198, 51, 100, 1})
	binary.BigEndian.PutUint16(ip[20:22], 40000)
	binary.BigEndian.PutUint16(ip[22:24], 80)
	ip[32], ip[33] = 0x50, 0x18
	copy(ip[40:], payload)
	at := time.Unix(1234, 456000000)
	comment := `socktrail interface=pid:123:eth0 packet_direction=tx flow_direction=outbound app=HTTP app_source="wire" origin_pid=42 origin_start_ns=70 origin_process="my curl" target_pid=0 target_start_ns=0 target_process="" domain="HTTP api.example.test"`
	if err := w.Packet(0, capture.EthernetFrame(0x800, ip), len(ip)+14, at, comment); err != nil {
		t.Fatal(err)
	}
	collectors, names, processes, first, err := readRecording(bytes.NewReader(out.Bytes()), 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(names) != 1 || names[0] != "pid:123:eth0" || !first.Equal(at) {
		t.Fatalf("interfaces=%v first=%v", names, first)
	}
	flows := collectors[names[0]].allFlows()
	if len(flows) != 1 {
		t.Fatalf("flows=%d", len(flows))
	}
	f := flows[0]
	if f.Client.PID != 42 || f.Client.StartNS != 70 || f.Client.Name != "my curl" || f.AppProtocol != "HTTP" || f.Direction != "outbound" || f.Domain == nil || f.Domain.Evidence().Label() != "HTTP api.example.test" || !f.First.Equal(at) || !f.Last.Equal(at) {
		t.Fatalf("restored flow: %+v", f)
	}
	if m := processes.meta(f.Client.id()); m == nil || m.Name != "my curl" {
		t.Fatalf("recorded process: %+v", m)
	}
}
