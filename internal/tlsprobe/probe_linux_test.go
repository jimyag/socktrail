//go:build linux && (386 || amd64 || arm64)

package tlsprobe

import "testing"

func TestDecodeEventRejectsInvalidHostname(t *testing.T) {
	raw := TlsEvent{Pid: 10, Family: 4, Source: 1, LocalPort: 50000, RemotePort: 443}
	copy(raw.LocalIp[:4], []byte{192, 0, 2, 10})
	copy(raw.RemoteIp[:4], []byte{192, 0, 2, 20})
	for i, b := range []byte("example.test") {
		raw.Hostname[i] = int8(b)
	}
	event, err := decodeEvent(raw)
	if err != nil || event.Hostname != "example.test" || event.Local.String() != "192.0.2.10:50000" {
		t.Fatalf("valid event: %+v %v", event, err)
	}
	raw.Hostname[0] = '/'
	if _, err := decodeEvent(raw); err == nil {
		t.Fatal("unsafe hostname accepted")
	}
}
