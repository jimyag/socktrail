package app

import (
	"net/netip"
	"reflect"
	"testing"
	"time"

	"github.com/jimyag/socktrail/internal/domain"
)

func TestConnectionChangesAreDelayedAndEmittedOnce(t *testing.T) {
	now := time.Now()
	a := netip.MustParseAddrPort("192.0.2.1:40000")
	b := netip.MustParseAddrPort("198.51.100.1:80")
	f := &flow{Key: keyFor(a, b, 6), First: now, Last: now, TCPState: "established"}
	current := map[uint64]*flow{1: f}
	var state hostViewState
	if got := state.detectChanges(current, nil, now); len(got) != 0 {
		t.Fatalf("new flow appeared before late-event window: %+v", got)
	}
	if got := state.detectChanges(current, current, now.Add(2*time.Second)); len(got) != 1 || !reflect.DeepEqual(got[0].Changes, []string{"new"}) {
		t.Fatalf("new flow change = %+v", got)
	}
	f.Domain = domain.New(1)
	firstRequest := []byte("GET / HTTP/1.1\r\nHost: first.example.test\r\n\r\n")
	f.Domain.Add(1, firstRequest)
	if got := state.detectChanges(current, current, now.Add(3*time.Second)); len(got) != 0 {
		t.Fatalf("name change appeared before delay: %+v", got)
	}
	if got := state.detectChanges(current, current, now.Add(5*time.Second)); len(got) != 1 || !reflect.DeepEqual(got[0].Changes, []string{"name"}) {
		t.Fatalf("name change = %+v", got)
	}
	f.Domain.Add(uint32(len(firstRequest)+1), []byte("GET / HTTP/1.1\r\nHost: second.example.test\r\n\r\n"))
	state.detectChanges(current, current, now.Add(6*time.Second))
	if got := state.detectChanges(current, current, now.Add(8*time.Second)); len(got) != 1 || !reflect.DeepEqual(got[0].Changes, []string{"name"}) {
		t.Fatalf("new HTTP Host change = %+v", got)
	}
	f.Client = participant{PID: 42, StartNS: 1}
	if got := state.detectChanges(current, current, now.Add(9*time.Second)); len(got) != 1 || !reflect.DeepEqual(got[0].Changes, []string{"process"}) {
		t.Fatalf("process change = %+v", got)
	}
	f.End = flowFin
	if got := state.detectChanges(current, current, now.Add(10*time.Second)); len(got) != 1 || !reflect.DeepEqual(got[0].Changes, []string{"end"}) {
		t.Fatalf("end change = %+v", got)
	}
	if got := state.detectChanges(nil, current, now.Add(11*time.Second)); len(got) != 0 {
		t.Fatalf("ended flow repeated on expiry: %+v", got)
	}
}

func BenchmarkUnchangedConnectionScan(b *testing.B) {
	now := time.Now()
	current := make(map[uint64]*flow, 10_000)
	for id := uint64(1); id <= 10_000; id++ {
		current[id] = &flow{TCPState: "established", Last: now}
	}
	var state hostViewState
	state.detectChanges(current, nil, now)
	state.detectChanges(current, current, now.Add(lateEventWindow))
	b.ReportAllocs()
	for b.Loop() {
		state.detectChanges(current, current, now.Add(3*time.Second))
	}
}
