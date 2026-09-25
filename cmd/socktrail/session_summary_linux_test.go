package main

import (
	"bytes"
	"strings"
	"testing"
	"time"
)

func TestSessionSummaryUsesSampledPeaksAndFinalTotals(t *testing.T) {
	start := time.Unix(0, 0)
	var summary sessionSummary
	summary.add(sessionSample{at: start, rss: 100 << 20, peakRSS: 100 << 20})
	summary.add(sessionSample{at: start.Add(time.Second), cpu: 200 * time.Millisecond, rss: 200 << 20, peakRSS: 200 << 20, packets: 100, ipBytes: 1000})
	summary.add(sessionSample{at: start.Add(2 * time.Second), cpu: 800 * time.Millisecond, rss: 100 << 20, peakRSS: 250 << 20, packets: 500, ipBytes: 3000})
	var output bytes.Buffer
	summary.print(&output, 2, 500, 3000, 3, 1)
	for _, want := range []string{
		"socktrail stopped (2s, 2 interfaces)",
		"avg 40.0%", "peak 60.0%",
		"avg 150.0 MiB", "peak 250.0 MiB",
		"total 500", "peak 400/s",
		"total 2.9 KiB", "peak 2.0 KiB/s",
		"AF_PACKET 3  PID ring 1",
		"may count the same packet more than once",
	} {
		if !strings.Contains(output.String(), want) {
			t.Errorf("summary missing %q: %s", want, output.String())
		}
	}
}

func TestSessionSummarySamplesCurrentProcess(t *testing.T) {
	var summary sessionSummary
	summary.sample(map[string]*collector{"lo": {packets: 3, bytes: 120}})
	if summary.first.at.IsZero() || summary.first.rss == 0 || summary.first.peakRSS == 0 || summary.first.packets != 3 || summary.first.ipBytes != 120 {
		t.Fatalf("process sample was incomplete: %+v", summary.first)
	}
}

func TestSessionSummaryStillPrintsTotalsWhenSamplingFails(t *testing.T) {
	var output bytes.Buffer
	(sessionSummary{}).print(&output, 1, 3, 120, 0, 0)
	if got := output.String(); !strings.Contains(got, "sampling failed") || !strings.Contains(got, "total 3") || !strings.Contains(got, "total 120 B") {
		t.Fatalf("missing fallback totals: %q", got)
	}
}
