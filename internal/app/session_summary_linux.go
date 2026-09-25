package app

import (
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"syscall"
	"time"
)

type sessionSample struct {
	at               time.Time
	cpu              time.Duration
	rss, peakRSS     uint64
	packets, ipBytes uint64
}

type sessionSummary struct {
	first, last               sessionSample
	rssByteSeconds            float64
	peakCPU, peakPPS, peakBPS float64
}

func (s *sessionSummary) sample(collectors map[string]*collector) {
	var usage syscall.Rusage
	if err := syscall.Getrusage(syscall.RUSAGE_SELF, &usage); err != nil {
		return
	}
	data, err := os.ReadFile("/proc/self/statm")
	if err != nil {
		return
	}
	fields := strings.Fields(string(data))
	if len(fields) < 2 {
		return
	}
	pages, err := strconv.ParseUint(fields[1], 10, 64)
	if err != nil {
		return
	}
	sample := sessionSample{
		at:  time.Now(),
		cpu: time.Duration(usage.Utime.Sec+usage.Stime.Sec)*time.Second + time.Duration(usage.Utime.Usec+usage.Stime.Usec)*time.Microsecond,
		rss: pages * uint64(os.Getpagesize()), peakRSS: uint64(max(0, usage.Maxrss)) * 1024,
	}
	for _, c := range collectors {
		sample.packets += c.packets
		sample.ipBytes += c.bytes
	}
	s.add(sample)
}

func (s *sessionSummary) add(next sessionSample) {
	if s.first.at.IsZero() {
		s.first, s.last = next, next
		return
	}
	seconds := next.at.Sub(s.last.at).Seconds()
	if seconds <= 0 {
		return
	}
	s.rssByteSeconds += float64(s.last.rss+next.rss) * seconds / 2
	s.peakCPU = max(s.peakCPU, float64(next.cpu-s.last.cpu)/seconds/float64(time.Second)*100)
	s.peakPPS = max(s.peakPPS, float64(next.packets-s.last.packets)/seconds)
	s.peakBPS = max(s.peakBPS, float64(next.ipBytes-s.last.ipBytes)/seconds)
	s.last = next
}

func (s sessionSummary) print(w io.Writer, interfaces int, packets, ipBytes, dropped, ringLost uint64) {
	if s.first.at.IsZero() {
		fmt.Fprintf(w, "socktrail stopped (%d interfaces)\n", interfaces)
		fmt.Fprintln(w, "  CPU, RSS and rates unavailable (process sampling failed)")
		fmt.Fprintf(w, "  IP packets  total %s\n  IP bytes    total %s\n", summaryCount(float64(packets)), summaryBytes(ipBytes))
		fmt.Fprintf(w, "  drops       AF_PACKET %d  PID ring %d\n", dropped, ringLost)
		if interfaces > 1 {
			fmt.Fprintln(w, "  Multi-interface totals may count the same packet more than once.")
		}
		return
	}
	elapsed := s.last.at.Sub(s.first.at).Seconds()
	if elapsed <= 0 {
		elapsed = 1
	}
	fmt.Fprintf(w, "socktrail stopped (%s, %d interfaces)\n", s.last.at.Sub(s.first.at).Truncate(time.Second), interfaces)
	fmt.Fprintf(w, "  CPU         avg %-12s peak %-12s (sampled; 100%% = 1 core)\n", fmt.Sprintf("%.1f%%", float64(s.last.cpu-s.first.cpu)/elapsed/float64(time.Second)*100), fmt.Sprintf("%.1f%%", s.peakCPU))
	fmt.Fprintf(w, "  RSS         avg %-12s peak %s\n", summaryBytes(uint64(s.rssByteSeconds/elapsed)), summaryBytes(s.last.peakRSS))
	fmt.Fprintf(w, "  IP packets  total %-10s avg %-12s peak %s/s\n", summaryCount(float64(packets)), summaryCount(float64(packets)/elapsed)+"/s", summaryCount(s.peakPPS))
	fmt.Fprintf(w, "  IP bytes    total %-10s avg %-12s peak %s/s\n", summaryBytes(ipBytes), summaryBytes(uint64(float64(ipBytes)/elapsed))+"/s", summaryBytes(uint64(s.peakBPS)))
	fmt.Fprintf(w, "  drops       AF_PACKET %d  PID ring %d\n", dropped, ringLost)
	if interfaces > 1 {
		fmt.Fprintln(w, "  Multi-interface totals may count the same packet more than once.")
	}
}

func summaryBytes(n uint64) string {
	switch {
	case n >= 1<<30:
		return fmt.Sprintf("%.1f GiB", float64(n)/float64(1<<30))
	case n >= 1<<20:
		return fmt.Sprintf("%.1f MiB", float64(n)/float64(1<<20))
	case n >= 1<<10:
		return fmt.Sprintf("%.1f KiB", float64(n)/float64(1<<10))
	default:
		return fmt.Sprintf("%d B", n)
	}
}

func summaryCount(n float64) string {
	switch {
	case n >= 1e9:
		return fmt.Sprintf("%.1fG", n/1e9)
	case n >= 1e6:
		return fmt.Sprintf("%.1fM", n/1e6)
	case n >= 1e3:
		return fmt.Sprintf("%.1fk", n/1e3)
	default:
		return fmt.Sprintf("%.0f", n)
	}
}
