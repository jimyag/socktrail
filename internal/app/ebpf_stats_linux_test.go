package app

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestProcessBPFIDs(t *testing.T) {
	dir := t.TempDir()
	for name, text := range map[string]string{
		"3": "pos:\t0\nprog_id:\t42\n",
		"4": "prog_id:\t42\nlink_id:\t100\n",
		"5": "map_id:\t7\n",
		"6": "map_id:\t7\n",
		"7": "map_id:\t8\n",
		"8": "pos:\t0\nino:\t123\n",
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(text), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	programs, bpfMaps, err := processBPFIDs(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(programs) != 1 || len(bpfMaps) != 2 {
		t.Fatalf("IDs not deduplicated: programs=%v maps=%v", programs, bpfMaps)
	}
	if _, ok := programs[42]; !ok {
		t.Fatal("program 42 missing")
	}
	_, has7 := bpfMaps[7]
	_, has8 := bpfMaps[8]
	if !has7 || !has8 {
		t.Fatalf("map 7 or 8 missing: %v", bpfMaps)
	}
	if err := os.WriteFile(filepath.Join(dir, "9"), []byte("map_id:\tinvalid\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := processBPFIDs(dir); err == nil {
		t.Fatal("invalid BPF ID was ignored")
	}
}

func TestBPFUsageRates(t *testing.T) {
	start := time.Now()
	before := bpfUsage{Programs: []bpfProgramUsage{
		{ID: 1, RuntimeNS: 100, RunCount: 20, sampledAt: start},
		{ID: 2, RuntimeNS: 200, RunCount: 10, sampledAt: start.Add(time.Second)},
		{ID: 3, RuntimeNS: 100, RunCount: 10, sampledAt: start},
		{ID: 5, RuntimeNS: 100, RunCount: 10, sampledAt: start},
	}}
	after := bpfUsage{Programs: []bpfProgramUsage{
		{ID: 1, RuntimeNS: 20_000_100, RunCount: 1020, sampledAt: start.Add(2 * time.Second)},
		{ID: 2, RuntimeNS: 80_000_200, RunCount: 4010, sampledAt: start.Add(5 * time.Second)},
		{ID: 3, RuntimeNS: 0, RunCount: 0, sampledAt: start.Add(2 * time.Second)},
		{ID: 4, RuntimeNS: 100, RunCount: 1, sampledAt: start.Add(2 * time.Second)},
		{ID: 5, RuntimeNS: 200, RunCount: 20, sampledAt: start},
	}}
	// Scanning metadata may take longer than either program's counter window.
	after.calculateRates(before, 7)
	if after.CPUPercentOneCore != 3 || after.Programs[0].ID != 2 {
		t.Fatalf("incorrect CPU total or ranking: %+v", after)
	}
	if after.Programs[0].SampleSeconds != 4 || after.Programs[0].RunsPerSecond != 1000 || after.Seconds != 7 {
		t.Fatalf("per-program windows were replaced by the overall duration: %+v", after)
	}
	program := after.Programs[1]
	if !program.Sampled || program.SampleSeconds != 2 || program.RuntimeDeltaNS != 20_000_000 || program.RunCountDelta != 1000 || program.RunsPerSecond != 500 || program.AverageRunNS != 20_000 || program.CPUPercentOneCore != 1 {
		t.Fatalf("incorrect program rates: %+v", program)
	}
	for _, program := range after.Programs[2:] {
		if program.Sampled || program.CPUPercentOneCore != 0 {
			t.Fatalf("new or reset program treated as a complete sample: %+v", program)
		}
	}
}

func TestBPFStatsRejectsInvalidIntervals(t *testing.T) {
	for _, seconds := range []string{"0", "-1", "31", "invalid", "0.5"} {
		request := httptest.NewRequest(http.MethodGet, "/debug/ebpf?seconds="+seconds, nil)
		response := httptest.NewRecorder()
		serveBPFStats(response, request)
		if response.Code != http.StatusBadRequest {
			t.Errorf("seconds=%q: status %d", seconds, response.Code)
		}
	}
}
