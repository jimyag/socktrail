package app

import (
	"cmp"
	jsonv2 "encoding/json/v2"
	"errors"
	"fmt"
	"maps"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/cilium/ebpf"
)

type bpfProgramUsage struct {
	ID                  ebpf.ProgramID `json:"id"`
	Name                string         `json:"name"`
	Type                string         `json:"type"`
	RuntimeNS           int64          `json:"runtime_ns"`
	RunCount            uint64         `json:"run_count"`
	Sampled             bool           `json:"sampled"`
	SampleSeconds       float64        `json:"sample_seconds"`
	RuntimeDeltaNS      int64          `json:"runtime_delta_ns"`
	RunCountDelta       uint64         `json:"run_count_delta"`
	RunsPerSecond       float64        `json:"runs_per_second"`
	AverageRunNS        float64        `json:"average_run_ns"`
	CPUPercentOneCore   float64        `json:"cpu_percent_one_core"`
	MemoryBytesEstimate *uint64        `json:"memory_bytes_estimate"`
	sampledAt           time.Time
}

type bpfMapUsage struct {
	ID                  ebpf.MapID `json:"id"`
	Name                string     `json:"name"`
	Type                string     `json:"type"`
	KeySize             uint32     `json:"key_size"`
	ValueSize           uint32     `json:"value_size"`
	MaxEntries          uint32     `json:"max_entries"`
	MemoryBytesEstimate *uint64    `json:"memory_bytes_estimate"`
}

type bpfUsage struct {
	PID                        int               `json:"pid"`
	Seconds                    float64           `json:"seconds"`
	CPUPercentOneCore          float64           `json:"cpu_percent_one_core"`
	ProgramMemoryBytesEstimate uint64            `json:"program_memory_bytes_estimate"`
	MapMemoryBytesEstimate     uint64            `json:"map_memory_bytes_estimate"`
	MemoryComplete             bool              `json:"memory_complete"`
	Programs                   []bpfProgramUsage `json:"programs"`
	Maps                       []bpfMapUsage     `json:"maps"`
	Errors                     []string          `json:"errors,omitempty"`
}

// Only inspect descriptors owned by this process, including all optional probes.
// IDs also deduplicate shared maps and programs referenced by multiple links.
func processBPFIDs(dir string) (map[ebpf.ProgramID]struct{}, map[ebpf.MapID]struct{}, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, nil, err
	}
	programs := make(map[ebpf.ProgramID]struct{})
	bpfMaps := make(map[ebpf.MapID]struct{})
	for _, entry := range entries {
		//nolint:gosec // G304: dir is /proc/self/fdinfo in production; names come from ReadDir.
		data, err := os.ReadFile(filepath.Join(dir, entry.Name()))
		if errors.Is(err, os.ErrNotExist) {
			continue // A descriptor may close while probes stop or HTTP clients leave.
		}
		if err != nil {
			return nil, nil, err
		}
		for line := range strings.SplitSeq(string(data), "\n") {
			key, value, _ := strings.Cut(line, ":")
			if key != "prog_id" && key != "map_id" {
				continue
			}
			id, err := strconv.ParseUint(strings.TrimSpace(value), 10, 32)
			if err != nil {
				return nil, nil, fmt.Errorf("parse %s in fdinfo %s: %w", key, entry.Name(), err)
			}
			if key == "prog_id" {
				programs[ebpf.ProgramID(id)] = struct{}{}
			} else {
				bpfMaps[ebpf.MapID(id)] = struct{}{}
			}
		}
	}
	return programs, bpfMaps, nil
}

func snapshotBPFUsage() (bpfUsage, error) {
	programs, bpfMaps, err := processBPFIDs("/proc/self/fdinfo")
	if err != nil {
		return bpfUsage{}, err
	}
	result := bpfUsage{PID: os.Getpid(), MemoryComplete: true, Programs: []bpfProgramUsage{}, Maps: []bpfMapUsage{}}
	for _, id := range slices.Sorted(maps.Keys(programs)) {
		program, err := ebpf.NewProgramFromID(id)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			result.Errors = append(result.Errors, fmt.Sprintf("open program %d: %v", id, err))
			continue
		}
		info, infoErr := program.Info()
		stats, statsErr := program.Stats()
		sampledAt := time.Now()
		_ = program.Close()
		if err := errors.Join(infoErr, statsErr); err != nil {
			result.Errors = append(result.Errors, fmt.Sprintf("read program %d: %v", id, err))
			continue
		}
		usage := bpfProgramUsage{ID: id, Name: info.Name, Type: info.Type.String(), RuntimeNS: stats.Runtime.Nanoseconds(), RunCount: stats.RunCount, sampledAt: sampledAt}
		if memory, ok := info.Memlock(); ok {
			usage.MemoryBytesEstimate = new(memory)
			result.ProgramMemoryBytesEstimate += memory
		} else {
			result.MemoryComplete = false
		}
		result.Programs = append(result.Programs, usage)
	}
	for _, id := range slices.Sorted(maps.Keys(bpfMaps)) {
		bpfMap, err := ebpf.NewMapFromID(id)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			result.Errors = append(result.Errors, fmt.Sprintf("open map %d: %v", id, err))
			continue
		}
		info, err := bpfMap.Info()
		_ = bpfMap.Close()
		if err != nil {
			result.Errors = append(result.Errors, fmt.Sprintf("read map %d: %v", id, err))
			continue
		}
		usage := bpfMapUsage{ID: id, Name: info.Name, Type: info.Type.String(), KeySize: info.KeySize, ValueSize: info.ValueSize, MaxEntries: info.MaxEntries}
		if memory, ok := info.Memlock(); ok {
			usage.MemoryBytesEstimate = new(memory)
			result.MapMemoryBytesEstimate += memory
		} else {
			result.MemoryComplete = false
		}
		result.Maps = append(result.Maps, usage)
	}
	return result, nil
}

func (usage *bpfUsage) calculateRates(before bpfUsage, elapsedSeconds float64) {
	usage.Seconds = elapsedSeconds
	previous := make(map[ebpf.ProgramID]bpfProgramUsage, len(before.Programs))
	for _, program := range before.Programs {
		previous[program.ID] = program
	}
	for i := range usage.Programs {
		program := &usage.Programs[i]
		prior, ok := previous[program.ID]
		if !ok || !program.sampledAt.After(prior.sampledAt) || program.RuntimeNS < prior.RuntimeNS || program.RunCount < prior.RunCount {
			continue // A new program has no complete observation interval yet.
		}
		seconds := program.sampledAt.Sub(prior.sampledAt).Seconds()
		program.SampleSeconds = seconds
		program.RuntimeDeltaNS = program.RuntimeNS - prior.RuntimeNS
		program.Sampled = true
		program.RunCountDelta = program.RunCount - prior.RunCount
		program.RunsPerSecond = float64(program.RunCountDelta) / seconds
		program.CPUPercentOneCore = float64(program.RuntimeDeltaNS) / (seconds * 1e9) * 100
		if program.RunCountDelta > 0 {
			program.AverageRunNS = float64(program.RuntimeDeltaNS) / float64(program.RunCountDelta)
		}
		usage.CPUPercentOneCore += program.CPUPercentOneCore
	}
	slices.SortFunc(usage.Programs, func(a, b bpfProgramUsage) int {
		return cmp.Compare(b.CPUPercentOneCore, a.CPUPercentOneCore)
	})
}

func serveBPFStats(w http.ResponseWriter, r *http.Request) {
	seconds := 1
	if value := r.URL.Query().Get("seconds"); value != "" {
		var err error
		seconds, err = strconv.Atoi(value)
		if err != nil || seconds < 1 || seconds > 30 {
			http.Error(w, "seconds must be an integer between 1 and 30", http.StatusBadRequest)
			return
		}
	}
	started := time.Now()
	before, err := snapshotBPFUsage()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	timer := time.NewTimer(time.Duration(seconds) * time.Second)
	defer timer.Stop()
	select {
	case <-r.Context().Done():
		return
	case <-timer.C:
	}
	after, err := snapshotBPFUsage()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	after.calculateRates(before, time.Since(started).Seconds())
	after.Errors = append(before.Errors, after.Errors...)
	if len(after.Errors) > 0 {
		after.MemoryComplete = false
	}
	w.Header().Set("Content-Type", "application/json")
	if err := jsonv2.MarshalWrite(w, after); err != nil {
		fmt.Fprintf(os.Stderr, "socktrail: write eBPF statistics: %v\n", err)
	}
}
