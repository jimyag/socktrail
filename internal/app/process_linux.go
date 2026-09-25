package app

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	auxClockTicks = 17 // AT_CLKTCK in the Linux auxiliary vector.
	maxProcText   = 2 << 20
)

var systemClockTicks = sync.OnceValues(readClockTicks)

type processDetails struct {
	started     string
	parentPID   int
	executable  string
	workingDir  string
	command     string
	environment []string
	truncated   bool
	errorText   string
}

func readClockTicks() (uint64, error) {
	data, err := os.ReadFile("/proc/self/auxv")
	if err != nil {
		return 0, fmt.Errorf("read clock ticks: %w", err)
	}
	wordSize := strconv.IntSize / 8
	readWord := func(b []byte) uint64 {
		if wordSize == 4 {
			return uint64(binary.NativeEndian.Uint32(b))
		}
		return binary.NativeEndian.Uint64(b)
	}
	for len(data) >= 2*wordSize {
		key, value := readWord(data[:wordSize]), readWord(data[wordSize:2*wordSize])
		if key == auxClockTicks && value > 0 {
			return value, nil
		}
		data = data[2*wordSize:]
	}
	return 0, fmt.Errorf("AT_CLKTCK unavailable in /proc/self/auxv")
}

func parseProcessStat(data []byte) (parentPID int, startTicks uint64, err error) {
	_, rest, ok := bytes.CutLast(data, []byte{')'})
	if !ok {
		return 0, 0, fmt.Errorf("malformed /proc PID stat")
	}
	// Fields after the command name start with field 3 (state).
	fields := bytes.Fields(rest)
	if len(fields) <= 19 {
		return 0, 0, fmt.Errorf("short /proc PID stat")
	}
	parentPID, err = strconv.Atoi(string(fields[1])) // field 4
	if err != nil {
		return 0, 0, fmt.Errorf("parse parent PID: %w", err)
	}
	startTicks, err = strconv.ParseUint(string(fields[19]), 10, 64) // field 22
	if err != nil {
		return 0, 0, fmt.Errorf("parse process start: %w", err)
	}
	return parentPID, startTicks, nil
}

// nsToTicks and ticksToNS convert process start times between eBPF
// nanoseconds and /proc clock ticks without overflowing on long uptimes.
func nsToTicks(ns, clockTicks uint64) uint64 {
	return ns/1_000_000_000*clockTicks + ns%1_000_000_000*clockTicks/1_000_000_000
}

func ticksToNS(ticks, clockTicks uint64) uint64 {
	return ticks/clockTicks*1_000_000_000 + ticks%clockTicks*1_000_000_000/clockTicks
}

// tickStartNS rounds an eBPF start time down to a whole clock tick, the
// precision the socket table gets from /proc, so a process found both ways
// keeps one identity.
func tickStartNS(startNS uint64) uint64 {
	clockTicks, err := systemClockTicks()
	if err != nil {
		return startNS
	}
	return ticksToNS(nsToTicks(startNS, clockTicks), clockTicks)
}

func processStartMatches(startNS, startTicks, clockTicks uint64) bool {
	if startNS == 0 || clockTicks == 0 {
		return false
	}
	// /proc truncates start time to clock ticks. Allow one tick for kernel
	// rounding while still rejecting a reused PID.
	expected := nsToTicks(startNS, clockTicks)
	if startTicks > expected {
		return startTicks-expected <= 1
	}
	return expected-startTicks <= 1
}

func readProcText(path string) ([]byte, bool, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, false, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, maxProcText+1))
	if err != nil {
		return nil, false, err
	}
	if len(data) > maxProcText {
		return data[:maxProcText], true, nil
	}
	return data, false, nil
}

func readProcessDetails(id processID) processDetails {
	ticks, err := systemClockTicks()
	if err != nil {
		return processDetails{errorText: err.Error()}
	}
	return readProcessDetailsAt("/proc", id, ticks)
}

func readProcessDetailsAt(procRoot string, id processID, clockTicks uint64) processDetails {
	base := filepath.Join(procRoot, strconv.Itoa(id.PID))
	statPath := filepath.Join(base, "stat")
	statData, err := os.ReadFile(statPath)
	if err != nil {
		return processDetails{errorText: fmt.Sprintf("process exited or stat unavailable: %v", err)}
	}
	parent, startTicks, err := parseProcessStat(statData)
	if err != nil {
		return processDetails{errorText: err.Error()}
	}
	if !processStartMatches(id.StartNS, startTicks, clockTicks) {
		return processDetails{errorText: "process exited or PID was reused; launch details unavailable"}
	}
	detail := processDetails{parentPID: parent}
	if statData, err := os.ReadFile(filepath.Join(procRoot, "stat")); err == nil {
		for line := range strings.Lines(string(statData)) {
			if boot, ok := strings.CutPrefix(line, "btime "); ok {
				if seconds, parseErr := strconv.ParseInt(strings.TrimSpace(boot), 10, 64); parseErr == nil {
					detail.started = time.Unix(seconds, 0).Add(time.Duration(startTicks/clockTicks)*time.Second+time.Duration(startTicks%clockTicks)*time.Second/time.Duration(clockTicks)).Local().Format("2006-01-02 15:04:05") + " (approx)"
				}
				break
			}
		}
	}
	if detail.started == "" {
		detail.started = "unavailable"
	}
	readLink := func(name string) string {
		value, err := os.Readlink(filepath.Join(base, name))
		if err != nil {
			return "unavailable (" + err.Error() + ")"
		}
		return strconv.QuoteToGraphic(value)
	}
	detail.executable = readLink("exe")
	detail.workingDir = readLink("cwd")
	if data, truncated, err := readProcText(filepath.Join(base, "cmdline")); err != nil {
		detail.command = "unavailable (" + err.Error() + ")"
	} else {
		detail.truncated = truncated
		args := make([]string, 0)
		for arg := range bytes.SplitSeq(bytes.TrimRight(data, "\x00"), []byte{0}) {
			if len(arg) > 0 {
				args = append(args, strconv.QuoteToGraphic(string(arg)))
			}
		}
		detail.command = strings.Join(args, " ")
		if detail.command == "" {
			detail.command = "unavailable (empty cmdline)"
		}
	}
	if data, truncated, err := readProcText(filepath.Join(base, "environ")); err != nil {
		detail.environment = []string{"unavailable (" + err.Error() + ")"}
	} else {
		detail.truncated = detail.truncated || truncated
		for entry := range bytes.SplitSeq(bytes.TrimRight(data, "\x00"), []byte{0}) {
			if len(entry) == 0 {
				continue
			}
			key, value, ok := bytes.Cut(entry, []byte{'='})
			if ok {
				detail.environment = append(detail.environment, strconv.QuoteToGraphic(string(key))+"="+strconv.QuoteToGraphic(string(value)))
			} else {
				detail.environment = append(detail.environment, strconv.QuoteToGraphic(string(entry)))
			}
		}
		slices.Sort(detail.environment)
	}
	// The PID can exit and be reused while its other /proc files are read.
	statData, err = os.ReadFile(statPath)
	if err != nil {
		return processDetails{errorText: "process exited while reading launch details"}
	}
	_, finalTicks, err := parseProcessStat(statData)
	if err != nil || finalTicks != startTicks {
		return processDetails{errorText: "PID changed while reading launch details"}
	}
	return detail
}
