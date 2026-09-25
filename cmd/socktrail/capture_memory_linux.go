package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"

	"golang.org/x/term"
)

const (
	defaultCaptureMemoryLimit = 512 << 20
	captureMemoryHeadroom     = 128 << 20
	memoryScopeEnv            = "SOCKTRAIL_MEMORY_SCOPE"
)

func captureRingSize(interfaces int) int {
	return max(4<<20, 16<<20/interfaces)
}

func parseCaptureMemoryLimit(value string, interfaces int) (uint64, error) {
	switch value {
	case "auto":
		if interfaces <= maxCaptureInterfaces {
			return 0, nil
		}
		return defaultCaptureMemoryLimit, nil
	case "none":
		return 0, nil
	}
	unit := uint64(1)
	for _, suffix := range [...]struct {
		name string
		size uint64
	}{{"GiB", 1 << 30}, {"MiB", 1 << 20}, {"KiB", 1 << 10}} {
		if number, ok := strings.CutSuffix(value, suffix.name); ok {
			value, unit = number, suffix.size
			break
		}
	}
	number, err := strconv.ParseUint(value, 10, 64)
	if err != nil || number == 0 || number > ^uint64(0)/unit {
		return 0, fmt.Errorf("invalid --memory-limit; use auto, none, or a size such as 512MiB")
	}
	return number * unit, nil
}

func validateCaptureMemory(limit, ringBytes, available uint64) error {
	if ringBytes > limit || captureMemoryHeadroom > limit-ringBytes {
		return fmt.Errorf("capture rings need %d MiB plus %d MiB headroom, above the %d MiB memory limit", ringBytes>>20, captureMemoryHeadroom>>20, limit>>20)
	}
	if limit > available/2 {
		return fmt.Errorf("memory limit %d MiB exceeds half of the %d MiB currently available; choose a lower --memory-limit or none", limit>>20, available>>20)
	}
	return nil
}

func availableMemory() (uint64, error) {
	data, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		return 0, err
	}
	for line := range strings.SplitSeq(string(data), "\n") {
		if rest, ok := strings.CutPrefix(line, "MemAvailable:"); ok {
			fields := strings.Fields(rest)
			if len(fields) != 2 || fields[1] != "kB" {
				break
			}
			kib, err := strconv.ParseUint(fields[0], 10, 64)
			if err == nil {
				groupAvailable, err := cgroupMemoryHeadroom()
				if err != nil {
					return 0, err
				}
				return min(kib<<10, groupAvailable), nil
			}
			break
		}
	}
	return 0, fmt.Errorf("MemAvailable missing from /proc/meminfo")
}

func currentCgroupPath() (string, error) {
	data, err := os.ReadFile("/proc/self/cgroup")
	if err != nil {
		return "", err
	}
	for line := range strings.SplitSeq(string(data), "\n") {
		if group, ok := strings.CutPrefix(line, "0::"); ok {
			return filepath.Join("/sys/fs/cgroup", strings.TrimPrefix(group, "/")), nil
		}
	}
	return "", fmt.Errorf("cgroup v2 is unavailable")
}

func currentMemoryMax() (uint64, error) {
	group, err := currentCgroupPath()
	if err != nil {
		return 0, err
	}
	data, err := os.ReadFile(filepath.Join(group, "memory.max"))
	if err != nil {
		return 0, err
	}
	return strconv.ParseUint(strings.TrimSpace(string(data)), 10, 64)
}

func cgroupMemoryHeadroom() (uint64, error) {
	group, err := currentCgroupPath()
	if err != nil {
		return 0, err
	}
	headroom := ^uint64(0)
	for group != "/sys/fs/cgroup" {
		maxData, err := os.ReadFile(filepath.Join(group, "memory.max"))
		if err != nil {
			return 0, err
		}
		if limitText := strings.TrimSpace(string(maxData)); limitText != "max" {
			limit, err := strconv.ParseUint(limitText, 10, 64)
			if err != nil {
				return 0, err
			}
			usedData, err := os.ReadFile(filepath.Join(group, "memory.current"))
			if err != nil {
				return 0, err
			}
			used, err := strconv.ParseUint(strings.TrimSpace(string(usedData)), 10, 64)
			if err != nil {
				return 0, err
			}
			headroom = min(headroom, limit-min(limit, used))
		}
		group = filepath.Dir(group)
	}
	return headroom, nil
}

// prepareCaptureMemory runs large captures in a limited systemd scope before
// any probes or packet rings are allocated. The child verifies its limit.
func prepareCaptureMemory(names []string, setting string, yes bool) (handled bool, err error) {
	limit, err := parseCaptureMemoryLimit(setting, len(names))
	if err != nil {
		return false, err
	}
	if os.Getenv(memoryScopeEnv) != "" {
		actual, err := currentMemoryMax()
		if err != nil || limit == 0 || actual > limit {
			return false, fmt.Errorf("memory-limited scope was not established: limit=%d, read error=%v", actual, err)
		}
		return false, nil
	}
	ringBytes := uint64(captureRingSize(len(names))) * uint64(len(names))
	if limit != 0 {
		available, err := availableMemory()
		if err != nil {
			return false, fmt.Errorf("check available memory: %w", err)
		}
		if err := validateCaptureMemory(limit, ringBytes, available); err != nil {
			return false, err
		}
		if _, err := exec.LookPath("systemd-run"); err != nil {
			return false, fmt.Errorf("memory protection needs systemd-run: %w; use --memory-limit=none to run without it", err)
		}
	}
	if len(names) > maxCaptureInterfaces {
		limitText := "none"
		if limit != 0 {
			limitText = fmt.Sprintf("%d MiB", limit>>20)
		}
		fmt.Fprintf(os.Stderr, "socktrail: %d interfaces: %s\npacket rings: at least %d MiB; total memory limit: %s\n", len(names), strings.Join(names, ","), ringBytes>>20, limitText)
		if !yes {
			if !term.IsTerminal(int(os.Stdin.Fd())) {
				return false, fmt.Errorf("large capture needs terminal confirmation or --yes")
			}
			fmt.Fprint(os.Stderr, "Start capture? [y/N] ")
			var answer string
			if _, err := fmt.Fscanln(os.Stdin, &answer); err != nil || !strings.EqualFold(answer, "y") {
				return false, fmt.Errorf("capture cancelled")
			}
		}
	}
	if limit == 0 {
		return false, nil
	}
	exe, err := os.Executable()
	if err != nil {
		return false, err
	}
	args := []string{"--scope", "--quiet", "--collect", "--same-dir"}
	if os.Geteuid() != 0 {
		args = append(args, "--user")
	}
	args = append(args, "-p", fmt.Sprintf("MemoryMax=%d", limit), exe)
	args = append(args, os.Args[1:]...)
	cmd := exec.Command("systemd-run", args...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	cmd.Env = append(os.Environ(), memoryScopeEnv+"=1")
	if err := cmd.Run(); err != nil {
		return true, fmt.Errorf("memory-limited capture: %w", err)
	}
	return true, nil
}
