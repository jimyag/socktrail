package app

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func testProcessStat(startTicks uint64) string {
	fields := make([]string, 20)
	for i := range fields {
		fields[i] = "0"
	}
	fields[0], fields[1], fields[19] = "S", "42", fmt.Sprint(startTicks)
	return "123 (worker (busy)) " + strings.Join(fields, " ")
}

func TestProcessDetailsCheckIdentityAndEscapeEnvironment(t *testing.T) {
	root := t.TempDir()
	base := filepath.Join(root, "123")
	if err := os.Mkdir(base, 0o700); err != nil {
		t.Fatal(err)
	}
	for name, content := range map[string]string{
		"stat":    testProcessStat(652),
		"cmdline": "worker\x00--name\x00hello world\x00",
		"environ": "ZED=last\x00API_TOKEN=abc\x1b[31m\x00ALPHA=first\x00",
	} {
		if err := os.WriteFile(filepath.Join(base, name), []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(root, "stat"), []byte("cpu 0\nbtime 1700000000\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for name, target := range map[string]string{"exe": "/usr/bin/worker", "cwd": "/tmp"} {
		if err := os.Symlink(target, filepath.Join(base, name)); err != nil {
			t.Fatal(err)
		}
	}
	id := processID{PID: 123, StartNS: 6_520_144_670}
	detail := readProcessDetailsAt(root, id, 100)
	if detail.errorText != "" || detail.parentPID != 42 || detail.started == "" || !strings.Contains(detail.command, "hello world") || len(detail.environment) != 3 {
		t.Fatalf("launch details missing: %+v", detail)
	}
	if !strings.HasPrefix(detail.environment[0], `"ALPHA"="first"`) || strings.Contains(strings.Join(detail.environment, "\n"), "\x1b") {
		t.Fatalf("environment was not sorted or escaped: %#v", detail.environment)
	}
	if got := readProcessDetailsAt(root, processID{PID: 123, StartNS: 9_000_000_000}, 100); !strings.Contains(got.errorText, "PID was reused") || len(got.environment) != 0 {
		t.Fatalf("reused PID inherited another process's details: %+v", got)
	}
}

func TestParseProcessStatWithParentheses(t *testing.T) {
	parent, start, err := parseProcessStat([]byte(testProcessStat(652)))
	if err != nil || parent != 42 || start != 652 {
		t.Fatalf("stat fields shifted by command name: parent=%d start=%d err=%v", parent, start, err)
	}
}

func TestCurrentProcessLaunchDetails(t *testing.T) {
	ticks, err := systemClockTicks()
	if err != nil {
		t.Fatal(err)
	}
	stat, err := os.ReadFile("/proc/self/stat")
	if err != nil {
		t.Fatal(err)
	}
	_, start, err := parseProcessStat(stat)
	if err != nil {
		t.Fatal(err)
	}
	id := processID{PID: os.Getpid(), StartNS: start/ticks*1_000_000_000 + start%ticks*1_000_000_000/ticks}
	detail := readProcessDetails(id)
	if detail.errorText != "" || detail.executable == "" || detail.command == "" || detail.started == "" {
		t.Fatalf("cannot read current process launch details: %+v", detail)
	}
	c := &collector{pidIO: map[processID]processIO{id: {Name: "go-test"}}}
	u := &terminalUI{mode: viewPID, tab: 1, screenWidth: 100, bottomHeight: 20}
	var lines []string
	u.renderBottom(&lines, u.rows(c, viewPID), c)
	page := strings.Join(lines, "\n")
	for _, field := range []string{"STARTED", "PARENT PID", "EXECUTABLE", "WORKDIR", "COMMAND", "ENVIRONMENT"} {
		if !strings.Contains(page, field) {
			t.Fatalf("process page did not show %s", field)
		}
	}
}
