package app

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCaptureMemoryPolicy(t *testing.T) {
	for _, tc := range []struct {
		setting    string
		interfaces int
		want       uint64
	}{
		{"auto", 8, 0},
		{"auto", 9, 512 << 20},
		{"none", 100, 0},
		{"1GiB", 30, 1 << 30},
		{"768MiB", 30, 768 << 20},
	} {
		got, err := parseCaptureMemoryLimit(tc.setting, tc.interfaces)
		if err != nil || got != tc.want {
			t.Errorf("limit %q for %d interfaces = %d, %v; want %d", tc.setting, tc.interfaces, got, err, tc.want)
		}
	}
	if _, err := parseCaptureMemoryLimit("0", 9); err == nil {
		t.Fatal("zero memory limit was accepted")
	}
	if ring := captureRingSize(30) * 30; ring != 120<<20 {
		t.Fatalf("30 packet rings = %d bytes, want 120 MiB", ring)
	}
	if err := validateCaptureMemory(512<<20, 120<<20, 4<<30); err != nil {
		t.Fatal(err)
	}
	if err := validateCaptureMemory(512<<20, 400<<20, 4<<30); err == nil || !strings.Contains(err.Error(), "headroom") {
		t.Fatalf("ring over budget: %v", err)
	}
	if err := validateCaptureMemory(512<<20, 120<<20, 800<<20); err == nil || !strings.Contains(err.Error(), "available") {
		t.Fatalf("memory pressure was accepted: %v", err)
	}
}

func TestCaptureMemoryScopeLockHelper(t *testing.T) {
	path := os.Getenv("SOCKTRAIL_TEST_LOCK")
	if path == "" {
		return
	}
	if os.Getenv(memoryScopeEnv) == "" {
		t.Fatal("scope marker missing")
	}
	lock, err := lockProcess(path)
	if err != nil || lock == nil {
		t.Fatalf("scope child could not take process lock: %v", err)
	}
	_ = lock.Close()
}

func TestCaptureMemoryScopeReleasesParentLock(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "lock")
	lock, err := lockProcess(path)
	if err != nil || lock == nil {
		t.Fatalf("parent lock: %v", err)
	}
	defer func() { _ = lock.Close() }()
	t.Setenv(memoryScopeEnv, "")
	if handled, err := prepareCaptureMemory([]string{"lo"}, "none", true, lock); handled || err != nil {
		t.Fatalf("unlimited capture: handled=%v, err=%v", handled, err)
	}
	if second, err := lockProcess(path); !errors.Is(err, errInstanceRunning) {
		if second != nil {
			_ = second.Close()
		}
		t.Fatalf("unlimited capture lost its lock: %v", err)
	}
	binary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("SOCKTRAIL_TEST_BINARY", binary)
	t.Setenv("SOCKTRAIL_TEST_LOCK", path)
	t.Setenv("PATH", dir)
	script := "#!/bin/sh\nexec \"$SOCKTRAIL_TEST_BINARY\" -test.run='^TestCaptureMemoryScopeLockHelper$'\n"
	if err := os.WriteFile(filepath.Join(dir, "systemd-run"), []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	if handled, err := prepareCaptureMemory([]string{"lo"}, "512MiB", true, lock); !handled || err != nil {
		t.Fatalf("scope capture: handled=%v, err=%v", handled, err)
	}
}
