package app

import (
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
