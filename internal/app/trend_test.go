package app

import (
	"strings"
	"testing"
	"time"
)

func TestTrendRingEmpty(t *testing.T) {
	var r trendRing
	r.newest = -1
	if got := r.sparkn(trendTopWidth); got != strings.Repeat(" ", trendTopWidth) {
		t.Errorf("empty ring should render %d blanks, got %q", trendTopWidth, got)
	}
	if v := r.latest(); v != 0 {
		t.Errorf("empty ring latest = %d, want 0", v)
	}
}

func TestTrendRingRanks(t *testing.T) {
	var r trendRing
	r.newest = -1
	r.add(0)   // age 3: blank below
	r.add(10)  // age 2: one rung above blank
	r.add(50)  // age 1
	r.add(100) // age 0: full block
	got := r.sparkn(4)
	want := " ▁▄█"
	if got != want {
		t.Errorf("sparkn(4) = %q, want %q", got, want)
	}
	if v := r.latest(); v != 100 {
		t.Errorf("latest = %d, want 100", v)
	}
}

func TestTrendRingSorts(t *testing.T) {
	var r trendRing
	r.newest = -1
	for i := 1; i <= 8; i++ {
		r.add(uint64(i * 10))
	}
	got := r.sparkn(8)
	want := "▁▂▃▄▅▆▇█"
	if got != want {
		t.Errorf("monotone ramp sparkn(8) = %q, want %q", got, want)
	}
}

func TestTrendRingWraps(t *testing.T) {
	var r trendRing
	r.newest = -1
	for i := range trendSeconds + 10 {
		r.add(uint64(i))
	}
	if r.count != trendSeconds {
		t.Errorf("count = %d, want %d after wrap-around", r.count, trendSeconds)
	}
	if v := r.latest(); v != uint64(trendSeconds+9) {
		t.Errorf("latest after wrap = %d, want %d", v, trendSeconds+9)
	}
	// Oldest still present: sample trendSeconds-1 ticks ago.
	if v, ok := r.at(trendSeconds - 1); !ok || v != 10 {
		t.Errorf("oldest sample = %d ok=%v, want 10 ok=true", v, ok)
	}
	if _, ok := r.at(trendSeconds); ok {
		t.Errorf("age %d should be out of range", trendSeconds)
	}
}

func TestTrendRingShort(t *testing.T) {
	var r trendRing
	r.newest = -1
	r.add(7)
	r.add(9)
	got := r.sparkn(6)
	// Most recent sample on the right; 4 left cells padded with blanks.
	want := "    ▆█"
	if got != want {
		t.Errorf("sparkn(6) = %q, want %q", got, want)
	}
}

func TestTrendRingAllZero(t *testing.T) {
	var r trendRing
	r.newest = -1
	r.add(0)
	r.add(0)
	got := r.sparkn(4)
	if got != "    " {
		t.Errorf("all-zero ring sparkn(4) = %q, want blanks", got)
	}
}

func TestTrendRingWindowAggregates(t *testing.T) {
	var r trendRing
	r.newest = -1
	// 10 seconds of history into 5 cells: each cell max-aggregates 2
	// seconds, and a single peak keeps its bucket tall.
	// Oldest first: 0,0, 1,100, 2,2, 0,0, 4,6
	for _, v := range []uint64{0, 0, 1, 100, 2, 2, 0, 0, 4, 6} {
		r.add(v)
	}
	got := r.sparkWindow(10, 5)
	want := " █▁ ▁"
	if got != want {
		t.Errorf("sparkWindow(10,5) = %q, want %q", got, want)
	}
}

func TestTrendRingWindowShortHistory(t *testing.T) {
	var r trendRing
	r.newest = -1
	r.add(10)
	r.add(20)
	// Only 2 samples though 10 seconds of width requested: newest lands in
	// the last cell, oldest spreads left by bucket math.
	got := r.sparkWindow(10, 5)
	if got != "  ▄ █" {
		t.Errorf("sparkWindow with 2 samples = %q, want \"  ▄ █\"", got)
	}
}

func TestTrendStoreEvictsUnused(t *testing.T) {
	s := newTrendStore()
	now := time.Unix(1000, 0)
	s.tick(now)
	s.add("a", 10)
	s.add("b", 20)
	s.tick(now.Add(time.Second))
	s.markUnused("a")
	s.add("b", 30)
	// a and b both still have rings.
	if s.ring("a") == nil || s.ring("b") == nil {
		t.Fatal("recently used rings must survive")
	}
	// Advance past the stale window and evict.
	s.tick(now.Add(trendRowStaleMs*time.Millisecond + time.Second))
	s.evict()
	if s.ring("a") != nil {
		t.Error("stale ring for a should have been evicted")
	}
	if s.ring("b") == nil {
		t.Error("active ring for b should survive")
	}
}
