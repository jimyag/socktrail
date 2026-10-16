package app

import (
	"time"
)

// Row traffic trends, per docs/roadmap.md item 12. Each row that the main
// table displays contributes one uint32 sample per second into a small ring
// buffer keyed by row identity. The ring is read in table rendering and the
// bottom 5-minute curve, and is pruned independently of the flow table.

const (
	// trendSeconds is how many per-second samples each row keeps. 300
	// seconds supports both the 30-second TREND column and the 5-minute
	// bottom panel from the same buffer.
	trendSeconds = 300
	// trendTopWidth cells in the main table's TREND column: one per second
	// over the last 30 seconds.
	trendTopWidth = 30
	// trendRows bounds the number of identities tracked. Rows absent from
	// the table for this many ticks are evicted on the next sample.
	trendRows       = 500
	trendRowStaleMs = 5 * 60 * 1000 // 5 minutes in milliseconds.
)

// sparkChars renders a uint32 sample to a cell by its rank among the
// samples currently in the buffer: the maximum maps to the top rung, zero
// and empty slots stay a blank so "no data" is not confused with "very
// small". The chars are East Asian Width ambiguous, like the existing └
// and ↑; docs/user/usage.md notes the layout effects.
const sparkChars = "▁▂▃▄▅▆▇█"

var sparkRunes = []rune(sparkChars)

// trendRing is one row's fixed-size ring of per-second byte totals.
// Count is the number of valid samples (0..trendSeconds), newest is the
// index of the most recently written sample.
type trendRing struct {
	samples [trendSeconds]uint32
	count   uint32
	newest  int32 // -1 until the first sample.
}

// add records one rx+tx total for the current tick.
func (t *trendRing) add(total uint64) {
	v := min(total, 0xFFFFFFFF)
	t.newest = (t.newest + 1) % trendSeconds
	t.samples[t.newest] = uint32(v)
	if t.count < trendSeconds {
		t.count++
	}
}

// at returns the sample age ticks ago (0 = most recent) and whether it is
// valid. Ages beyond count return ok=false so callers can render blanks
// instead of zeros.
func (t *trendRing) at(age int) (uint32, bool) {
	if age < 0 || age >= int(t.count) {
		return 0, false
	}
	return t.samples[(int(t.newest)-age+trendSeconds)%trendSeconds], true
}

// latest returns the most recent sample, or 0 when the ring is empty.
func (t *trendRing) latest() uint64 {
	if t.count == 0 {
		return 0
	}
	return uint64(t.samples[t.newest])
}

// sparkRung maps v onto 1..len(sparkChars) rungs for a scale topped by top
// (top > 0, v <= top). Zero stays a blank cell.
func sparkRung(v, top uint32) rune {
	if v == 0 || top == 0 {
		return ' '
	}
	rung := uint64(v) * uint64(len(sparkRunes)) / (uint64(top) + 1)
	return sparkRunes[min(rung, uint64(len(sparkRunes))-1)]
}

// sparkn renders the last width samples as at most width characters,
// right-aligned; short history pads on the left. Cells beyond width are
// truncated from the oldest end. Empty ring returns a string of blanks.
// The output is ASCII-safe for cell math: width CJK-ambiguous single cells.
func (t *trendRing) sparkn(width int) string {
	if width <= 0 {
		return ""
	}
	cells := make([]rune, width)
	for i := range cells {
		cells[i] = ' '
	}
	if t.count == 0 {
		return string(cells)
	}
	// Find the max over the samples we will actually draw.
	shown := min(width, int(t.count))
	var top uint32
	for age := range shown {
		if v, ok := t.at(age); ok && v > top {
			top = v
		}
	}
	if top == 0 {
		return string(cells) // All zero: render blanks, no fake floor.
	}
	for age := range shown {
		v, ok := t.at(age)
		if !ok {
			break
		}
		// Position: age 0 lands on the rightmost drawn cell.
		pos := width - 1 - age
		if pos < 0 {
			break
		}
		cells[pos] = sparkRung(v, top)
	}
	return string(cells)
}

// sparkWindow renders the last seconds samples compressed into width cells:
// each cell is the max of the bucket of seconds/width samples behind it, so
// peaks survive aggregation. Pads left when history is shorter than width.
func (t *trendRing) sparkWindow(seconds, width int) string {
	if width <= 0 || seconds <= 0 {
		return ""
	}
	cells := make([]rune, width)
	for i := range cells {
		cells[i] = ' '
	}
	if t.count == 0 {
		return string(cells)
	}
	if seconds > int(t.count) {
		seconds = int(t.count)
	}
	// Bucket boundaries: cell i covers ages [lo, hi) from the newest down.
	var top uint32
	bucketMax := make([]uint32, width)
	for age := 0; age < seconds; age++ {
		v, ok := t.at(age)
		if !ok {
			break
		}
		// Newest sample goes to the last cell; cells sized seconds/width.
		cell := width - 1 - age*width/seconds
		if cell < 0 {
			break
		}
		if v > bucketMax[cell] {
			bucketMax[cell] = v
		}
		if v > top {
			top = v
		}
	}
	if top == 0 {
		return string(cells)
	}
	for i, v := range bucketMax {
		cells[i] = sparkRung(v, top)
	}
	return string(cells)
}

// trendStore owns every row's ring, keyed by the row's identity string.
// seenRates caches the rate written at the latest tick per identity so the
// main table can sort by TREND without walking rings.
type trendStore struct {
	rings     map[string]*trendRing
	unused    map[string]time.Time
	seenRates map[string]uint64
	now       time.Time
}

func newTrendStore() *trendStore {
	return &trendStore{rings: make(map[string]*trendRing), unused: make(map[string]time.Time)}
}

// tick advances the store's clock; sampleAll calls it before recording
// rates so eviction compares against the same instant.
func (s *trendStore) tick(now time.Time) {
	s.now = now
}

// add records total bytes for identity at the tick time and clears its
// unused mark if the row had been skipped earlier.
func (s *trendStore) add(identity string, total uint64) {
	if identity == "" {
		return
	}
	delete(s.unused, identity)
	r, ok := s.rings[identity]
	if !ok {
		if len(s.rings) >= trendRows {
			s.evictOldest()
		}
		r = &trendRing{newest: -1}
		s.rings[identity] = r
	}
	r.add(total)
}

// markUnused notes that identity had no sample this tick; the ring is
// kept around so a row that disappears briefly keeps its history.
func (s *trendStore) markUnused(identity string) {
	if identity == "" {
		return
	}
	if _, ok := s.rings[identity]; ok {
		if _, pending := s.unused[identity]; !pending {
			s.unused[identity] = s.now
		}
	}
}

// evict drops rings that have been unused for at least trendRowStaleMs,
// and is also called when adding a new ring would exceed trendRows.
func (s *trendStore) evict() {
	for identity, since := range s.unused {
		if s.now.Sub(since) >= trendRowStaleMs*time.Millisecond {
			delete(s.unused, identity)
			delete(s.rings, identity)
		}
	}
}

func (s *trendStore) evictOldest() {
	var oldest string
	var when time.Time
	for identity, since := range s.unused {
		if when.IsZero() || since.Before(when) {
			when, oldest = since, identity
		}
	}
	if oldest == "" {
		// No unused ring: drop the first map key. Sampling will refill.
		for identity := range s.rings {
			oldest = identity
			break
		}
	}
	delete(s.unused, oldest)
	delete(s.rings, oldest)
}

// ring returns the ring for identity, or nil when the row has no samples
// yet. Rendering reads through this without allocating.
func (s *trendStore) ring(identity string) *trendRing {
	return s.rings[identity]
}
