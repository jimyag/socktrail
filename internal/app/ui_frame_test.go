package app

import (
	"strings"
	"testing"
)

func TestFrameDeltaUpdatesChangedRowsWithoutClearingScreen(t *testing.T) {
	first, previous := frameDelta([]string{"header", "long connection row"}, nil, 40, 24, true)
	if strings.Contains(first, "\x1b[2J") || !strings.Contains(first, "\x1b[1;1Hheader\x1b[m\x1b[K") {
		t.Fatalf("initial frame controls: %q", first)
	}
	changed, current := frameDelta([]string{"header", "short"}, previous, 40, 24, false)
	if changed != "\x1b[2;1Hshort\x1b[m\x1b[K" || current[1] != "short" {
		t.Fatalf("changed row was not updated in place: %q", changed)
	}
	unchanged, _ := frameDelta([]string{"header", "short"}, current, 40, 24, false)
	if unchanged != "" {
		t.Fatalf("unchanged frame was redrawn: %q", unchanged)
	}
}
