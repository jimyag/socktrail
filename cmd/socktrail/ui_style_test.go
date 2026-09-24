package main

import (
	"strings"
	"testing"

	"github.com/charmbracelet/x/ansi"
)

func TestStyledRowsKeepTheirTextAndWidth(t *testing.T) {
	layout := newTableLayout([]tableColumn{{title: "DIR"}, {title: "STATE"}, {title: "RETX", right: true}}, 0)
	line := func(layout tableLayout, cursor string) string {
		return layout.line(cursor, "inbound", "established", "3")
	}
	plain := scrollTableLine(line(layout, " "), 2, 12)
	if colored := tableRow(layout, 2, 12, false, false, line); ansi.Strip(colored) != plain || !strings.Contains(colored, styleGreen.on) {
		t.Fatalf("scrolled colored row %q, want the text %q", colored, plain)
	}
	if bar := tableRow(layout, 0, 40, true, true, line); !strings.HasPrefix(bar, styleBar.on) || ansi.StringWidth(bar) != 40 {
		t.Fatalf("the focused selection is not a bar across the screen: %q", bar)
	}
	if marked := tableRow(layout, 0, 40, true, false, line); !strings.HasPrefix(ansi.Strip(marked), "▸inbound") {
		t.Fatalf("the unfocused selection lost its marker: %q", marked)
	}
	for state, want := range map[string]style{"established": styleGreen, "syn": styleYellow, "reset": styleRed, "closed": styleFaint,
		"established, port-unreachable": styleRed, "established, packet-too-big": styleYellow, "frag-needed": styleYellow} {
		if got := stateCell(state); got != want.paint(state) {
			t.Errorf("state %q painted %q", state, got)
		}
	}
}
