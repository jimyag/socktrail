package main

import (
	"fmt"
	"os"
	"strings"
)

// frameDelta redraws only changed rows. Clearing to the end of each changed
// row removes stale text without blanking the entire terminal on every tick;
// resetting the style first keeps a row cut inside a colored span from
// coloring the cleared cells.
func frameDelta(lines, previous []string, width, height int, force bool) (string, []string) {
	visible := make([]string, len(lines))
	var output strings.Builder
	for i, line := range lines {
		visible[i] = fit(line, width)
		if !force && i < len(previous) && previous[i] == visible[i] {
			continue
		}
		fmt.Fprintf(&output, "\x1b[%d;1H%s\x1b[m\x1b[K", i+1, visible[i])
	}
	for i := len(lines); i < min(len(previous), height); i++ {
		fmt.Fprintf(&output, "\x1b[%d;1H\x1b[K", i+1)
	}
	return output.String(), visible
}

func (u *terminalUI) draw(lines []string, width, height int) {
	force := u.renderedWidth != width || u.renderedHeight != height
	output, visible := frameDelta(lines, u.drawnLines, width, height, force)
	u.drawnLines, u.renderedWidth, u.renderedHeight = visible, width, height
	if output != "" {
		// Synchronized output: a terminal that supports mode 2026 shows the
		// frame at once instead of row by row; others ignore it.
		fmt.Fprint(os.Stdout, "\x1b[?2026h"+output+"\x1b[?2026l")
	}
}
