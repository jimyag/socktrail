package app

import (
	"os"
	"slices"
	"strings"
	"unicode/utf8"

	"github.com/charmbracelet/x/ansi"
)

// The TUI draws with the terminal's 16 theme colors, which a theme keeps
// readable on its own background. The highlight bar is reverse video in
// cyan: cyan behind text of the background color, as readable as cyan text
// on light and dark themes alike. Yellow only marks warnings. NO_COLOR
// (no-color.org) drops the colors but keeps bold, faint and reverse video.
//
// A style's off sequence resets only what it set, so a colored cell does not
// end the bold or the background of the text around it.
type style struct{ on, off string }

func (s style) paint(text string) string {
	if s.on == "" || text == "" {
		return text
	}
	return s.on + text + s.off
}

// color is a style that NO_COLOR replaces with fallback.
func color(on, off string, fallback style) style {
	if os.Getenv("NO_COLOR") != "" {
		return fallback
	}
	return style{on, off}
}

var (
	styleBold    = style{"\x1b[1m", "\x1b[22m"}
	styleFaint   = style{"\x1b[2m", "\x1b[22m"}
	styleRed     = color("\x1b[31m", "\x1b[39m", style{})
	styleGreen   = color("\x1b[32m", "\x1b[39m", style{})
	styleYellow  = color("\x1b[33m", "\x1b[39m", style{})
	styleMagenta = color("\x1b[35m", "\x1b[39m", style{})
	styleCyan    = color("\x1b[36m", "\x1b[39m", style{})
	styleAccent  = color("\x1b[1;36m", "\x1b[22;39m", styleBold)
	styleAlert   = color("\x1b[1;31m", "\x1b[22;39m", styleBold)
	// styleBar marks the selected row of the focused table, the current page
	// and the current tab.
	styleBar = color("\x1b[7;36m", "\x1b[27;39m", style{"\x1b[7m", "\x1b[27m"})
)

// cellStyles colors table cells by their column's title.
var cellStyles = map[string]func(string) string{
	"RX/s":  styleGreen.paint,
	"TX/s":  styleGreen.paint,
	"PID?":  styleYellow.paint,
	"RETX":  styleYellow.paint,
	"APP":   styleCyan.paint,
	"STATE": stateCell,
	"DIR":   directionCell,
	"PPID":  styleFaint.paint,
	"FIRST": styleFaint.paint,
	"LAST":  styleFaint.paint,
}

// styleCell colors one table cell. A cell without a value, such as a zero
// count or an unknown process, is faint whatever its column.
func styleCell(title, value string) string {
	switch value {
	case "-", "0", "unknown", "unknown process", "ambiguous":
		return styleFaint.paint(value)
	}
	if paint := cellStyles[title]; paint != nil {
		return paint(value)
	}
	return value
}

// stateCell colors a flow's state: green once established, yellow during the
// handshake or after an ICMP warning, red after a reset or an ICMP error that
// fails the connection, and faint once closed.
func stateCell(state string) string {
	switch state {
	case "established":
		return styleGreen.paint(state)
	case "syn":
		return styleYellow.paint(state)
	case "closing", "closed":
		return styleFaint.paint(state)
	case "", "midstream":
		return state
	}
	tcp, icmp, found := strings.Cut(state, ", ") // A UDP flow's state is just its ICMP error.
	if !found {
		icmp = tcp
	}
	failed := icmp != "frag-needed" && (slices.Contains(icmpUnreachable, icmp) || slices.Contains(icmp6Unreachable, icmp) || strings.HasPrefix(icmp, "unreachable"))
	if tcp == "reset" || failed {
		return styleRed.paint(state)
	}
	return styleYellow.paint(state)
}

func directionCell(direction string) string {
	switch direction {
	case "inbound", "first-packet-in":
		return styleMagenta.paint(direction)
	case "forwarded":
		return styleCyan.paint(direction)
	}
	return direction
}

// tableRow draws one table row. The selected row is a bar across the screen
// while its table has the focus, and bold behind a cyan marker otherwise;
// the other rows color their cells.
func tableRow(layout tableLayout, x, width int, selected, focused bool, line func(tableLayout, string) string) string {
	if !selected {
		layout.styled = true
		return scrollTableLine(line(layout, " "), x, width)
	}
	text := scrollTableLine(line(layout, "▸"), x, width)
	if focused {
		return styleBar.paint(text + strings.Repeat(" ", max(0, width-displayWidth(text))))
	}
	return styleAccent.paint("▸") + styleBold.paint(strings.TrimPrefix(text, "▸"))
}

// label marks the name of a field in a detail line.
func label(name string) string { return styleCyan.paint(name) }

// topPages are the top line's page keys, and pageEntries each page's entry.
const topPages = "1 PID  2 SRC  3 DST  4 PROTO  5 SVC  d DOMAINS  0 IFACES"

var pageEntries = map[viewMode]string{
	viewPID: "1 PID", viewSource: "2 SRC", viewTarget: "3 DST", viewProtocol: "4 PROTO",
	viewService: "5 SVC", viewDomain: "d DOMAINS", viewInterfaces: "0 IFACES",
}

// topKeys colors the top line's "key name" entries, which two spaces
// separate: the key in the accent color and the name in the given style, or
// the current entry on the bar.
func topKeys(entries, current string, name style) string {
	parts := strings.Split(entries, "  ")
	for i, entry := range parts {
		if entry == current {
			parts[i] = styleBar.paint(entry)
		} else if key, rest, ok := strings.Cut(entry, " "); ok {
			parts[i] = styleAccent.paint(key) + " " + name.paint(rest)
		}
	}
	return strings.Join(parts, "  ")
}

// displayWidth is the number of terminal cells s takes. Table text is mostly
// plain ASCII, which skips the escape-sequence and grapheme scan.
func displayWidth(s string) int {
	for i := 0; i < len(s); i++ {
		if s[i] >= utf8.RuneSelf || s[i] < ' ' {
			return ansi.StringWidth(s)
		}
	}
	return len(s)
}

// fit cuts a line to the screen width without splitting an escape sequence
// or a wide character.
func fit(line string, width int) string {
	if displayWidth(line) <= width {
		return line
	}
	return ansi.Truncate(line, width, "")
}

// scrollLine shows width cells of a line from offset; the escape sequences
// before offset are kept, so a style that starts off screen still applies.
func scrollLine(line string, offset, width int) string {
	if width <= 0 {
		return ""
	}
	return ansi.Cut(line, max(0, offset), max(0, offset)+width)
}

// scrollTableLine scrolls a table row but keeps its first cell, the cursor.
func scrollTableLine(line string, offset, width int) string {
	if width <= 0 || line == "" {
		return ""
	}
	_, size := utf8.DecodeRuneInString(line)
	return line[:size] + scrollLine(line[size:], offset, width-1)
}
