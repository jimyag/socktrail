// Package procname makes process names safe to show on a terminal.
package procname

import (
	"bytes"
	"strings"
	"unicode"
)

// Clean returns a task name (comm) fit for a terminal: it ends at the first
// NUL, loses surrounding spaces, and has every character that is not
// graphic replaced with '?'. Any user can name their own process, so a raw
// name could carry escape sequences, 8-bit C1 controls or bidi overrides to
// the terminal of whoever runs socktrail.
func Clean(name []byte) string {
	if end := bytes.IndexByte(name, 0); end >= 0 {
		name = name[:end]
	}
	return strings.Map(func(r rune) rune {
		if unicode.IsGraphic(r) {
			return r
		}
		return '?'
	}, strings.TrimSpace(strings.ToValidUTF8(string(name), "?")))
}
