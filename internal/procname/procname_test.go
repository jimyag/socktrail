package procname

import "testing"

func TestClean(t *testing.T) {
	for _, c := range []struct{ name, want string }{
		{"nginx\x00\x00junk", "nginx"},
		{" tailscaled\n", "tailscaled"},
		{"\x1b[7mEVIL\x1b[0m", "?[7mEVIL?[0m"},
		{"\xc2\x9b31mred", "?31mred"},       // U+009B, an 8-bit CSI.
		{"abc\xe2\x80\xaedcba", "abc?dcba"}, // U+202E, a bidi override, reorders what follows.
		{"bad\xffutf8", "bad?utf8"},         // Invalid UTF-8.
		{"kworker/0:1H-kblockd", "kworker/0:1H-kblockd"},
		{"日志 agent", "日志 agent"},
	} {
		if got := Clean([]byte(c.name)); got != c.want {
			t.Errorf("Clean(%q) = %q, want %q", c.name, got, c.want)
		}
	}
}
